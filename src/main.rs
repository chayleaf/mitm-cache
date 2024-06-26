use base64::Engine;
use clap::{Parser, Subcommand};
use http_body_util::BodyExt;
use hudsucker::{
    certificate_authority::RcgenAuthority,
    decode_request, decode_response,
    futures::channel::mpsc,
    hyper::{Request, Response},
    rcgen::KeyPair,
    rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer},
    tokio_tungstenite::tungstenite::http::uri::Scheme,
    Body, HttpContext, HttpHandler, Proxy, RequestOrResponse,
};
use hyper::{StatusCode, Uri};
use hyper_rustls::{HttpsConnector, HttpsConnectorBuilder};
use hyper_util::{
    client::legacy::{connect::HttpConnector, Client},
    rt::TokioExecutor,
};
use rustls_pemfile as pemfile;
use serde::{Deserialize, Serialize};
use sha2::Digest;
use std::{
    collections::BTreeMap,
    future::Future,
    net::{Ipv4Addr, SocketAddr},
    path::PathBuf,
    sync::Arc,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::RwLock,
};

async fn shutdown_signal() {
    tokio::signal::ctrl_c()
        .await
        .expect("Failed to install CTRL+C signal handler");
}

#[derive(Clone, Debug, Deserialize, Serialize)]
enum Contents {
    #[serde(rename = "redirect")]
    Redirect(String),
    #[serde(rename = "sha256")]
    Sha256(String),
    #[serde(rename = "text")]
    Text(String),
}

#[derive(Default, Deserialize, Serialize)]
struct Page {
    #[serde(skip_serializing_if = "Option::is_none", flatten)]
    contents: Option<Contents>,
    // replaying not implemented
    #[serde(skip_serializing_if = "BTreeMap::is_empty", rename = "post")]
    post_responses: BTreeMap<String, Contents>,
}

#[derive(Default)]
struct Pages(BTreeMap<String, Page>, PathBuf);

impl Drop for Pages {
    fn drop(&mut self) {
        self.0
            .serialize(&mut serde_json::Serializer::with_formatter(
                std::fs::File::create(&self.1).unwrap(),
                serde_json::ser::PrettyFormatter::with_indent(b" "),
            ))
            .unwrap();
    }
}

#[derive(Clone)]
enum Handler {
    Record {
        client: Client<HttpsConnector<HttpConnector>, Body>,
        pages: Arc<RwLock<Pages>>,
        forget_redirects_from: Option<regex::Regex>,
        forget_redirects_to: Option<regex::Regex>,
        record_text: Option<regex::Regex>,
        reject: Option<regex::Regex>,
    },
    Replay(PathBuf),
}

fn process_uri(uri: Uri) -> Uri {
    let mut parts = uri.clone().into_parts();
    // strip query
    if let Some(ref mut pq) = &mut parts.path_and_query {
        if let Ok(pq2) = pq.path().parse() {
            *pq = pq2;
        }
    }
    if let Some(ref mut auth) = &mut parts.authority {
        if let Some(scheme) = &parts.scheme {
            if scheme == &Scheme::HTTPS && auth.port_u16() == Some(443) {
                if let Some(auth2) = auth
                    .as_str()
                    .strip_suffix(":443")
                    .and_then(|x| x.parse().ok())
                {
                    *auth = auth2;
                }
            }
        }
    }
    Uri::from_parts(parts).unwrap_or(uri)
}

impl HttpHandler for Handler {
    #[allow(clippy::manual_async_fn)]
    fn handle_request(
        &mut self,
        _ctx: &HttpContext,
        req: Request<Body>,
    ) -> impl Future<Output = RequestOrResponse> + Send {
        async move {
            match self {
                Self::Record {
                    client,
                    pages,
                    forget_redirects_to,
                    forget_redirects_from,
                    record_text,
                    reject,
                } => {
                    let mut forget = false;
                    let mut all_urls = vec![];
                    let mut req1 = Some(req);
                    loop {
                        let req = req1.take().unwrap();
                        break match req.method().as_str() {
                            "CONNECT" => req.into(),
                            "GET" | "POST" | "HEAD" => {
                                let original_url = req.uri().clone();
                                println!("{req:?}");
                                let Ok(req) = decode_request(req) else {
                                    let mut res = Response::new("not found".into());
                                    *res.status_mut() = StatusCode::NOT_FOUND;
                                    return res.into();
                                };
                                let (info, body) = req.into_parts();
                                let Ok(req_body) = body.collect().await.map(|x| x.to_bytes())
                                else {
                                    let mut res = Response::new("not found".into());
                                    *res.status_mut() = StatusCode::NOT_FOUND;
                                    return res.into();
                                };
                                let post_body = (info.method == "POST")
                                    .then(|| std::str::from_utf8(&req_body).ok())
                                    .flatten()
                                    .map(ToOwned::to_owned);
                                let req_method = info.method.clone();
                                let req_version = info.version;
                                let req_headers = info.headers.clone();
                                let req = Request::from_parts(
                                    info,
                                    Body::from_stream(futures_util::stream::iter([Ok::<
                                        _,
                                        hudsucker::Error,
                                    >(
                                        req_body
                                    )])),
                                );
                                let store_body_info = req.method() != "HEAD";
                                let url = process_uri(original_url);
                                if !forget {
                                    all_urls.push(url.to_string());
                                }
                                if matches!(reject, Some(x) if x.is_match(&url.to_string())) {
                                    let mut res = Response::new("not found".into());
                                    *res.status_mut() = StatusCode::NOT_FOUND;
                                    return res.into();
                                }
                                let store_full_body = req.method() == "POST"
                                    || matches!(record_text, Some(x) if x.is_match(&url.to_string()));
                                let Ok(res) = client.request(req).await else {
                                    let mut res = Response::new("not found".into());
                                    *res.status_mut() = StatusCode::NOT_FOUND;
                                    return res.into();
                                };
                                let Ok(mut res) = decode_response(
                                    res.map(|body| Body::from_stream(body.into_data_stream())),
                                ) else {
                                    let mut res = Response::new("not found".into());
                                    *res.status_mut() = StatusCode::NOT_FOUND;
                                    return res.into();
                                };
                                // println!("{res:?}");
                                if res.status().is_redirection() {
                                if let Ok(location) = res.headers().get("Location").unwrap().to_str() {
                                    let mut pages = pages.write().await;
                                    let location = if let Ok(target) = location.parse::<Uri>() {
                                        let target1 = process_uri(target.clone());
                                        if matches!(forget_redirects_from, Some(x) if x.is_match(&url.to_string()))
                                            || matches!(forget_redirects_to, Some(x) if x.is_match(&target1.to_string()))
                                        {
                                            forget = true;
                                            let mut req = Request::new(Body::from_stream(futures_util::stream::empty::<Result<hyper::body::Bytes, hudsucker::Error>>()));
                                            *req.method_mut() = req_method;
                                            *req.headers_mut() = req_headers;
                                            *req.version_mut() = req_version;
                                            if let Some(host) = target.host().and_then(|x| TryInto::try_into(x).ok()) {
                                                req.headers_mut().insert("host", host);
                                            }
                                            *req.uri_mut() = if target.port().is_some() {
                                                target
                                            } else {
                                                let target0 = target.clone();
                                                let mut parts = target.into_parts();
                                                if let Some(auth) = &mut parts.authority {
                                                    if let Ok(x) = format!("{}:{}", auth.host(), if matches!(&parts.scheme, Some(x) if *x == Scheme::HTTP) {
                                                        80
                                                    } else {
                                                        443
                                                    }).parse() {
                                                        *auth = x;
                                                    }
                                                }
                                                Uri::from_parts(parts).unwrap_or(target0)
                                            };
                                            req1 = Some(req);
                                            continue;
                                        }
                                        target1.to_string()
                                    } else {
                                        location.to_owned()
                                    };
                                    let contents = Contents::Redirect(location.to_owned());
                                    for url in all_urls {
                                        let page = pages.0.entry(url.to_string()).or_default();
                                        if let Some(post_body) = post_body.clone() {
                                            page.post_responses.entry(post_body).or_insert(contents.clone());
                                        } else if page.contents.is_none() {
                                            page.contents = Some(contents.clone());
                                        }
                                    }
                                }
                                res
                            } else if res.status().is_success() {
                                if store_body_info {
                                    let (info, mut body) = res.into_parts();
                                    let (mut tx, rx) = mpsc::channel(1);
                                    let ret_body = Body::from_stream(rx);
                                    let pages = pages.clone();
                                    tokio::spawn(async move {
                                        let mut sha256 = sha2::Sha256::new();
                                        let mut contents = Vec::<u8>::new();
                                        let mut error = false;
                                        while let Some(data) = body.frame().await {
                                            let data = match data {
                                                Ok(data) => data,
                                                Err(err) => {
                                                    error = true;
                                                    if futures_util::future::poll_fn(|cx| tx.poll_ready(cx)).await.is_err() {
                                                        break;
                                                    }
                                                    if tx.start_send(Err(err)).is_err() {
                                                        break;
                                                    }
                                                    continue;
                                                }
                                            };
                                            let Ok(data) = data.into_data() else {
                                                break;
                                            };
                                            if store_full_body {
                                                contents.extend_from_slice(&data);
                                            }
                                            sha256.update(&data);
                                            if futures_util::future::poll_fn(|cx| tx.poll_ready(cx)).await.is_err() {
                                                error = true;
                                                break;
                                            }
                                            if tx.start_send(Ok(data)).is_err() {
                                                error = true;
                                                break;
                                            }
                                        }
                                        if error {
                                            return;
                                        }
                                        let base64 = base64::engine::general_purpose::STANDARD
                                            .encode(sha256.finalize());
                                        let contents = if let Some(contents) =
                                            std::str::from_utf8(&contents)
                                                .ok()
                                                .filter(|_| store_full_body)
                                        {
                                            Contents::Text(contents.to_owned())
                                        } else {
                                            Contents::Sha256(base64)
                                        };
                                        let mut pages = pages.write().await;
                                        for url in all_urls {
                                            let page = pages.0.entry(url).or_default();
                                            if let Some(post_body) = post_body.clone() {
                                                page.post_responses.entry(post_body).or_insert(contents.clone());
                                            } else if page.contents.is_none() {
                                                page.contents = Some(contents.clone());
                                            }
                                        }
                                    });
                                    Response::from_parts(info, ret_body)
                                } else {
                                    // remove hash headers to force the software to download this
                                    // so we get sha256
                                    let headers_to_remove = res
                                        .headers()
                                        .keys()
                                        .filter(|x| {
                                            x.as_str().ends_with("-md5")
                                                || x.as_str().ends_with("-sha1")
                                                || x.as_str().ends_with("-sha256")
                                                || x.as_str().ends_with("-sha512")
                                                || x.as_str() == "x-checksum"
                                        })
                                        .cloned()
                                        .collect::<Vec<_>>();
                                    for header in headers_to_remove {
                                        res.headers_mut().remove(header);
                                    }
                                    res
                                }
                            } else {
                                res
                            }
                            .into()
                            }
                            _ => {
                                let mut res = Response::new("not found".into());
                                *res.status_mut() = StatusCode::NOT_FOUND;
                                res.into()
                            }
                        };
                    }
                }
                Self::Replay(dir) => match req.method().as_str() {
                    "CONNECT" => req.into(),
                    "HEAD" | "GET" => {
                        let mut path = dir.clone();
                        let url = process_uri(req.uri().clone());
                        if let Some(scheme) = url.scheme_str() {
                            path.push(scheme);
                        }
                        if let Some(auth) = url.authority() {
                            path.push(auth.to_string());
                        }
                        for comp in url.path().split('/').filter(|x| !x.is_empty()) {
                            path.push(comp);
                        }
                        if let Ok(mut file) = tokio::fs::File::open(path).await {
                            let (mut tx, rx) =
                                mpsc::channel::<Result<hyper::body::Bytes, hudsucker::Error>>(1);
                            let body = Body::from_stream(rx);
                            if req.method().as_str() != "HEAD" {
                                tokio::spawn(async move {
                                    let mut buf = vec![0u8; 65536];
                                    while let Ok(n) = file.read(&mut buf).await {
                                        if n == 0 {
                                            break;
                                        }
                                        if futures_util::future::poll_fn(|cx| tx.poll_ready(cx))
                                            .await
                                            .is_err()
                                        {
                                            break;
                                        }
                                        if tx.start_send(Ok(buf[..n].to_vec().into())).is_err() {
                                            break;
                                        }
                                    }
                                });
                            }
                            Response::new(body).into()
                        } else {
                            let mut res = Response::new("not found".into());
                            *res.status_mut() = StatusCode::NOT_FOUND;
                            res.into()
                        }
                    }
                    _ => {
                        let mut res = Response::new("not found".into());
                        *res.status_mut() = StatusCode::NOT_FOUND;
                        res.into()
                    }
                },
            }
        }
    }
}

#[derive(Subcommand)]
enum Command {
    Record {
        /// Record text from URLs matching this regex
        #[clap(long, short)]
        record_text: Option<regex::Regex>,
        /// Reject requests to URLs matching this regex
        #[clap(long, short = 'x')]
        reject: Option<regex::Regex>,
        /// Forget redirects from URLs matching this regex
        #[clap(long, short = 'f')]
        forget_redirects_from: Option<regex::Regex>,
        /// Forget redirects to URLs matching this regex
        #[clap(long, short = 't')]
        forget_redirects_to: Option<regex::Regex>,
    },
    Replay {
        /// Path to the cache fetched using fetch.nix
        dir: PathBuf,
    },
}

#[derive(Parser)]
struct Args {
    /// Proxy listen address
    #[clap(long, short)]
    listen: Option<SocketAddr>,
    /// Path to the ca.key file
    #[clap(long, short = 'k')]
    ca_key: Option<PathBuf>,
    /// Path to the ca.cer file
    #[clap(long, short = 'c')]
    ca_cert: Option<PathBuf>,
    /// Write MITM cache description to this file
    #[clap(long, short = 'o')]
    out: Option<PathBuf>,
    #[command(subcommand)]
    cmd: Command,
}

#[tokio::main]
async fn main() -> Result<(), hudsucker::Error> {
    let args = Args::parse();
    let addr = args
        .listen
        .unwrap_or_else(|| SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 1337));

    let private_key_bytes = tokio::fs::read(args.ca_key.unwrap_or_else(|| "ca.key".into()))
        .await
        .unwrap();
    let ca_cert_bytes = tokio::fs::read(args.ca_cert.unwrap_or_else(|| "ca.cer".into()))
        .await
        .unwrap();
    let private_key = PrivatePkcs8KeyDer::from(
        pemfile::pkcs8_private_keys(&mut &private_key_bytes[..])
            .next()
            .unwrap()
            .expect("Failed to parse private key")
            .secret_pkcs8_der()
            .to_vec(),
    );
    let ca_cert = CertificateDer::from(
        pemfile::certs(&mut &ca_cert_bytes[..])
            .next()
            .unwrap()
            .expect("Failed to parse CA certificate")
            .to_vec(),
    );

    let key_pair = KeyPair::try_from(&private_key).expect("Failed to parse private key");
    let ca_cert_params = hudsucker::rcgen::CertificateParams::from_ca_cert_der(&ca_cert)
        .expect("Failed to parse CA certificate");
    let ca_cert = ca_cert_params
        .self_signed(&key_pair)
        .expect("Failed to generate CA certificate");
    let ca = RcgenAuthority::new(key_pair, ca_cert, 1_000);

    let pages = Arc::new(RwLock::new(Pages(
        BTreeMap::default(),
        args.out.unwrap_or_else(|| "out.json".into()),
    )));
    let proxy = Proxy::builder()
        .with_addr(addr)
        .with_rustls_client()
        .with_ca(ca)
        .with_http_handler(match args.cmd {
            Command::Replay { dir } => Handler::Replay(dir),
            Command::Record {
                forget_redirects_to,
                forget_redirects_from,
                record_text,
                reject,
            } => Handler::Record {
                client: Client::builder(TokioExecutor::new()).build(
                    HttpsConnectorBuilder::new()
                        .with_native_roots()
                        .unwrap()
                        .https_or_http()
                        .enable_http1()
                        .build(),
                ),
                pages: pages.clone(),
                forget_redirects_from,
                forget_redirects_to,
                record_text,
                reject,
            },
        })
        .with_graceful_shutdown(shutdown_signal())
        .build();

    tokio::spawn(async move {
        let mut ch =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::user_defined1()).unwrap();
        while let Some(()) = ch.recv().await {
            let pages = pages.read().await;
            let mut file = tokio::fs::File::create("tmp.json").await.unwrap();
            let mut buf = Vec::new();
            pages
                .0
                .serialize(&mut serde_json::Serializer::with_formatter(
                    &mut buf,
                    serde_json::ser::CompactFormatter,
                ))
                .unwrap();
            file.write_all(&buf).await.unwrap();
        }
    });
    proxy.start().await
}
