use base64::Engine;
use clap::{Parser, Subcommand};
use dashmap::DashMap;
use hudsucker::{
    async_trait::async_trait,
    certificate_authority::RcgenAuthority,
    decode_request, decode_response,
    hyper::{client::HttpConnector, Body, Client, Request, Response},
    rustls,
    tokio_tungstenite::tungstenite::http::uri::Scheme,
    HttpContext, HttpHandler, Proxy, RequestOrResponse,
};
use hyper::{body::HttpBody, StatusCode, Uri};
use hyper_rustls::{HttpsConnector, HttpsConnectorBuilder};
use rustls_pemfile as pemfile;
use serde::{Deserialize, Serialize};
use sha2::Digest;
use std::{
    collections::BTreeMap,
    net::{Ipv4Addr, SocketAddr},
    path::PathBuf,
    sync::Arc,
};
use tokio::{io::AsyncReadExt, sync::RwLock};

async fn shutdown_signal() {
    tokio::signal::ctrl_c()
        .await
        .expect("Failed to install CTRL+C signal handler");
}

#[derive(Debug, Deserialize, Serialize)]
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
        client: hyper::Client<HttpsConnector<HttpConnector>, Body>,
        pages: Arc<RwLock<Pages>>,
        redirects: Arc<DashMap<Uri, Uri>>,
        forget_redirects_from: Option<regex::Regex>,
        forget_redirects_to: Option<regex::Regex>,
        record_text: Option<regex::Regex>,
        reject: Option<regex::Regex>,
    },
    Replay(PathBuf),
}

fn process_uri(uri: Uri, redirects: Option<&DashMap<Uri, Uri>>) -> (Uri, bool) {
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
    let ret = Uri::from_parts(parts).unwrap_or(uri);
    if let Some(redirects) = redirects {
        if let Some(ret) = redirects.get(&ret) {
            return (ret.value().clone(), true);
        }
    }
    (ret, false)
}

#[async_trait]
impl HttpHandler for Handler {
    async fn handle_request(
        &mut self,
        _ctx: &HttpContext,
        req: Request<Body>,
    ) -> RequestOrResponse {
        match self {
            Self::Record {
                client,
                pages,
                redirects,
                forget_redirects_to,
                forget_redirects_from,
                record_text,
                reject,
            } => {
                match req.method().as_str() {
                    "CONNECT" => req.into(),
                    "GET" | "POST" | "HEAD" => {
                        let original_url = req.uri().clone();
                        let Ok(req) = decode_request(req) else {
                            let mut res = Response::new("not found".into());
                            *res.status_mut() = StatusCode::NOT_FOUND;
                            return res.into();
                        };
                        let (info, body) = req.into_parts();
                        let Ok(req_body) = hyper::body::to_bytes(body).await else {
                            let mut res = Response::new("not found".into());
                            *res.status_mut() = StatusCode::NOT_FOUND;
                            return res.into();
                        };
                        let post_body = (info.method == "POST")
                            .then(|| std::str::from_utf8(&req_body).ok())
                            .flatten()
                            .map(ToOwned::to_owned);
                        let mut req = Request::from_parts(info, req_body.into());
                        let store_body_info = req.method() != "HEAD";
                        let (url, mut forget_redirect) =
                            process_uri(original_url, Some(&*redirects));
                        if matches!(reject, Some(x) if x.is_match(&url.to_string())) {
                            let mut res = Response::new("not found".into());
                            *res.status_mut() = StatusCode::NOT_FOUND;
                            return res.into();
                        }
                        let store_full_body = req.method() == "POST"
                            || matches!(record_text, Some(x) if x.is_match(&url.to_string()));
                        // contents may always be overwritten when forget_redirect == true,
                        // so we can't have any etags, or previously good contents may be
                        // overwritten with an empty response
                        req.headers_mut().remove("if-match");
                        req.headers_mut().remove("if-unmodified-since");
                        req.headers_mut().remove("if-modified-since");
                        let Ok(res) = client.request(req).await else {
                            let mut res = Response::new("not found".into());
                            *res.status_mut() = StatusCode::NOT_FOUND;
                            return res.into();
                        };
                        let Ok(mut res) = decode_response(res) else {
                            let mut res = Response::new("not found".into());
                            *res.status_mut() = StatusCode::NOT_FOUND;
                            return res.into();
                        };
                        if res.status().is_redirection() {
                            if let Ok(location) = res.headers().get("Location").unwrap().to_str() {
                                let mut pages = pages.write().await;
                                let page = pages.0.entry(url.to_string()).or_default();
                                let location = if let Ok(target) = location.parse::<Uri>() {
                                    let (target, _) = process_uri(target, Some(&*redirects));
                                    if !forget_redirect {
                                        forget_redirect =
                                            matches!(forget_redirects_from, Some(x) if x.is_match(&url.to_string()))
                                            || matches!(forget_redirects_to, Some(x) if x.is_match(&target.to_string()));
                                    }
                                    if forget_redirect {
                                        redirects.insert(target.clone(), url.clone());
                                    }
                                    target.to_string()
                                } else {
                                    location.to_owned()
                                };
                                let contents = Contents::Redirect(location.to_owned());
                                if let Some(post_body) = post_body {
                                    page.post_responses.entry(post_body).or_insert(contents);
                                } else if forget_redirect || page.contents.is_none() {
                                    page.contents = Some(contents);
                                }
                            }
                            res
                        } else if res.status().is_success() {
                            if store_body_info {
                                let (info, mut body) = res.into_parts();
                                let (mut tx, ret_body) = Body::channel();
                                let pages = pages.clone();
                                tokio::spawn(async move {
                                    let mut sha256 = sha2::Sha256::new();
                                    let mut contents = Vec::<u8>::new();
                                    while let Some(data) = body.data().await {
                                        let Ok(data) = data else {
                                            return;
                                        };
                                        if store_full_body {
                                            contents.extend_from_slice(&data);
                                        }
                                        sha256.update(&data);
                                        if tx.send_data(data).await.is_err() {
                                            break;
                                        }
                                    }
                                    let base64 = base64::engine::general_purpose::STANDARD
                                        .encode(sha256.finalize());
                                    let mut pages = pages.write().await;
                                    let page = pages.0.entry(url.to_string()).or_default();
                                    let contents = if let Some(contents) =
                                        std::str::from_utf8(&contents)
                                            .ok()
                                            .filter(|_| store_full_body)
                                    {
                                        Contents::Text(contents.to_owned())
                                    } else {
                                        Contents::Sha256(base64)
                                    };
                                    if let Some(post_body) = post_body {
                                        page.post_responses.entry(post_body).or_insert(contents);
                                    } else if forget_redirect || page.contents.is_none() {
                                        page.contents = Some(contents);
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
                }
            }
            Self::Replay(dir) => match req.method().as_str() {
                "CONNECT" => req.into(),
                "HEAD" | "GET" => {
                    let mut path = dir.clone();
                    let (url, _) = process_uri(req.uri().clone(), None);
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
                        let (mut tx, body) = Body::channel();
                        if req.method().as_str() != "HEAD" {
                            tokio::spawn(async move {
                                let mut buf = vec![0u8; 65536];
                                while let Ok(n) = file.read(&mut buf).await {
                                    if n == 0
                                        || tx.send_data(buf[..n].to_vec().into()).await.is_err()
                                    {
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

    async fn handle_response(&mut self, _ctx: &HttpContext, res: Response<Body>) -> Response<Body> {
        res
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
async fn main() {
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
    let private_key = rustls::PrivateKey(
        pemfile::pkcs8_private_keys(&mut &private_key_bytes[..])
            .next()
            .unwrap()
            .expect("Failed to parse private key")
            .secret_pkcs8_der()
            .to_vec(),
    );
    let ca_cert = rustls::Certificate(
        pemfile::certs(&mut &ca_cert_bytes[..])
            .next()
            .unwrap()
            .expect("Failed to parse CA certificate")
            .to_vec(),
    );

    let ca = RcgenAuthority::new(private_key, ca_cert, 1_000)
        .expect("Failed to create Certificate Authority");

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
                client: Client::builder().build(
                    HttpsConnectorBuilder::new()
                        .with_native_roots()
                        .https_or_http()
                        .enable_http1()
                        .build(),
                ),
                pages: pages.clone(),
                redirects: Arc::default(),
                forget_redirects_from,
                forget_redirects_to,
                record_text,
                reject,
            },
        })
        .build();

    tokio::spawn(async move {
        let mut ch =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::user_defined1()).unwrap();
        while let Some(()) = ch.recv().await {
            let pages = pages.read().await;
            pages
                .0
                .serialize(&mut serde_json::Serializer::with_formatter(
                    std::fs::File::create("tmp.json").unwrap(),
                    serde_json::ser::CompactFormatter,
                ))
                .unwrap();
        }
    });
    if let Err(e) = proxy.start(shutdown_signal()).await {
        eprintln!("{}", e);
    }
}
