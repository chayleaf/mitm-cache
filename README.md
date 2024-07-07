# MITM cache

This is a caching MITM proxy for fetching the dependencies of poorly
designed build systems. To use it, first create a root CA cert using
`./generate.sh`, and then run the proxy:

```
Usage: mitm-cache [OPTIONS] <COMMAND>

Commands:
  record  
  replay  
  help    Print this message or the help of the given subcommand(s)

Options:
  -l, --listen <LISTEN>    Proxy listen address
  -k, --ca-key <CA_KEY>    Path to the ca.key file
  -c, --ca-cert <CA_CERT>  Path to the ca.cer file
  -o, --out <OUT>          Write MITM cache description to this file
  -h, --help               Print help
```

```
Usage: mitm-cache record [OPTIONS]

Options:
  -r, --record-text <RECORD_TEXT>
          Record text from URLs matching this regex
  -x, --reject <REJECT>
          Reject requests to URLs matching this regex
  -f, --forget-redirects-from <FORGET_REDIRECTS_FROM>
          Forget redirects from URLs matching this regex
  -t, --forget-redirects-to <FORGET_REDIRECTS_TO>
          Forget redirects to URLs matching this regex
  -h, --help
          Print help
```

While the cache is running, you can send `SIGUSR1` to write the current
cache into `tmp.json`. At the end, you should send `SIGINT` to make the
proxy write the final cache into `out.json`, and then
use [fetch.nix](./fetch.nix) for fetching the dependencies
([default.nix](./default.nix) provides it at `mitm-cache.fetch`), and
finally pass the resulting derivation output to `mitm-cache replay`:

```
Usage: mitm-cache replay <DIR>

Arguments:
  <DIR>  Path to the cache fetched using fetch.nix

Options:
  -h, --help  Print help
```

## Lockfile Format

```json
{
  "!version": 1,
  "https://example.org/a": {
    "hash": "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
  },
  "https://example.org/b": {
    "text": "example"
  },
  "https://example.org/c": {
    "redirect": "https://example.org/d"
  }
}
```

`!version` specifies the lockfile version. `fetch.nix` is maintained to support
all lockfile versions, but mitm-cache only supports creating the
latest lockfile version.

Per-URL value is a JSON object containing one of the following keys:

- `hash` - specifies the response body's [SRI hash](https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity#using_subresource_integrity)
- `text` - specifies the response body as text. Only written if the
  `--record-text` regex matches this URL.
- `redirect` - specifies the URL this page redirects to. If
  any of the `--forget-redirects-*` rules apply, the target page's
  value will be written as the page's value instead.
