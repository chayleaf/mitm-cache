# MITM cache

This is a caching MITM proxy for fetching the dependencies of poorly
designed build systems. To use it, first create a root CA cert using
`./generate.sh`, and then:

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

After recording it, use [fetch.nix](./fetch.nix) for fetching the
dependencies ([default.nix](./default.nix) provides it at
`mitm-cache.fetch`), and pass the resulting derivation output to
`mitm-cache replay`:

```
Usage: mitm-cache replay <DIR>

Arguments:
  <DIR>  Path to the cache fetched using fetch.nix

Options:
  -h, --help  Print help
```
