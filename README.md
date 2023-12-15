# MITM cache

This is a caching MITM proxy for fetching the dependencies of poorly
designed build systems. To use it:

1. Create a root CA cert, using `./generate.sh`
2. Run the proxy in a dir with `ca.key` and `ca.cer` files via
   `mitm-cache 127.0.0.1:1234`
3. Configure the application to use this as the http/https proxy
4. After making the application fetch the necessary files, kill
   `mitm-cache` with SIGINT - it should produce `out.json` containing
   hashes of all downloaded files
5. Check the resulting JSON into nixpkgs and use
   `mitm-cache.fetch { data = builtins.readJSON ./deps.json; }` to fetch
   all dependencies
6. Add `mitm-cache` to `nativeBuildInputs`, and pass the dependencies to
   the derivation via the `mitmCache` env var. The proxy port defaults
   to 1337, but you can override it with `mitmCachePort`. To get access
   to `ca.cer` in derivation phases, use the `$MITM_CACHE_CA` env var
   set in the configure hook. To get the proxy address, use
   `$MITM_CACHE_ADDRESS` (127.0.0.1:1337), `$MITM_CACHE_HOST`
   (127.0.0.1), `$MITM_CACHE_PORT` (1337).
