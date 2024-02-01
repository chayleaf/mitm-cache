#! /usr/bin/env nix-shell
#! nix-shell -i bash -p openssl
openssl genrsa -out ca.key 2048
openssl req -x509 -new -nodes -key ca.key -sha256 -days 1 -out ca.cer -subj "/C=AL/ST=a/L=a/O=a/OU=a/CN=example.org"
