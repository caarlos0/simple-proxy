# simple-proxy

A small HTTP/HTTPS forward proxy with host blocking and structured request logs.
It uses only the Go standard library.

## Run

Add one hostname per line to `blocklist.txt`:

```text
# Blocks the host and all of its subdomains.
example.com
ads.example.net
```

Use ASCII/Punycode for internationalized hostnames. IP literals are
canonicalized before matching.

Then start the proxy:

```sh
go run . -listen 127.0.0.1:8080 -blocklist blocklist.txt
```

Use it with an HTTP client:

```sh
curl --proxy http://127.0.0.1:8080 http://example.org
curl --proxy http://127.0.0.1:8080 https://example.org
```

The blocklist is loaded at startup, so restart the proxy after changing it.
Each request is logged with its method, destination, client address, and whether
it was allowed or blocked. Query strings are omitted from logs. HTTPS uses
`CONNECT`, so the proxy logs the tunnel destination but cannot inspect requests
inside the encrypted tunnel.
