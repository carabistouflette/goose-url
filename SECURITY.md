# Security

Report suspected vulnerabilities through private communication with repository maintainers.
Include the affected commit, Goose compiler version, platform, and a minimal reproducer.
Keep exploit details out of public issues until a fix is available.

`goose-url` is a pure Goose implementation of RFC 3986 Uniform Resource Identifiers.
It contains zero native C shims, memory allocations outside Goose runtime guarantees, or external network access.

Security considerations for callers:
- **Length Bounds**: Input strings and total reconstructed URIs are capped at `MAX_URL_BYTES` (64 KiB) and query parameter count at `MAX_QUERY_PARAMS` (1024) to avoid resource exhaustion and algorithmic complexity attacks.
- **SSRF and Authorization**: URI parsing and reference resolution normalize paths (including RFC 3986 dot-segment removal), but do NOT validate destination safety or network policy. Applications accepting untrusted URLs must validate destination schemes, hosts (including IPv4/IPv6 literals and DNS rebinding risks), and ports before dispatching network requests.
- **Percent-Encoding**: `percent_decode` strictly checks `%XX` hex sequences and returns `false` on malformed percent sequences rather than silently dropping or passing through corrupt bytes.
