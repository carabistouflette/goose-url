# URI Parser and Resolver Contract

Pure Goose implementation of Uniform Resource Identifiers (URI) conforming to RFC 3986.
Zero native C shims, zero foreign function calls, completely memory-safe. Goose compiler
pinned by `GOOSE_REVISION`.

## Core Interface

- `parse_view(raw: const u8[:]) -> UrlView, Error`:
  Zero-copy parser returning sub-slice views referencing `raw`. Performs character-set
  validation, scheme/authority/path/query/fragment boundary decomposition, port parsing,
  and IPv6 bracket syntax verification without allocating heap storage.
- `parse(raw: const u8[:]) -> Url, Error`:
  Owned parser. Returns a `Url` with normalized lowercase scheme and host buffers,
  and owned growable buffers (`u8[]`) for userinfo, path, query, and fragment.
- `to_string(url: Url&) -> u8[>..]`:
  Reconstructs the full RFC 3986 URI string into a newly allocated builder buffer.
- `format(url: Url&, out: u8[>..]&)`:
  Appends the reconstructed URI representation onto an existing builder buffer `out`.
- `resolve(base: Url&, reference: const u8[:]) -> Url, Error`:
  Full RFC 3986 §5.2 reference resolution algorithm. Resolves relative references,
  relative paths, network paths (`//...`), and queries against `base`. Removes dot-segments
  from the target path per RFC 3986 §5.2.4.
- `remove_dot_segments(path: const u8[:], out: u8[>..]&)`:
  Normalizes path segments (`.` and `..`) per RFC 3986 §5.2.4.
- `percent_decode(input: const u8[:], out: u8[>..]&) -> bool`:
  Decodes percent-encoded octets (`%XX`). Returns `false` on truncated or non-hex sequences.
- `percent_encode(input: const u8[:], out: u8[>..]&)`:
  Encodes bytes outside the unreserved character set (`ALPHA / DIGIT / "-" / "." / "_" / "~"`).
- `parse_query(query: const u8[:]) -> QueryParam[>..]`:
  Parses `application/x-www-form-urlencoded` query strings into key-value pairs (`+` <-> space).
- `format_query(params: QueryParam[:], out: u8[>..]&)`:
  Serializes query parameters into form-urlencoded format.

## WHATWG URL Compatibility Surface

- `query_has(params: QueryParam[:], key: const u8[:]) -> bool`:
  Checks whether a query parameter with `key` exists.
- `query_get(params: QueryParam[:], key: const u8[:], out: u8[>..]&) -> bool`:
  Retrieves the first value associated with `key` into `out`. Returns `false` if not found.
- `query_append(params: QueryParam[>..]&, key: const u8[:], value: const u8[:])`:
  Appends a new query parameter pair to `params`.
- `query_set(params: QueryParam[>..]&, key: const u8[:], value: const u8[:])`:
  Sets the value of `key` to `value`, updating the first occurrence and removing subsequent duplicates per WHATWG §6.3.
- `query_delete(params: QueryParam[>..]&, key: const u8[:])`:
  Removes all occurrences of `key` from `params`.
- `query_sort(params: QueryParam[>..]&)`:
  Sorts query parameter pairs by key bytes using a stable sort per WHATWG §6.3.
- `origin(url: Url&, out: u8[>..]&)` / `origin_string(url: Url&) -> u8[>..]`:
  Computes the ASCII serialization of the URL's origin per WHATWG §4.2. Omits default ports
  (80 for `http`/`ws`, 443 for `https`/`wss`, 21 for `ftp`). Returns `"null"` for opaque schemes (`file:`, `urn:`).
- `clone_url(url: Url&) -> Url`:
  Clones a `Url` with newly owned deep copies of all buffer containers.
- `with_scheme(url: Url&, new_scheme: const u8[:]) -> Url, bool`:
  Functional modifier returning an updated `Url` with validated lowercase scheme.
- `with_host(url: Url&, new_host: const u8[:]) -> Url, bool`:
  Functional modifier returning an updated `Url` with validated lowercase host (including bracketed IPv6).
- `with_port(url: Url&, new_port: i32) -> Url, bool`:
  Functional modifier returning an updated `Url` with validated port (`0..65535` or `-1` to clear).
- `with_path(url: Url&, new_path: const u8[:]) -> Url`:
  Functional modifier returning an updated `Url` with dot-segment-normalized path.
- `with_query(url: Url&, new_query: const u8[:]) -> Url`:
  Functional modifier returning an updated `Url` with updated query string.
- `with_fragment(url: Url&, new_frag: const u8[:]) -> Url`:
  Functional modifier returning an updated `Url` with updated fragment string.

## Hard Bounds & Guarantees

- **Length Bound**: `MAX_URL_BYTES = 65536` (64 KiB). Input strings and reconstructed URIs
  exceeding this limit fail with `ErrorKind.TooLong`.
- **Query Parameter Cap**: `MAX_QUERY_PARAMS = 1024`. Prevents hash-collision or memory-exhaustion
  denial of service on pathological query strings.
- **Port Bounds**: Explicitly checked to fit `0..65535`. Non-digit or overflowing ports return
  `ErrorKind.InvalidPort`.
- **IPv6 Syntax**: Bracketed hosts (`[...]`) must contain at least one `:` and strictly valid
  hexadecimal digits or dots (for IPv4-mapped IPv6). Malformed bracketed hosts return
  `ErrorKind.InvalidHost`.
- **Error Safety**: On error, parser functions return a cleanly typed `Error` structure with
  `kind` and byte `offset`. Returned URL structs are default-initialized; no partial state leaks.

## Security & Non-Goals

- **SSRF Authorization**: Path normalization and URI parsing do NOT validate whether a target
  network address is safe or allowed. Callers accepting untrusted input must inspect `host` and
  `port` and enforce authorization policies prior to opening sockets or making HTTP requests.
- **No Native Dependencies**: Does not link to platform resolver libraries or external C runtimes.
