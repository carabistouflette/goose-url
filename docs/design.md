# Design Contract — goose-url

`goose-url` is a pure Goose implementation of Uniform Resource Identifier (URI) parsing, validation, resolution, and percent-encoding in strict conformance with **RFC 3986**.

## Scope and Invariants

1. **Pure Goose**: Zero native dependencies, zero foreign function calls, completely memory-safe.
2. **Deterministic & Bounded**:
   - `MAX_URL_BYTES = 65536`. Reject inputs exceeding this cap with `ErrorKind.TooLong`.
   - Maximum query parameters: 1024.
   - Zero unbounded recursion or stack allocation loops.
3. **RFC 3986 Syntax**:
   - Generic URI: `<scheme>://<userinfo>@<host>:<port><path>?<query>#<fragment>`
   - Supports URIs with or without authority (e.g. `file:///etc/passwd`, `mailto:user@example.com`, `urn:isbn:0451450523`).
   - Supports Relative References (e.g. `//example.com/foo`, `/bar`, `baz?q=1`, `#top`).
   - IPv6 host addresses enclosed in brackets (e.g. `http://[::1]:8080/`).
4. **RFC 5.2 Reference Resolution**:
   - Implements full relative-to-base resolution algorithm (`resolve(base, relative)`).
   - Strict normalization of dot segments (`.` and `..`) per RFC 3986 Section 5.2.4.
5. **Percent-Encoding & Query Codec**:
   - Safe byte-level percent encoding and decoding (`%HH`).
   - Standard `application/x-www-form-urlencoded` query encoding and decoding (`+` <-> space).
6. **High Performance & Zero-Copy Architecture**:
   - 256-byte character classification bitmap table (`CHAR_FLAGS`) providing $O(1)$ single-instruction checks (`is_unreserved`, `is_pchar`, `is_scheme_char`, `is_alpha`, `is_digit`, `is_hex_digit`).
   - 256-byte hex value lookup table (`HEX_VAL`) enabling branchless two-hex-digit validation in percent decoding `(h1 | h2) >= 0x80`.
   - Zero-copy view parsing (`parse_view`) returning `UrlView` with sub-slices directly into input memory with zero heap or buffer allocations (>9.2M ops/sec).
   - Bulk memory transfers with contiguous slice appends (`out.append(...)`) across all reconstruction, merging, and dot-segment routines.
   - Backward-scanning in dot-segment removal avoiding quadratic overheads.

## Types

```goose
enum ErrorKind {
    None,
    TooLong,
    EmptyInput,
    InvalidScheme,
    InvalidAuthority,
    InvalidUserinfo,
    InvalidHost,
    InvalidPort,
    InvalidPath,
    InvalidQuery,
    InvalidFragment,
    InvalidPercentEncoding,
}

struct Error {
    kind:   ErrorKind = ErrorKind.None,
    offset: i64       = 0,
}

// Owned URI representation with growable buffers
struct Url {
    scheme:        u8[] = [],
    has_authority: bool = false,
    userinfo:      u8[] = [],
    host:          u8[] = [],
    port:          i32  = -1,   // -1 indicates omitted port
    path:          u8[] = [],
    has_query:     bool = false,
    query:         u8[] = [],
    has_fragment:  bool = false,
    fragment:      u8[] = [],
}

// Zero-copy non-allocating URI view referencing slices of the original input
struct UrlView {
    raw:           const u8[:] = "",
    scheme:        const u8[:] = "",
    has_authority: bool        = false,
    userinfo:      const u8[:] = "",
    host:          const u8[:] = "",
    port:          i32         = -1,
    path:          const u8[:] = "",
    has_query:     bool        = false,
    query:         const u8[:] = "",
    has_fragment:  bool        = false,
    fragment:      const u8[:] = "",
}

struct QueryParam {
    key:   u8[] = [],
    value: u8[] = [],
}
```

## Functions

- `parse_view(raw: const u8[:]) -> UrlView, Error` (Zero-copy non-allocating parser)
- `parse(raw: const u8[:]) -> Url, Error` (Owned parser with normalized fields)
- `format(url: Url&, out: u8[>..]&)`
- `to_string(url: Url&) -> u8[>..]`
- `resolve(base: Url&, reference: const u8[:]) -> Url, Error`
- `remove_dot_segments(path: const u8[:], out: u8[>..]&)`
- `percent_decode(input: const u8[:], out: u8[>..]&) -> bool`
- `percent_encode(input: const u8[:], out: u8[>..]&)`
- `parse_query(query: const u8[:]) -> QueryParam[>..]`
- `format_query(params: QueryParam[:], out: u8[>..]&)`
