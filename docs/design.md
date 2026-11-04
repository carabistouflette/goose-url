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
6. **Owned Values & Zero Mutating Side-Effects**:
   - On error, parser functions return a cleanly typed `Error` with `ErrorKind` and byte `offset`.
   - Result structs own their allocated data stacks.

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

struct QueryParam {
    key:   u8[] = [],
    value: u8[] = [],
}
```

## Functions

- `parse(text: const u8[:]) -> Url, Error`
- `format(url: Url&, out: u8[>..])`
- `to_string(url: Url&) -> u8[>..]`
- `resolve(base: Url&, reference: const u8[:]) -> Url, Error`
- `remove_dot_segments(path: const u8[:], out: u8[>..])`
- `percent_decode(input: const u8[:], out: u8[>..]) -> bool`
- `percent_encode(input: const u8[:], out: u8[>..])`
- `parse_query(query: const u8[:]) -> QueryParam[>..]`
- `format_query(params: QueryParam[:], out: u8[>..])`
