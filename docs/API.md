# API contract

The library parses generic URI references, not browser URLs. Inputs are bytes; URI syntax is ASCII, so percent-encode other octets. Empty input is a valid reference.

## Parse, format and resolve

- `parse_view(raw)` returns component slices borrowed from `raw`.
- `parse(raw)` returns owned fields and lowercases the ASCII scheme and host. Numeric ports serialize without leading zeroes.
- `format(url, out)` appends a checked serialization. `to_string(url)` returns a new serialized value.
- `resolve(base, reference)` requires a base with a scheme and applies RFC 3986 section 5.2.
- `remove_dot_segments(path, out)` reduces literal dot segments without validating URI path syntax.

Parsing does not decode percent escapes, normalize IP spellings or remove dot segments. Numeric ports are limited to 0–65535. IPv6 and IPvFuture literals are parsed; zone identifiers, raw Unicode/IRIs, IDNA and browser IPv4 rules are not supported. A parsed host is not proof of a routable address.

`Url` and `UrlView` preserve whether authority, userinfo, port, query and fragment delimiters were present, including empty values. An explicitly empty port differs from no port. `parse` returns empty fields on failure; a failed `parse_view` can retain raw input for diagnostics. Error offsets identify detected boundaries and may not point to the first invalid byte.

`ErrorKind` includes `None`, `TooLong`, `EmptyInput`, `InvalidScheme`, `InvalidAuthority`, `InvalidUserinfo`, `InvalidHost`, `InvalidPort`, `InvalidPath`, `InvalidQuery`, `InvalidFragment` and `InvalidPercentEncoding`. Empty input is a valid URI reference.

Input and serialized output are limited to 65,536 bytes. Existing output prefixes count toward that limit. Resolution may merge two bounded paths before reducing them, but the final URI must fit. Serialization validates caller-created values. Borrowed inputs and output buffers must not overlap.

Append-style formatting and codecs leave the old output unchanged on failure. Check return values; a valid empty URI and a failed serialization can both produce empty bytes.

## Percent and query data

`percent_encode` leaves RFC unreserved bytes unchanged and writes uppercase `%HH` escapes for other bytes. `percent_decode` rejects malformed escapes and does not treat `+` as a space.

Query helpers use form-style encoding. Parsing maps `+` to space, decodes `%HH`, splits on `&` and only the first `=`, skips empty pairs, and preserves duplicate keys and order. A key without `=` gets an empty value. Values are arbitrary bytes and may contain NUL; validate them before passing them to text, terminal, HTML, path or network APIs.

There may be at most 1,024 nonempty query pairs. Parsing is all-or-error. Query formatting maps spaces to `+`; ASCII letters/digits and `*-._` remain literal, and other bytes use uppercase percent escapes. Every formatted pair is `key=value`. Encoded and decoded storage is bounded by the same 65,536-byte limit. Escaping can make formatting fail even when parsed data fits.

`QueryParam` owns decoded keys and values. `query_has` checks for a key; `query_get` appends the first value and preserves its output if it returns false. `query_append` adds a pair; `query_set` replaces the first match and removes later duplicates; `query_delete` removes all matches; `query_sort` uses stable byte order, not WHATWG UTF-16 order. Sorting uses quadratic comparisons, bounded to 1,024 pairs. Mutations leave the list unchanged on failure.

## Component setters and origin formatting

`with_scheme`, `with_host`, `with_port`, `with_path`, `with_query` and `with_fragment` return a value and a success flag. A bad edit preserves a valid original; an invalid original returns an empty value and false. Setters validate raw component syntax before constructing the result. Host and scheme edits fold ASCII case. Port `-1` clears the port; other accepted values are 0–65535. With an authority, a path must be empty or begin with `/`. A path edit rejects literal `?` and `#`. Empty query or fragment edits clear that component. Setters take a component, not a complete URL.

`origin` and `origin_string` format a limited tuple for `http`, `https`, `ws`, `wss` and `ftp`. They omit the usual numeric port and do not implement browser origin rules, IDNA or same-origin authorization. Unsupported or invalid input is formatted as `null` by `origin`; `origin_string` returns empty bytes on invalid input. Do not use either as a security check.

See [security considerations](../SECURITY.md) and [test coverage](../tests/README.md).
