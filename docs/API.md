# API contract

Experimental generic URI references, not WHATWG/browser URLs. The public contract
is the functions listed here; other functions in `url.goose` and `address.goose`
are implementation helpers. Inputs are bytes. URI syntax requires ASCII; use
percent escapes for other octets. Query/percent codecs operate on arbitrary bytes.

## Types and parsing

`Error { kind: ErrorKind, offset: i64 }`: `None` means success. Other kinds include
`TooLong`, `InvalidScheme`, `InvalidAuthority`, `InvalidUserinfo`, `InvalidHost`,
`InvalidPort`, `InvalidPath`, `InvalidQuery`, `InvalidFragment` and
`InvalidPercentEncoding`. Offsets identify a detected byte/component boundary;
constructed-value/resource errors can use zero. They are not always a pinpoint
location of the first invalid byte. Empty input is a valid reference.

`UrlView` borrows `raw`, `scheme`, `userinfo`, `host`, `path`, `query`, `fragment`.
`Url` owns the corresponding fields. Both contain `has_authority`, `has_userinfo`,
`has_port`, `has_query`, `has_fragment` flags and numeric `port: i32` (`-1` means
no numeric value). `has_port=true, port=-1` preserves an explicitly empty port.
`has_userinfo=true` preserves an empty userinfo delimiter. A failed owned parse
returns empty fields; a failed view can retain `raw` for caller diagnostics.

- `parse_view(raw) -> UrlView, Error`: nonallocating borrowed component view.
- `parse(raw) -> Url, Error`: owned fields; lowercases ASCII scheme/host. Numeric
  ports serialize without leading zeroes. It does not remove path dot segments,
  decode host/path escapes or canonicalize IP spelling.

Syntax follows RFC 3986, including relative references, empty generic authorities,
IPv6 and IPvFuture literals. Numeric ports are deliberately restricted to
0..65535. Zone identifiers, raw Unicode/IRIs, IDNA and browser IPv4 rules are not
implemented. Invalid dotted-decimal-looking names can be generic reg-names;
parsing them is not validation of a routable IPv4 address. Empty HTTP hosts and
scheme-specific requirements remain application policy.

## Serialization, resolution and path reduction

- `format(value: Url&, out: u8[>..]&) -> Error`: checks every field, delimiter flag,
  path shape and final byte length before appending. Failure preserves `out`.
- `to_string(value: Url&) -> u8[>..], Error`: same validation, fresh output; empty
  output on error. Check the error because an empty valid reference also exists.
- `resolve(base: Url&, reference) -> Url, Error`: validates an absolute base with
  a scheme, parses the reference, and applies RFC 3986 section 5.2. It reduces
  literal dot segments, not percent-encoded dots. Errors return an empty Url.
- `remove_dot_segments(path, out) -> bool`: bounded byte-level section 5.2.4
  reduction, appended atomically. This helper does not validate URI path grammar.

Inputs and serialized outputs are at most `MAX_URL_BYTES=65536`. An existing
output prefix counts against the limit. Resolution can merge two bounded paths
(up to twice that cap) before reduction, but the final URI must fit. Caller-owned
structs can be manually assembled; serialization validates those fields rather
than treating them as trusted parsed values. Borrowed input and writable outputs
must not overlap; the pinned compiler enforces ordinary borrow restrictions.

## Percent and query codecs

- `percent_encode(input, out) -> bool`: RFC unreserved bytes remain literal;
  others use uppercase `%HH`.
- `percent_decode(input, out) -> bool`: strict escapes; does not map `+` to space.
- `parse_query(input) -> QueryParam[>..], Error`: strict form-style decoding;
  `+` maps to space, `%HH` to bytes. Split on `&`, skip empty pairs, split only the
  first `=`, preserve duplicates/order, and use empty value for a bare key.
  Malformed escapes/overflow return an empty set and an error, never a prefix.
- `format_query(params, out) -> bool`: space maps to `+`; ASCII letters/digits and
  `*-._` remain literal; other bytes are `%HH`. Every pair is `key=value`.

All input byte slices in these codecs are capped at 65536. Encoders also check
expanded output plus existing prefix before writing. Decoder failure preserves
that prefix, including on a late malformed escape. Decoded values need not be
UTF-8 and may include NUL. This is not WHATWG Unicode replacement behavior.
`MAX_QUERY_PARAMS=1024` counts nonempty input pairs. Query formatting, append and set
check the encoded 65536-byte budget; inspection/deletion/sorting check decoded
storage and parameter caps. Consequently valid byte query data can parse yet fail
formatting if escaping expands it beyond the budget.

## Query operations

`QueryParam { key: u8[], value: u8[] }` owns decoded bytes.

- `query_has(params, key) -> bool`: first matching key exists.
- `query_get(params, key, out) -> bool`: append the first matching value; false
  for absent key or resource failure, preserving the old output on false.
- `query_append(params&, key, value) -> bool`: append a copied pair.
- `query_set(params&, key, value) -> bool`: replace the first and remove later
  duplicates; append if absent.
- `query_delete(params&, key) -> bool`: remove all matching pairs.
- `query_sort(params&) -> bool`: stable lexicographic byte ordering. This is not
  URLSearchParams' UTF-16 code-unit order. It uses quadratic key comparisons with
  constant-time key lookup, bounded to 1024 pairs and 65536 decoded bytes.

Mutation failures leave the old list unchanged. Inspection returns false for
invalid caller-constructed storage. Inputs to mutation must not borrow mutable
list storage across the call; copy a key/value first if needed.

## Component edits and tuple formatting

`with_scheme`, `with_host`, `with_port`, `with_path`, `with_query`, `with_fragment`
return `(Url, bool)`. They copy a valid original, validate the raw edit and the
resulting fields/length, and return the original copy on invalid edit. Invalid
original structs return an empty Url and false. Scheme/host fold ASCII case.
Host edits take a host only, not userinfo or a port. Paths are already encoded
components: an authority requires empty or slash-prefixed path; literal `?`/`#`
are rejected before path reduction. An empty query/fragment edit clears that
component. Port `-1` clears an explicit port; other accepted ports are 0..65535.

`origin(value, out) -> bool` formats a limited tuple for lowercase `http`, `https`,
`ws`, `wss`, `ftp` with nonempty authority host, omitting its usual numeric port;
otherwise it appends `null`. Invalid input/output overflow returns false without
writing. `origin_string(value) -> bytes` is a convenience returning empty on
invalid input. These functions do not implement browser host/IDNA normalization,
blob origins or same-origin authorization. Use an actual browser URL model when
that security contract is required.
