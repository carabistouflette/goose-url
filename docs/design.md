# Design scope

A small, pure-Goose, byte-oriented generic URI library. The authoritative
public contract is [API.md](API.md). The implementation adds no native package,
network requests or filesystem operations. The compiler/runtime is still required.

Parser views borrow slices; owned parsing copies them. Components are validated
before allocation or reconstruction where possible. IPv6/IPvFuture grammar is
isolated in the iterative `url_address` helper. Literal delimiters and percent
escapes remain separate: decoding is explicit and does not occur before parsing.
Numeric port policy is 0..65535, deliberately narrower than generic RFC syntax.

Public encoded-component setters validate raw input before normalization and
validate the final fields to prevent delimiter injection. Serialization checks
public structs, including authority/path shape and empty-component presence flags.
Query parsing is all-or-error. Append-style output operations preflight limits
and syntax before writing so errors cannot return a valid-looking prefix.

The URI cap is 65536 bytes and query count cap is 1024. Resolution may reduce an
intermediate merged path up to twice the input cap. Query sorting uses borrowed
key views inside a separate order-building scope, then copies owned records;
key lookup no longer adds a linear traversal to each insertion-sort comparison.
It intentionally orders bytes, not WHATWG UTF-16 units.

RFC 3986 syntax/resolution and form-style byte encoding are the scope. Browser
URL normalization, IDNA, scheme-specific routing policy, Unicode coercion and
security origin identity are excluded. Benchmarks describe exact workloads and
retain source/toolchain/raw samples; no universal performance claim is implied.
