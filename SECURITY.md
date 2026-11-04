# Security

Report suspected vulnerabilities using
[GitHub private vulnerability reporting](https://github.com/carabistouflette/goose-url/security/advisories/new).
Include affected revision, compiler/platform and a minimal reproducer. Keep
details private until a fix is available.

The parser validates ASCII generic URI syntax, component delimiters, percent
escapes, IPv6/IPvFuture literals and the documented numeric-port policy. It does
not resolve names, connect to hosts, apply IDNA or implement browser URL rules.
It accepts generic empty authorities and relative references. Parsing does not
authorize destinations, schemes, ports, resolved addresses or filesystem paths.
Applications own SSRF, DNS-rebinding, redirect and network policy.

`origin_string` is not a browser origin or same-origin check. Case folding is not
full canonicalization; host escapes are not decoded into a DNS identity. Parsed
strings and decoded query bytes remain untrusted: escape for terminals/HTML and
reject disallowed bytes, including NUL, before use in another API. Decode only at
the intended layer; percent-encoded dot segments are not literal dot segments.

URI inputs/serialized outputs are capped at 65536 bytes. Query operations also
limit parameters to 1024 and enforce bounded decoded storage or encoded output
as described in the API. Malformed/oversized query input returns no partial set.
Check all errors/boolean returns. Append-style codecs/serializers preserve the
old destination on failure; component setters reject delimiters rather than
silently changing component meaning. Public structs are checked at serialization.
Resolution may use an intermediate path up to twice the input cap. These bounds
are not an exact allocator, stack or process memory limit.

The implementation is pure Goose; compiler/runtime defects remain possible.
Tests, sanitizers and reviews improve evidence but do not prove absence of bugs.
Only the documented platform/toolchain has been validated.
