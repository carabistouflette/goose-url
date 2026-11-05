# Design scope

goose-url is a pure Goose byte parser and resolver. It follows RFC 3986 syntax and reference resolution, with form-style byte query encoding. It adds no native package, network request or filesystem operation.

The library keeps parsing, percent decoding and application policy separate. Parse views borrow input; owned parsing copies fields. Setters validate components before serialization. Output helpers check limits before appending so failure does not leave a partial value.

Inputs and serialized outputs are limited to 65,536 bytes; query operations allow up to 1,024 nonempty pairs. The API does not implement browser URL normalization, IDNA, Unicode replacement, scheme-specific routing or security origin checks.

See the [API contract](API.md) for exact behavior and limits. Benchmarks compare named workloads with different contracts; see [their scope and results](../bench/README.md).
