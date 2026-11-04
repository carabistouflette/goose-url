# Contributing

Keep the library small, pure Goose and byte-oriented. Preserve its explicit
ownership, syntax, atomic-error and resource contracts in [docs/API.md](docs/API.md).
RFC 3986 is the generic syntax/resolution reference; do not silently substitute
browser normalization or claim WHATWG compatibility for byte helpers.

Behavior fixes need regression tests for malformed input, bounds and unchanged
outputs on failure. Run `make format check test fuzz`, GCC and Clang `make sanitize`,
and `git diff --check`. Request independent correctness/security review and fix
concrete findings. No performance or memory-safety superlatives: preserve validation
and retain raw measured samples, flags, source hashes and workload boundaries.

Use focused Conventional Commits with imperative subjects (`fix: reject ...`,
`test: cover ...`, `docs: clarify ...`). Do not commit credentials, generated builds
or private planning. Preserve Apache-2.0 headers/license and third-party notices.
Experimental APIs can change before 1.0; document changes rather than implying
compatibility. Report vulnerabilities through [SECURITY.md](SECURITY.md).
