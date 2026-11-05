# Artifact example validation

The optional [caller example](../examples/artifact/README.md) checks an
independently configured HTTPS host and port before passing the original URL to
the pinned artifact downloader. Core URL/HTTP APIs and existing consumer,
release and parent pins are unchanged.

## Local tested source

Clean commit `902a8d72330e3b0aab5a2cf8f721d80f7ece2c72` passed all four runs:

```sh
make artifact-check CC=gcc ARTIFACT_FLAGS=--bench
make artifact-check CC=gcc ARTIFACT_FLAGS=--sanitize
make artifact-check CC=clang ARTIFACT_FLAGS=--bench
make artifact-check CC=clang ARTIFACT_FLAGS=--sanitize
```

Each passed 80 policy/libcurl cases and 17 real artifact-consumer cases: accepted
authority agreement, IPv6 semantics, encoded delimiters, numeric aliases, bounds,
signed publication, redirects/non-200, production TLS trust rejection, signature/
digest/signed-URL mismatch, body limits and policy rejection before download or
mutation. Existing sentinel bytes and absence of staging/final output on rejection
are checked. Expected errors require exact stages/exits; a crash cannot pass.

Sanitizers instrument generated Goose/runtime and native adapters, including a
mixed C/C++ vptr link preflight. Installed system libraries are not instrumented.
Core normal/debug/no-BCE tests and seeded fuzz checks also passed, including core
GCC/Clang ASan/UBSan. A failed-rerun regression verified removal of a prior passed
report when the selected compiler cannot be started.

Reports fingerprint source, compiler, immutable dependency source/license and
consumer binary bytes before/after execution, and retain effective commands and
per-case outcomes. Backend versions are pkg-config observations, not proof of
detecting replaced system libraries. Hosted CI uploads full reports under
`artifact-example-gcc` and `artifact-example-clang`. Release/sanitizer filenames
are distinct; old selected reports are removed before validation and successful
output is atomically replaced. Hidden uploads are enabled and missing files fail.

## Timing scope and raw data

[Raw local samples/provenance](../bench/results/artifact-origin-2026-11-05.json)
retain seven alternating pairs after warmup, 100,000 operations per sample, and
checked counts. Both modes use the same four syntactically valid URLs; two pass
the configured policy and two fail. `parse` checks syntax/authority; `policy`
additionally checks the origin rules. These are different workloads for observing
validation cost, not equivalent alternative parsers.

Shared-host release medians in nanoseconds per operation:

| Compiler | Syntax parse | Syntax plus origin policy |
| --- | ---: | ---: |
| GCC 16.2.1 | 112.165 | 131.019 |
| Clang 23.1.4 | 113.421 | 138.029 |

These are monotonic elapsed observations without exclusive CPU/host claims.
They do not measure DNS/TLS/HTTP/file I/O or establish a universal ranking.
Backends: libcurl 8.23.0, libsodium 1.0.22, simdjson 5.0.5. Sanitized runs are
excluded from timings. The evidence commit adds documentation/results only;
tested implementation hashes are retained in the JSON.

## Independent reviews

- Design/security: no blocker; canonical ports and semantic IPv6 backend
  comparison incorporated. DNS/address and path authorization remain caller-owned.
- Standards: evidence-retention finding fixed with distinct reports and embedded
  commands. No remaining code-standard finding.
- Specification/security: the same evidence issue fixed; Python/Goose iteration
  limits agree. No policy/scope defect found.
- Final harness: stale pass after failed rerun fixed and regression-checked.
  No further blocking finding reported.

This finite regression coverage is not a complete update-protocol audit,
SSRF/address confinement or resource/path authorization guarantee.
