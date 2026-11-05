# Artifact example: validation and measurements

The optional [artifact example](../examples/artifact/README.md) checks an application-supplied HTTPS host and port before passing the unchanged URL bytes to the pinned downloader.

## Validation

The recorded checks ran on clean source `902a8d72330e3b0aab5a2cf8f721d80f7ece2c72`. Each GCC and Clang release/sanitizer run passed 80 policy/libcurl cases and 17 artifact-consumer cases. They covered authority comparison, IPv6, limits, signed-URL mismatch, TLS trust rejection, redirects and non-200 responses, and policy rejection before download or file mutation. Sanitizers cover generated Goose/runtime and the native adapter; installed system libraries are not instrumented.

Current main `52cc3c9c810f8c413eaf1fd64661cc0c865fbd0a` has the same SHA-256 content for all nine source files recorded by those runs: `url.goose`, `address.goose`, the four `examples/artifact/` Goose files, `scripts/artifact-check.py` and the two `tests/artifact/` C files. Dependency pins in the report match `examples/artifact/main.goose`. The raw JSON contains each hash and build command.

A fresh `make artifact-check` on that published commit also passed all 80 policy/CURLU cases and 17 consumer cases with GCC 16.2.1. This checks the documented example build and local fixtures without contacting an external server.

## Performance claim

N/A. The optional example has no public performance claim. Its local timing mode compares syntax parsing with syntax parsing plus caller policy; those workloads do different work and do not compare implementations. The [historical raw report](../bench/results/artifact-origin-2026-11-05.json) is preserved, with compiler, dependency, source, binary and sample data. It does not record the host OS or CPU, so its timings are not used as current performance evidence. No rerun is needed for this documentation release.
