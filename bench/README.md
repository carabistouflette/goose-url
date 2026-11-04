# Benchmark boundaries

`make bench` runs the Goose microbenchmark driver. `make bench-compare` runs
`scripts/compare.py` and saves `.build/compare_results.json`: three raw measured
samples per available driver after one excluded process warmup. Each driver uses
100000 operations. Override `--samples` (3..20) or `--warmups` (1..5) directly for
longer campaigns. `GOOSE` and `CC` environment variables or `--goose`/`--cc` select
executables; pass a single compiler executable, not a shell command or flags.

The report records source revision and dirty state, source hashes, actual compiler,
Goose/Python/Node/libcurl versions, build commands/output/flags, platform and CPU,
affinity, raw driver output, checksums and medians. Samples rotate driver order.
This is a shared host with no exclusive-isolation claim or CI timing threshold.
A failed command, missing expected workload, invalid duration or wrong checksum
fails the campaign and removes any stale successful report.

## Workloads have different contracts

These measurements are not a universal speed ranking. A zero-copy generic URI
view, an owned generic URI result, libcurl's CURLU, WHATWG URL normalization and
Python's `urllib.parse` do different validation, normalization and allocation work.
In particular:

- Goose resolution reuses an already parsed base; curl parses the base on every
  iteration, and Node/Python receive a base string.
- Python repeatedly splits one identical string with its normal cache enabled.
- Node starts a fresh process for each sample. An excluded warmup process does
  not retain its JIT state in the measured processes.
- Drivers report internal loop timing, excluding process startup. Their checksums
  read different result fields. Each workload currently repeats one fixed input.
- Query sorting includes rebuilding parameters for every operation; dot removal
  and origin formatting reuse their output buffer.

Use each series to track the corresponding workload on a recorded environment.
Do not convert these observations into cross-parser speedup or “fastest” claims.
The Goose `-O2` option controls language inlining; its verbose build transcript
records the pinned compiler's actual C build commands. The native curl driver is
built with explicit C `-O2`.

The library itself has no extra native package. Optional comparison dependencies
are a C11 compiler with POSIX monotonic-clock support, pkg-config/libcurl development
files and Node.js. The native comparison is exercised on Linux. Their absence
is recorded as a skipped driver. Python 3 and the pinned Goose compiler are needed
for the runner. Maintained system packages are preferable to obsolete frozen
native dependencies. Benchmarks perform no network requests.

## Fuzzing evidence

`make fuzz` uses `scripts/fuzz.py` with deterministic seed 491, property tests,
130 fixed resolution cases on a shared Python/Goose domain, 1000 ASCII form-query
cases and 5000 seeded text-robustness cases by default. CLI `--seed`, `--cases` and
`--query-cases` control bounded campaigns; `GOOSE`/`CC` overrides also apply.
`.build/fuzz-results.json` retains seed, input hash, binary/source hashes, compiler
identity and result counts. Failures preserve the current batch or single command
at `.build/fuzz-failure.txt`; replay it through `.build/fuzz --stdin`.

The line protocol excludes CR/LF in generated text, encodes non-ASCII text as
UTF-8 and is not arbitrary-byte transport. The Goose property suite separately
contains raw-byte invalid-input cases. Python's permissive URL helpers are not a
general RFC validation oracle; form comparisons use an ASCII shared domain and
compare decoded pairs. Every subprocess is bounded by a finite deadline, stdout
and stderr are drained together, and child status/output counts are checked.
This is deterministic mutation/property testing, not coverage-guided fuzzing or
a proof of security.
