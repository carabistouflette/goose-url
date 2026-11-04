# Publication measurement sample

Source: `91bd034844894e7174607a81147bbda58b556ff5` (clean). UTC recording: `2026-11-04T23:48:18.885782+00:00`.

Linux x86-64, Intel(R) Core(TM) Ultra 7 258V; GCC 16.2.1, Goose `eadca409f68210893f366e60d0c2f0dc29a339be`
(runtime 3025e5810379), Python 3.14.9, Node v26.13.0, libcurl 8.23.0.
Shared host, allowed CPU affinity [0, 1, 2, 3, 4, 5, 6, 7]; no exclusive-isolation claim.

Three measured process samples per available driver follow one excluded process
warmup. Each loop performs 100000 operations on one fixed input. Goose reports
the following integer median timings for its own distinct workloads:

| Workload | Reported median ns/operation |
| --- | ---: |
| `bench_parse` | 265 |
| `bench_parse_view` | 188 |
| `bench_resolve` | 304 |
| `bench_dot_remove` | 83 |
| `bench_query_parse` | 434 |
| `bench_origin` | 121 |
| `bench_query_sort` | 771 |

The [raw report](results/publication-2026-11-05.json) retains every stdout result,
checksum, elapsed duration, source/binary hashes, versions and C build transcript.
Goose -O2 controls inlining; inspect the transcript for C optimization flags.
All operations/checksums must succeed before any result is accepted.

These workloads differ in validation, allocation, base-parse reuse and cache/JIT
behavior. The external libcurl, Node and Python samples are labeled separately
in the report; they are not equivalent implementations or a speed ranking.
Driver clocks exclude startup; elapsed checks and assertions remain in the timed
loops. No timing threshold, universal speedup or stability guarantee is inferred.
See [benchmark boundaries](README.md) and rerun `make bench-compare CC=gcc`
on your own workload before making performance decisions.
