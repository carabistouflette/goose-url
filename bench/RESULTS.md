# Recorded URL workloads

This clean run was recorded at `2026-11-04T23:48:18Z` from source `91bd034844894e7174607a81147bbda58b556ff5`. It used Goose `eadca409f68210893f366e60d0c2f0dc29a339be` (runtime `3025e5810379`), GCC 16.2.1, Python 3.14.9, Node v26.13.0 and libcurl 8.23.0 on Linux 7.2.11 x86-64, Intel Core Ultra 7 258V. The host was shared; the process could run on CPUs 0–7.

The source bridge was checked at commit `52cc3c9c810f8c413eaf1fd64661cc0c865fbd0a`, tagged `v0.1.0-alpha.1`. Each of the nine source-file SHA-256 values recorded in the [raw report](results/publication-2026-11-05.json) matches that commit, including `url.goose`, `address.goose`, the four benchmark drivers, comparison runner and compiler pin. The report contains the hashes and build commands. This identifies the verified source checkpoint, not the moving tip of `main`; recheck the recorded hashes before applying these results to a later revision.

Each row below shows the median and range across three measured process samples, in reported nanoseconds per operation. Each measured loop ran 100,000 operations after one excluded warmup process. Raw values, elapsed seconds and checksums are in the JSON report.

| Driver and workload | Median ns/op | Sample range ns/op |
| --- | ---: | ---: |
| Goose `bench_parse` | 265 | 249–287 |
| Goose `bench_parse_view` | 188 | 179–213 |
| Goose `bench_resolve` | 304 | 287–307 |
| Goose `bench_dot_remove` | 83 | 82–87 |
| Goose `bench_query_parse` | 434 | 434–437 |
| Goose `bench_origin` | 121 | 121–125 |
| Goose `bench_query_sort` | 771 | 733–846 |
| CURLU parse | 517.2 | 431.8–518.6 |
| CURLU resolve | 1,973.5 | 1,904.0–2,056.0 |
| Node URL parse | 636.9 | 631.6–740.2 |
| Node URL resolve | 640.0 | 510.5–696.7 |
| Python urlsplit parse | 1,708.9 | 1,696.2–1,756.8 |
| Python urljoin resolve | 6,448.6 | 6,440.9–6,801.5 |

Goose `-O2` controls language inlining; the report keeps the actual C build transcript. The curl driver uses C `-O2`. These single-input workloads have different validation, allocation, caching and normalization contracts. They do not establish a cross-parser ranking or end-to-end latency.

Reproduce with `make bench-compare CC=gcc`. See [the workload boundaries](README.md).
