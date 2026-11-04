# goose-url

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

A pure [Goose](https://github.com/aardappel/goose) library implementing [RFC 3986](https://www.rfc-editor.org/rfc/rfc3986) Uniform Resource Identifiers (URI) parsing, reference resolution, and query handling.

## Features

- **Strict RFC 3986 Compliance**:
  - Full generic URI parser decomposing components: scheme, authority (userinfo, host, port), path, query, fragment.
  - Standard reference resolution algorithm (RFC 3986 §5.2) covering absolute and relative references.
  - Path dot-segment normalization (`remove_dot_segments`, RFC 3986 §5.2.4).
  - Percent-encoding and decoding (RFC 3986 §2.1).
  - Form-urlencoded query parsing and formatting.
- **Zero Native Dependencies**: 100% written in Goose with no C shims or external runtime dependencies.
- **State-of-the-Art Performance**:
  - Zero-copy view parse throughput: **>9.2M URLs/sec (~108 ns/op)**.
  - Owned parse throughput: **>6.0M URLs/sec (~166 ns/op)**.
  - Reference resolution throughput: **>5.8M ops/sec (~171 ns/op)**.
  - Dot-segment removal throughput: **>17M ops/sec (~58 ns/op)**.
- **Robust & Hardened**:
  - Tested against full RFC 3986 test suites (normal and abnormal relative resolution cases).
  - Differential fuzzing verified across 130 test cases against Python's `urllib.parse`.
  - Property-based fuzzing with 5,000+ randomized iterations and zero crashes or bounds violations.
  - Memory-safe with bounded buffer limits (`MAX_URL_BYTES = 65536`).

## Comparative Benchmarks

Benchmark performed on standard Linux x86_64 hardware across 100,000 iterations:

| Operation | Implementation | Throughput (ops/sec) | Latency (ns/op) | Speedup vs Competitor |
| :--- | :--- | :---: | :---: | :---: |
| **URI Parsing** | **goose-url (`parse_view`)** | **9,249,002** | **108.0 ns** | **Baseline (Fastest)** |
| | **goose-url (`parse` owned)** | **6,010,091** | **166.0 ns** | **1.5x slower than view** |
| | libcurl 8.23.0 C (`curl_url`) | 2,186,419 | 457.4 ns | 4.2x slower than view |
| | Node.js WHATWG URL (Ada backend) | 1,358,340 | 736.2 ns | 6.8x slower than view |
| | Python 3.14 (`urllib.parse.urlsplit`) | 548,129 | 1,824.4 ns | 16.9x slower than view |
| **Reference Resolution** | **goose-url (`resolve`)** | **5,814,047** | **171.0 ns** | **Baseline (Fastest)** |
| | Node.js WHATWG URL (Ada backend) | 1,292,801 | 773.5 ns | 4.5x slower |
| | libcurl 8.23.0 C (`curl_url`) | 794,929 | 1,258.0 ns | 7.3x slower |
| | Python 3.14 (`urllib.parse.urljoin`) | 156,361 | 6,395.5 ns | 37.2x slower |

## Usage

Import `url` in your Goose project:

```goose
import url from "path/to/goose-url";

fn main() {
    // 1. Zero-Copy Non-Allocating View Parsing
    let raw = "https://user:pass@example.com:8443/api/v1/resource?filter=active#sec-1";
    let v, v_err = url::parse_view(raw);
    if v_err.kind == url::ErrorKind.None {
        print("View Host: ", v.host); // Points directly into raw slice without allocation
        print("View Port: ", v.port);
    }

    // 2. Owned Parsing
    let u, err = url::parse(raw);
    if err.kind != url::ErrorKind.None {
        print("Parse error at offset: ", err.offset);
        return;
    }
    print("Scheme: ", u.scheme);
    print("Host: ", u.host);
    print("Port: ", u.port);
    print("Path: ", u.path);

    // 3. Reference Resolution (RFC 3986 §5.2)
    let resolved, r_err = url::resolve(u, "../other/endpoint?key=val");
    if r_err.kind == url::ErrorKind.None {
        print("Resolved URL: ", url::to_string(resolved));
        // Output: https://user:pass@example.com:8443/api/other/endpoint?key=val
    }

    // 4. Query Parameter Parsing
    let params = url::parse_query(u.query);
    for p in params {
        print("Param: ", p.key, " = ", p.value);
    }
}
```

## Building and Testing

Prerequisites: Goose toolchain. Run `./scripts/setup-goose.sh` to clone and build the pinned compiler revision.

```bash
# Run type checks and code formatting verification
make check

# Run unit tests and JIT/AOT builds
make test

# Run property and differential fuzzing suite
make fuzz

# Run microbenchmarks
make bench

# Run multi-ecosystem comparative benchmark against libcurl, Node.js, and Python
make bench-compare
```

## License

Apache-2.0
