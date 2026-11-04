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
- **High Performance**:
  - Parse throughput: >5.5M URLs/sec (~180 ns/op)
  - Reference resolution throughput: >6.9M ops/sec (~140 ns/op)
  - Dot segment removal throughput: >18M ops/sec (~50 ns/op)
- **Robust & Hardened**:
  - Tested against full RFC 3986 test suites (normal and abnormal relative resolution cases).
  - Fuzzed with property-based testing and differential testing against Python's `urllib.parse`.
  - Memory-safe with bounded buffer limits (`MAX_URL_BYTES = 65536`).

## Usage

Import `url` in your Goose project:

```goose
import url from "path/to/goose-url";

fn main() {
    // 1. Parsing
    let u, err = url::parse("https://user:pass@example.com:8443/api/v1/resource?filter=active#sec-1");
    if err.kind != url::ErrorKind.None {
        print("Parse error at offset: ", err.offset);
        return;
    }
    print("Scheme: ", u.scheme);
    print("Host: ", u.host);
    print("Port: ", u.port);
    print("Path: ", u.path);

    // 2. Reference Resolution
    let resolved, r_err = url::resolve(u, "../other/endpoint?key=val");
    if r_err.kind == url::ErrorKind.None {
        print("Resolved URL: ", url::to_string(resolved));
        // Output: https://user:pass@example.com:8443/api/other/endpoint?key=val
    }

    // 3. Query Parameter Parsing
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
```

## License

Apache-2.0
