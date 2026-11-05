# goose-url

A bounded URI-reference parser and resolver for [Goose](https://github.com/aardappel/goose). It works on bytes, follows the generic syntax and resolution rules in [RFC 3986](https://www.rfc-editor.org/rfc/rfc3986.html), and has no network, filesystem or native-library dependency. Apache-2.0; Linux x86-64 is the validated platform. The API is experimental before 1.0.

## Quick start

From a clone:

```sh
git clone https://github.com/carabistouflette/goose-url.git
cd goose-url
make setup
.toolchain/goose/build/goose run examples/resolve.goose
```

For a dependency pinned to the current published revision:

```goose
import url from "carabistouflette/goose-url@52cc3c9c810f8c413eaf1fd64661cc0c865fbd0a";
```

This is also tag `v0.1.0-alpha.1` at the same commit. See [examples/resolve.goose](examples/resolve.goose) and the [API contract](docs/API.md).

## What it provides

- `parse_view` for borrowed components and `parse` for owned components.
- RFC 3986 reference resolution, serialization and literal dot-segment removal.
- Strict percent and form-style query codecs, query editing and sorting.
- Checked setters for scheme, host, port, path, query and fragment.

URI input and serialized output are limited to 65,536 bytes. Query parsing and editing allow up to 1,024 nonempty pairs. Numeric ports are limited to 0–65535.

This is not a browser URL parser. It does not apply IDNA, browser IPv4 normalization, Unicode replacement, or WHATWG origin rules. Parsing does not authorize a network destination. Use an application policy before making requests; `origin_string` is only a formatter.

## Build and checks

Setup needs Git, Make, Python 3, CMake >=3.27 and a C++20 compiler. Applications need a C compiler and the Goose runtime. On Debian or Ubuntu, start with `build-essential cmake ninja-build git python3`.

`make check test fuzz` runs formatting checks, tests and seeded property checks. `make sanitize SANITIZER_CC=gcc` and `make sanitize SANITIZER_CC=clang` run the sanitizer suites. See [test coverage](tests/README.md), [security policy](SECURITY.md) and [third-party notices](THIRD_PARTY_NOTICES.md).

The optional [artifact example](examples/artifact/README.md) adds an application-owned HTTPS host/port policy and uses pinned Goose dependencies. Its native dependencies and security limits are separate from the core parser. Benchmark methods and recorded results are in [bench/README.md](bench/README.md) and [bench/RESULTS.md](bench/RESULTS.md).
