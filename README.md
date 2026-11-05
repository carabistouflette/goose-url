# goose-url

A bounded, byte-oriented URI-reference parser and resolver for
[Goose](https://github.com/aardappel/goose), under Apache-2.0. Experimental API;
Linux x86-64 is the validated platform. No compatibility promise before 1.0.

The library follows the generic ASCII component syntax and reference-resolution
algorithm of [RFC 3986](https://www.rfc-editor.org/rfc/rfc3986.html). It provides
borrowed views, owned values, percent codecs, strict form-style query decoding,
checked component setters and serialization. It performs no network or filesystem
access and adds no native package dependency beyond the Goose runtime.

This is not a WHATWG/browser URL parser. It does not apply IDNA, browser IPv4
normalization or Unicode replacement. Numeric ports are restricted to 0..65535,
a deliberate policy narrower than generic RFC port syntax. Generic empty hosts
and relative references are allowed; callers must authorize network destinations.
`origin_string` is a limited scheme/authority formatter, not a security identity.

The optional [artifact download example](examples/artifact/README.md) applies an
explicit caller-owned HTTPS host/port policy before using the pinned
goose-artifact downloader. Its native/test dependencies are separate from the
core library.

## Quickstart

From a standalone clone:

```sh
git clone https://github.com/carabistouflette/goose-url.git
cd goose-url
make setup
.toolchain/goose/build/goose run examples/resolve.goose
make check test fuzz
```

In a neighboring application's root source:

```goose
import url from "../goose-url";
import std;

fn main() {
    let base, error = url::parse("https://example.com/a/b");
    if error.kind != url::ErrorKind.None { print("invalid base"); return; }
    let result, resolve_error = url::resolve(base, "../c?x=1");
    if resolve_error.kind != url::ErrorKind.None { print("cannot resolve"); return; }
    let encoded, encode_error = url::to_string(result);
    if encode_error.kind != url::ErrorKind.None { print("cannot serialize"); return; }
    print(encoded); // https://example.com/c?x=1
}
```

For an immutable published dependency, use this root binding:

```goose
import url from "carabistouflette/goose-url@91bd034844894e7174607a81147bbda58b556ff5";
```

See [the API contract](docs/API.md) for ownership.

## Bounds and errors

URI inputs and serialized outputs are capped at 65536 bytes. Output limits
include an existing destination prefix. Resolution can temporarily combine two
individually bounded paths before reduction; the final URI must fit. Query parsing
is all-or-error with at most 1024 nonempty pairs. Invalid escapes and excess pairs
return an empty result plus an error.

Codecs and append-style serializers preserve the destination on failure. Check
boolean/Error returns. Component setters return `(Url, bool)` and validate the
original component before normalization. Invalid edits preserve a valid original.
Query data is bytes, not necessarily UTF-8: decoding can produce NUL or other
bytes that need validation before use in another API.

`parse_view` borrows input; `parse` owns its fields. Owned parsing lowercases scheme
and host and serializes numeric ports without leading zeroes. Flags preserve
empty userinfo, port, query and fragment delimiters. Sorting is stable byte order,
not WHATWG UTF-16 order. The caps are not an exact allocator/process memory budget.
See [security considerations](SECURITY.md).

## Build and verification

Use the exact compiler revision in [GOOSE_REVISION](GOOSE_REVISION). Setup requires
Git, Make, Python 3, CMake >=3.27 and a C++20 compiler. Applications need a C compiler
and the Goose runtime. On Debian/Ubuntu start with `build-essential cmake
ninja-build git python3`; ensure CMake satisfies the version requirement.

Pass `GOOSE=/absolute/path/to/goose` and `CC=gcc` to Make to reuse a compiler.
Run builds serially per checkout: test scripts share ignored build paths.

```sh
make format check test fuzz
make sanitize SANITIZER_CC=gcc
make sanitize SANITIZER_CC=clang
make bench
make bench-compare
```

Sanitizers instrument standalone generated Goose/runtime C. Seeded fuzzing checks
property invariants and a shared-domain Python comparison; it is not exhaustive
RFC certification or coverage-guided fuzzing. See [test boundaries](tests/README.md).
Benchmarks retain repeated raw samples, source hashes, versions and timing scope.
The APIs have different validation/caching/allocation contracts; no cross-parser
speed ranking is claimed. Optional comparison tools are pkg-config/libcurl
development files and Node.js. See [benchmark boundaries](bench/README.md),
[contributing](CONTRIBUTING.md) and [third-party notices](THIRD_PARTY_NOTICES.md).
