# Optional artifact download example

This Linux example applies an application-owned HTTPS host/port policy before calling the pinned Goose artifact downloader. The core `goose-url` library does not make network or filesystem calls.

## URL policy

The application supplies the trusted host and port separately. The example checks the original URL before reading metadata, then passes those exact bytes to `artifact::execute`. It does not parse signed metadata to choose a destination. The downloader verifies the signature and requires the signed URL to equal the expected URL before network or file changes.

The policy accepts URLs up to 8 KiB with lowercase `https` and an authority. It rejects userinfo, including an empty `@`, and fragments, including an empty `#`. Paths and queries must pass `goose-url` syntax checks.

The configured host must match the URL host byte for byte. DNS names use lowercase ASCII labels of 1–63 bytes, no leading or trailing hyphen, no trailing dot, and at most 253 bytes total. The last label must start with a letter; single-label names such as `localhost` are allowed when configured. IPv4 literals and alternate numeric spellings are rejected. Bracketed IPv6 is allowed in lowercase hexadecimal, including embedded IPv4; zone IDs and IPvFuture are rejected. The configured port must be 1–65535. An absent URL port means 443. An explicit port must be canonical decimal with no leading zeroes.

The policy checks syntax and origin only. It does not resolve hostnames, block private addresses, establish signing-key trust, enforce freshness or prevent rollback. It does not restrict the URL path or query; libcurl can remove literal dot segments. Percent escapes are not decoded. Diagnostics use fixed labels and numbers; the example does not print the URL, host, metadata, key or signature.

## Build and run

The core parser needs only the pinned Goose compiler. This optional example needs Linux x86-64/glibc, C and C++ compilers, CMake >=3.27, pkg-config, libsodium >=1.0.18, libcurl >=7.85 with TLS and asynchronous DNS, and simdjson development files. On Ubuntu, install `build-essential cmake ninja-build pkg-config libsodium-dev libcurl4-openssl-dev libsimdjson-dev`.

From the repository root:

```sh
make setup
mkdir -p .build
.toolchain/goose/build/goose build --standalone -O2 examples/artifact/main.goose -o .build/artifact
mkdir -m 700 /absolute/private-parent
.build/artifact /absolute/metadata.json SIGNATURE_HEX TRUSTED_KEY_HEX \
  https://downloads.example.org/file.bin downloads.example.org 443 \
  /absolute/private-parent staging.part file.bin 67108864
```

Building the optional program downloads its pinned Goose library dependencies. The pins are artifact `c2d190b613c541a5dba839ce380de8b111c9ab0c`, crypto `a4643f62bd5e76b371054c6537a95169a7930101`, HTTP `aa915a0b21db1129f85e6e339a6f0171bcac0e77`, FS `cd0bd29c78c435caaebf75bfecd8e3e2083636eb` and JSON `3fa7b5275399641f8069698b6c097ea66cef7929`. These sources are fetched by the Goose compiler; they are not vendored here.

Use a private parent directory with no other writer. Staging and final names must be safe leaf names. Only a clean HTTP 200, valid signature, matching digest, successful sync and checked close permit publication. Publication and cleanup can have separate outcomes; an error can leave staging residue. Inspect the result fields before retrying. The example has no signal handlers, so process termination can leave residue. Transfer and cleanup limits are not hard DNS, filesystem or wall-clock deadlines. Read the pinned [artifact contract](https://github.com/carabistouflette/goose-artifact/blob/c2d190b613c541a5dba839ce380de8b111c9ab0c/README.md) before use.

## Checks

After `make setup`, run the local checks:

```sh
make artifact-check
make artifact-check CC=gcc ARTIFACT_FLAGS=--sanitize
make artifact-check CC=clang ARTIFACT_FLAGS=--sanitize
```

Tests use loopback TLS and temporary signing keys. A test-only wrapper trusts the fixture CA; a separate unmodified binary verifies that production does not. Python >=3.11 and `python3-cryptography` are test dependencies. These commands do not contact an external server. The optional `ARTIFACT_FLAGS=--bench` mode records local parser/policy timing; see [its report](../../docs/ARTIFACT_EXAMPLE.md).
