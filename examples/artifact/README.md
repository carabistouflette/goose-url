# Artifact download with an explicit origin policy

This optional Linux example uses goose-url before calling the reviewed
goose-artifact downloader. The policy belongs to this example; it adds no core
URL or HTTP API and changes no existing consumer pin.

The application supplies a trusted host and port separately from the download
URL. Do not derive that configuration from the untrusted URL or signed metadata.
`artifact_url::allows` checks the original bytes with `url::parse_view` and accepts:

- 1..8192 bytes, the exact lower-case `https` scheme and an absolute authority.
- An exact textual match to the configured host. DNS names use lower-case ASCII
  labels of 1..63 bytes, no edge hyphens or trailing dot, and at most 253 bytes.
  The final label starts with a letter. This deliberately excludes IPv4 literals
  and alternative numeric IPv4 spellings. Single-label names such as `localhost`
  are permitted when explicitly configured.
- Valid bracketed IPv6 in lower-case hexadecimal, including embedded IPv4, with
  exact textual host matching. Zone identifiers and IPvFuture are excluded.
- The configured port in 1..65535. An absent port means 443. Explicit ports use
  canonical nonzero decimal digits without leading zeroes, at most five bytes.
- No userinfo, including empty userinfo, and no fragment, including empty `#`.
  Paths and queries must pass the URL library's syntax checks.

It does not decode, normalize or reconstruct an accepted URL: the exact original
bytes go to `artifact::execute`. The artifact module verifies the signature and
requires the signed URL to equal these bytes before networking or mutation.
Policy rejection occurs before even reading metadata. Diagnostics use fixed
labels/numbers and do not print the URL, host, metadata, key or signature.

This is an origin policy. DNS resolution and destination-address restrictions,
key trust, freshness, rollback prevention and installation authorization remain
the caller's responsibility. DNS names can resolve to private addresses. This
example does not authorize a decoded resource/path or constrain requests to a
path prefix: libcurl can remove literal dot segments. Path/query escapes are
allowed, including encoded delimiters. IPv6 parser comparison tests use address
bytes because libcurl may normalize IPv6 spelling; the policy itself still
requires exact configured spelling.

## Build and run

Use the compiler revision in `../../GOOSE_REVISION` (from this directory), Linux
x86-64/glibc, C/C++20, CMake >=3.27, pkg-config, libsodium >=1.0.18, libcurl
>=7.85 with TLS/asynchronous DNS, and simdjson development packages. On Ubuntu:
`build-essential cmake ninja-build pkg-config libsodium-dev libcurl4-openssl-dev
libsimdjson-dev`. These dependencies are optional for the core pure Goose library.

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

Dependency downloads happen only when explicitly building this optional example.
The root source pins artifact `c2d190b613c541a5dba839ce380de8b111c9ab0c`, crypto
`a4643f62bd5e76b371054c6537a95169a7930101`, HTTP
`aa915a0b21db1129f85e6e339a6f0171bcac0e77`, FS
`cd0bd29c78c435caaebf75bfecd8e3e2083636eb` and JSON
`3fa7b5275399641f8069698b6c097ea66cef7929`. No source is vendored.

Read the pinned [artifact caller contract](https://github.com/carabistouflette/goose-artifact/blob/c2d190b613c541a5dba839ce380de8b111c9ab0c/README.md)
before use: strict private paths, no other directory writers, staging/final leaf
rules, signature format, independent publication/cleanup outcomes and possible
residue all apply. The body limit is 0..1 GiB. Only clean terminal HTTP 200,
digest equality, sync and checked close permit publication. HTTP has verified
TLS and no redirects, proxies or credentials. Transfer/connect budgets are not
hard DNS/cleanup/filesystem wall deadlines.

This minimal CLI uses the default artifact call without cancellation polling or
signal handlers. Ordinary return performs artifact cleanup; process termination
can leave staging residue. For cooperative SIGINT/SIGTERM cleanup, adapt the
artifact project's signal-aware CLI and preserve its publication commitment
boundary. Successful publication can coexist with an error, so inspect the
numeric publication/cleanup fields rather than retrying blindly.

## Validation

Python >=3.11 and `python3-cryptography` are test dependencies. Run the optional
real TLS fixture, libcurl authority comparison and local overhead measurement:

```sh
make artifact-check
make artifact-check ARTIFACT_FLAGS=--bench
make artifact-check CC=gcc ARTIFACT_FLAGS=--sanitize
make artifact-check CC=clang ARTIFACT_FLAGS=--sanitize
```

The fixture trusts a generated local CA only through a test-link wrapper.
A separate unmodified production binary must reject that CA. Tests use loopback
only and signed metadata with temporary keys. Generated files stay in `.build/`.
Measurements compare syntax parsing against syntax plus this origin policy on
the same four inputs. They do not measure HTTP throughput, establish a universal
ranking or claim host isolation. Retain raw samples and provenance when sharing
results.
