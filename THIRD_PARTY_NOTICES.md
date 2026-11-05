# Third-party notices

goose-url's implementation is Apache-2.0; see [LICENSE](LICENSE). No third-party
implementation source is vendored in the core library.

The optional artifact example downloads exact Apache-2.0 Goose library revisions
listed in [its README](examples/artifact/README.md). Their sources/licenses remain
in the compiler dependency cache, not this repository. Its native dependencies
include libsodium (ISC), libcurl (curl license) and simdjson (Apache-2.0/MIT);
retain the relevant upstream notices when redistributing binaries. Fixture tests
also use installed Python cryptography (Apache-2.0/BSD) and its dependencies.

The compiler/runtime is provided by [Goose](https://github.com/aardappel/goose),
under Apache-2.0, at the exact revision in [GOOSE_REVISION](GOOSE_REVISION).
`make setup` downloads it into ignored `.toolchain/`, including upstream notices.
Preserve applicable compiler/runtime and dependency notices when redistributing
build outputs; those downloaded sources are not part of this source repository.

Optional benchmark drivers use installed Python (`urllib.parse`), Node.js and
system libcurl. They are measurement dependencies, not library dependencies and
are not vendored. Their licenses apply to redistributed binaries/dependencies;
consult their distributions and [curl's license](https://curl.se/docs/copyright.html).

The generic syntax/resolution reference is
[RFC 3986](https://www.rfc-editor.org/rfc/rfc3986.html). The code is this project's
implementation, not a copy of another parser. The form-style codec uses the
space/plus convention and safe-byte set described by the
[URL Standard](https://url.spec.whatwg.org/#application/x-www-form-urlencoded);
this does not imply WHATWG parser, Unicode, sorting or origin compatibility.
