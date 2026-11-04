# Test boundaries

`make test` runs unit/regression cases in the pinned compiler's in-process runner,
compiled release, and debug with bounds-check elimination disabled, plus the
example. Cases include RFC resolution, component grammar, valid/invalid IP
literals, malformed escapes, empty delimiter presence, setter injection, resource
boundaries, atomic output failure, ownership and stable byte sorting.

`make fuzz` uses seed 491 by default. It runs Goose property loops, 130 selected
ASCII resolution comparisons with Python, 1000 query comparisons on a shared
domain and 5000 text mutation cases. The last group checks parser/formatter
robustness, not agreement with Python on arbitrary syntax. Its protocol is
line-oriented: CR/LF are excluded, random text is encoded as UTF-8, and it is not
a raw-byte fuzzer. Explicit unit tests cover controls/invalid byte inputs. Python
and browser parsers are not normative RFC validators.

The runner batches input, drains stdout/stderr, checks child status/response
counts and imposes finite build/process deadlines. `.build/fuzz-results.json`
records seed, corpus/source/binary hashes and source dirty state. Failed commands
are retained in `.build/fuzz-failure.txt`. Source hashing rejects a changing
implementation during a campaign. Run campaigns serially per checkout.

`make sanitize SANITIZER_CC=gcc` and Clang instrument standalone generated
Goose/runtime C, run the regression suite, and run the seeded fuzz driver with
the same instrumentation. The test wrapper adds ASan/UBSan and C -O1 after compiler
arguments; it is not an application shim. No test/application network requests
occur; compiler/package setup can require network. CI runs both compilers and an
optional comparison smoke without timing thresholds. Explicit hidden-file
artifact allowlists retain reports and any failure command.

These checks are not exhaustive or proof of memory safety independently of the
compiler/runtime. Windows/macOS and WHATWG URL processing are outside this
publication's validated scope.
