# Test coverage

`make check test` checks formatting, compiled Goose programs, API/regression cases and the runnable resolver example. Cases cover RFC 3986 resolution, components, IPv4/IPv6 syntax, empty delimiters, malformed escapes, bounds, ownership and unchanged output on failure.

`make fuzz` runs seeded property tests and Python comparisons on a defined shared input domain. It is not a raw-byte or coverage-guided fuzzer, and Python/browser URL parsers are not general RFC validators.

`make sanitize SANITIZER_CC=gcc` and the Clang equivalent run the regression and fuzz suites with AddressSanitizer and UndefinedBehaviorSanitizer. They instrument the generated Goose/runtime code; system libraries are outside that instrumentation.

Tests make no application network request. Compiler and package setup may use the network. Build outputs and fuzz corpora are under ignored `.build/`; run campaigns serially in one checkout. Windows, macOS and WHATWG URL behavior are outside the validated scope.
