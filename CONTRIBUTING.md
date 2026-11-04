# Contributing

`goose-url` is designed to be a fast, memory-safe, zero-dependency pure Goose library implementing RFC 3986 URI parsing, reference resolution, and query parameter handling.

### Guidelines
- **Zero Native Dependencies**: Maintain 100% pure Goose code without extern C wrappers or platform shims.
- **Specification Adherence**: Strict compliance with RFC 3986 (URI Generic Syntax), specifically:
  - Reference Resolution (§5.2)
  - Dot Segment Removal (§5.2.4)
  - Character classification and percent-encoding (§2.1–§2.4)
- **Bounded Resources**: Preserve explicit limits (`MAX_URL_BYTES`, `MAX_QUERY_PARAMS`) to prevent denial-of-service vulnerabilities.
- **Testing**: All changes must pass `make check`, `make test`, and differential fuzzing `make fuzz`.
- **Commit Messages**: Follow Conventional Commits (`feat:`, `fix:`, `test:`, `docs:`, `chore:`).
