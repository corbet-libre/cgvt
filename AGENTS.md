# Agent instructions

Write all code comments and documentation in English.

## Product boundary

- cgvt is a reusable government eID gate for cvld admission. It verifies
  a selectively disclosed credential presentation and returns only the
  requested attributes, bound to an opaque community member.
- Real identity (name, birth date, document number, portrait, address)
  must never enter attestation output, logs, errors or fixtures.
- This crate is LGPL-3.0-only WITH LGPL-3.0-linking-exception. Do not add
  implementation code available only under the full GPL or AGPL.
- No live wallet or issuer calls in tests. Fixtures only.

## Quality boundary

- `cargo fmt --check`, `cargo clippy --all-targets` (no warnings),
  `cargo test` — all green before every commit. No local workstation
  builds; use GHA, Crow as fallback.
