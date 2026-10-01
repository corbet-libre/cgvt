# cgvt

**Government-document admission gate for cvld.**

`cgvt` is reserved for two government-document routes: a selectively disclosed
eID presentation and an established vendor's document-verification result.
The gate receives only the requested eligibility attributes bound to an opaque
member; raw documents, identity fields and biometric material stay outside
cvld and this library.

Status: no implementation or qualified provider adapter exists. Wallet/vendor
selection and the requested attribute set remain open. The configured coverage
gate must reject an empty production inventory.

## Boundaries

One invocation checks one provider result. `cfbk` owns ordering/fallback and
`crbk` owns requirements; cvld combines gate results into eligibility. Community
policy belongs under `cvld`/`cmty`, not Forum. No confidence ranking, local
cryptographic primitive, live identity request or raw identity fixture is
introduced. See [the current contract](docs/CONTRACT.md).

## License

Copyright 2026 Julian Y. Richard Corbet. Licensed under
[LGPL-3.0-only](LICENSES/LGPL-3.0-only.txt)
[WITH LGPL-3.0-linking-exception](LICENSES/LGPL-3.0-linking-exception.txt).
See [LICENSE.md](LICENSE.md).

## Continuous verification

Dependency updates follow main and are tested against one CI-resolved lockfile.
Line and branch coverage target 100%; failures remain blocking. See
[the coverage contract](docs/COVERAGE.md) for measurement and exclusions.
