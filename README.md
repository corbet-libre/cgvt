# cgvt

Reusable safe Rust government-identity verification: holder-bound SD-JWT VC and
Veriff authenticated decision results, caller-requested attributes/predicates,
opaque scoped comparison identities and atomic caller-owned registration limits.

## Scope

Applications request meaning and select trust roots, policy and output. Minimal
predicate projection suits cvld; complete authenticated upstream representations
remain explicitly available in private RAM. No database or provider I/O is used.
No identity equivalence beyond the issuer/provider's supported domain is claimed.

See [the contract](docs/CONTRACT.md) for exact route coverage, credentials,
security limits, costs and tests. SD-JWT transport/DCQL/mDOC and other vendors
remain additional candidates. Implemented local verification has no provider API
charge; prior issuance and verification-session charges are separate.

Crow validates real signed fixture flows and adversarial tests; live provider
qualification is unrun. Never substitute a fixture for production evidence.

Copyright 2026 Julian Y. Richard Corbet.
[LGPL-3.0-only WITH LGPL-3.0-linking-exception](LICENSE.md).

See the [provider and protocol catalogue](docs/PROVIDERS.md) for implemented paths,
research candidates, credentials, cost bases and unsupported guarantees.
