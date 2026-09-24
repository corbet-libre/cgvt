# cgvt

**Government eID admission gate for cvld.**

`cgvt` will verify a member's government-issued electronic identity
credential (for example the Swiss E-ID or an EU Digital Identity Wallet)
through selective disclosure. cvld receives only the requested attributes
(for example "is a person", "over 18") bound to an opaque community member,
never a name, birth date, document number or other real identity.

Status: name reserved, no implementation yet. Scope, supported wallets and
the disclosed-attribute set are still to be decided.

## Boundaries

- `cgvt` proves a credential presentation; `cvld` combines gates into
  eligibility; `cfrm` owns community policy.
- Wallet and issuer specifics stay in this crate. No real identity data
  enters attestation output, logs, errors or fixtures.

## License

Copyright 2026 Julian Y. Richard Corbet. Licensed under
[LGPL-3.0-only](LICENSES/LGPL-3.0-only.txt)
[WITH LGPL-3.0-linking-exception](LICENSES/LGPL-3.0-linking-exception.txt).
See [LICENSE.md](LICENSE.md).
