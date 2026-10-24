# Agent instructions

English code/documentation. cgvt is a reusable government-identity domain
library. Use maintained verification libraries; authenticate issuer, holder,
provider, challenge, scope and expiry before producing facts. Caller policy
selects meaning and requests rich transient outputs; cvld receives minimal
requested predicates. Identity domains remain explicit: document reuse is not
person uniqueness, and a session ID is not an identity.

All data is RAM-only. No DB connections, SQL, file caches or hidden persistence.
Caller atomic ports own registration counts and idempotency. Credentials are
explicit; raw data and secrets never enter default Debug/errors/logs. Owned Rust
forbids unsafe code. LGPL with linking exception, no GPL/AGPL-only dependencies.

Hard no spending/live provider calls/account registration/publishing. Real
upstream libraries with inert signed fixtures test behavior. Local checkouts edit
and format; Crow compiles/tests committed candidates. Preserve existing quality
and coverage checks. Clearly separate working integrations from candidates.
