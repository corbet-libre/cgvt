# Government identity domain contract

cgvt is reusable independently of cvld. It authenticates upstream evidence,
projects caller-requested information and derives supported scoped comparison
identities. All inputs/results/session state remain in RAM. No database, file
cache, hidden persistence, provider discovery or live HTTP dispatch exists.

## Implemented routes

**Wallet/eID: holder-bound SD-JWT VC.** `wallet::WalletVerifier` uses
[sd-jwt-payload](https://github.com/iotaledger/sd-jwt-payload) for disclosure
resolution and [jsonwebtoken](https://github.com/Keats/jsonwebtoken) for actual
issuer/holder signatures. Caller-supplied trusted issuer JWK, exact issuer and
credential type establish government credential semantics; a signed JWT alone
does not. Explicit asymmetric algorithms, `dc+sd-jwt`/`kb+jwt` types, complete
holder key binding, audience, nonce, SD hash, expiry/not-before/issued time and
maximum holder-proof age are checked with caller time. SHA-256 disclosure
resolution rejects duplicate and unused disclosures. No issuer network lookup,
embedded-key trust, unsigned credential or unbound bearer fallback is accepted.

This verifies the credential presentation, not the entire OpenID4VP transport,
DCQL negotiation, X.509 trust-list distribution or mDOC device authentication.
Those remain explicit additional integrations, not claimed implementations.

**Vendor: Veriff decision webhook.** `veriff::Veriff` verifies HMAC-SHA256 over
exact incoming bytes using the explicitly configured integration secret. It
checks known session ID, independently bound vendorData challenge, approved
status/code and bounded decision time. Pending decisions are distinct from
refusal. Original extension fields remain available only through requested
private output. Session creation and capture are external operations; this
library does not trigger billing or trust a caller-supplied success boolean.
[Authentication](https://devdocs.veriff.com/docs/hmac-authentication-and-endpoint-security),
[decision schema](https://devdocs.veriff.com/apidocs/v1sessionsiddecision-1).

## Information and identity

`VerifiedIdentity` cannot be constructed/deserialized from arbitrary JSON.
`project` checks the exact context and returns only requested attributes and
named predicates. Equality and explicit date-cutoff predicates introduce no
minimum age or jurisdictional rule. Provider-reported fields are authenticated
as provider statements; arbitrary extensions are not automatically legal facts.
Original signed representation is available only on explicit `complete` request.
Default Debug and errors expose no person/document/session information.

Wallet comparison identity uses an explicitly configured stable issuer claim,
within issuer and credential-type namespace. Veriff supports authenticated
country/type/document-number reuse only, scoped additionally to the integration;
it does not prove one person cannot hold multiple documents. Names, birth dates,
endUserId, vendorData and session IDs never substitute for identity. No
cross-provider equivalence is inferred. Missing supported identity refuses.

Stable caller HMAC keys derive opaque scoped identities through RustCrypto.
They are distinct from rotatable Veriff secrets. `RegistrationStore` is a trusted
caller-owned atomic check-and-reserve port for general X registrations, policy
scope and exact operation retries. Window/release/reset meaning belongs to the
caller. No volatile counter is represented as durable uniqueness.

## Costs, credentials and qualification

Local verification previews use cfbk quotes with zero provider API calls. They
exclude local compute and all prior issuance/capture/session fees. Planning is
inert; it does not query potentially billable price endpoints. Caller-configured
provider tariffs and cfbk authorization are required before any future outbound
billable adapter. Wallet simulation returns a distinct non-proof summary.

Hosts inject trusted issuer JWK/configuration, Veriff integration account and
secret, independent subject/action/challenge/time, and a separate stable identity
key. There is no environment discovery or secret-file reader. Owned private
original buffers zeroize on drop; parser/JWT/JSON libraries create temporary
copies, and caller copies, process dumps and swap remain host responsibilities.

Tests use real Ed25519 issuer/holder signatures and actual HMAC decisions,
selective disclosures, tampering, wrong context, requested projection and
concurrent X-registration claims. Keys under tests/fixtures are inert local test
material. No live issuer, wallet or Veriff account has been contacted. Crow checks
and independent review are required before claiming validation. Other provider
catalogue entries must remain labelled candidates until their real integration
and tests are added. No deployment or registry publication is authorized.

`VerifiedIdentity::upstream` explicitly exposes the private original representation
even if a requested projection cannot be satisfied. It grants no fresh proof.
Offline verification borrows the caller's original bytes, so the caller already
retains complete inputs when authentication itself refuses them.


Async registration/consumption takes an injected trusted live clock, rather than
reusing a pre-await timestamp. It rechecks exclusive validity after awaited
state work; a clock rollback refuses the operation. State completion after the validity deadline creates no fresh success receipt.
The caller still retains the original verified value and its requested private
information. This local operation performs no provider dispatch.
Atomic registration/consumption ports receive the exclusive validity deadline.
The host must check its trusted current time within the atomic commit after any
queue wait; an expired attempt leaves state unchanged. If time expires after a
valid commit but before return, the API refuses a fresh success receipt and does
not undo the host's committed reservation.
