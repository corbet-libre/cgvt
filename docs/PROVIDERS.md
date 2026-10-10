# Provider and protocol catalogue

## Provider and protocol arsenal

Primary documentation reviewed 2026-10-10. **Implemented** means the local
fixture-tested path described here, not live-provider qualification.
**Extension-compatible** means the existing trusted interface can carry the
integration; provider-specific authentication/correlation still needs work.
**Candidate** means researched only. **Unsupported** means the stated guarantee
must not be inferred. These are integration options, not activated services.

Every future network route needs an explicit injected credential, account/mode
binding, bounded cost quote with provenance and expiry, atomic host reservations,
fresh dispatch deadlines, rich private reports and negative fixtures. Unknown
prices block dispatch. Cost bases below identify what a host must obtain; they
are not current numeric quotations or permission to contact the provider.

| Ecosystem and source | Status / reuse path | Credentials and cost basis | Semantic limit |
|---|---|---|---|
| [SD-JWT](https://www.rfc-editor.org/rfc/rfc9901.html) wallet credentials | Implemented holder-bound verification through `sd-jwt-payload` and `jsonwebtoken`; trusted issuer/vct configuration. | Public issuer JWK plus caller challenge/audience; local verification has zero remote service fee, excluding issuance and compute. | Valid signature/disclosure does not make an arbitrary issuer governmental. Stable subject identity stays in its issuer domain. |
| [Veriff decision webhooks](https://devdocs.veriff.com/docs/webhooks-guide) | Implemented exact-body authentication and session/challenge/freshness checks. | Inject account/webhook secret and independently bound session; local checking fee is separate from contracted session/check costs. | Document identity is account/country/type/number scoped. Session IDs and names are not universal person identifiers. |
| [OpenID4VP 1.0](https://openid.net/specs/openid-4-verifiable-presentations-1_0-final.html) | Candidate presentation orchestration using maintained protocol libraries; current wallet verifier is only one credential-format component. | Trusted verifier/issuer metadata and profile-specific keys; quote any wallet/issuer or hosted verifier services separately. | Requires response, nonce/audience, query and transaction binding. No current DCQL, mdoc or full wallet-session flow is claimed. |
| [Stripe Identity reports](https://docs.stripe.com/api/identity/verification_reports/retrieve) | Candidate: maintained Stripe SDK plus explicit VerificationSession/Report projection. | Inject appropriately scoped Stripe credentials and webhook trust; configured identity-check tariff, with reads/retries accounted for. | A payment result is not an Identity result. Verified fields and report status need exact session/context correlation. |
| [Persona inquiries](https://docs.withpersona.com/tutorial-hosted-flow-unique-api) | Candidate: official API/SDK and authenticated inquiry events. | [Scoped API key](https://docs.withpersona.com/api-keys), template/environment and webhook verification configuration; account workflow quote. | Inquiry completion, individual checks and stable provider-supported identity differ; caller policy selects meaning. |
| [Sumsub verification](https://docs.sumsub.com/reference/about-sumsub-api) | Candidate: official API/SDK, applicant/check/webhook correlation. | [App token and request signing](https://docs.sumsub.com/reference/authentication); contracted verification-level/workflow quote. | Applicant IDs are account bookkeeping unless an independently supported identity guarantee is established. Sandbox/live may share an API host. |

No candidate is a ready adapter. Prefer upstream protocol/SDK verification; do not
write credential cryptography, biometric matching, or cross-vendor person joins.
Unverified inputs remain available to the caller that supplied them; explicit
private upstream access never turns them into government identity evidence.
