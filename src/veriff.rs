//! Veriff decision webhook authentication over exact signed bytes.
use crate::{Context, Error, Private, VerifiedIdentity, identifier};
use hmac::{Hmac, KeyInit, Mac};
use serde_json::Value;
use sha2::Sha256;
use zeroize::Zeroizing;

/// An explicitly selected integration's webhook secret and account identity.
pub struct Veriff {
    account: String,
    secret: Zeroizing<Vec<u8>>,
}
impl Veriff {
    /// No environment lookup, request, session creation or billable operation.
    pub fn new(account: String, secret: Vec<u8>) -> Result<Self, Error> {
        identifier(&account)?;
        if secret.len() < 16 || secret.len() > 4096 {
            return Err(Error::Configuration);
        }
        Ok(Self {
            account,
            secret: Zeroizing::new(secret),
        })
    }
    /// Preview only local decision authentication. Creating a Veriff session is
    /// a separate potentially billable operation not performed by this adapter.
    pub fn preview(
        &self,
        body: &[u8],
        session: &str,
        context: &Context,
        mode: cfbk::cost::Mode,
    ) -> cfbk::cost::Quote {
        crate::planning::quote(
            &[
                b"veriff-decision",
                self.account.as_bytes(),
                session.as_bytes(),
                body,
            ],
            context,
            mode,
        )
    }
    /// Verify a decision for a caller-known session and fresh vendorData challenge.
    /// The caller created/bound that session independently. Final decision age and
    /// requested lifetime are bounded by `max_age`, never invented by the adapter.
    pub fn verify(
        &self,
        body: &[u8],
        signature: &str,
        session: &str,
        context: &Context,
        now: u64,
        max_age: u64,
    ) -> Result<VerifiedIdentity, Error> {
        context.validate(now)?;
        identifier(session)?;
        if body.len() > 1024 * 1024 || signature.len() != 64 || max_age == 0 {
            return Err(Error::Rejected);
        }
        let signature = hex::decode(signature).map_err(|_| Error::Rejected)?;
        let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(&self.secret)
            .map_err(|_| Error::Configuration)?;
        mac.update(body);
        mac.verify_slice(&signature).map_err(|_| Error::Rejected)?;
        let value: Value = serde_json::from_slice(body).map_err(|_| Error::Rejected)?;
        if value.get("status").and_then(Value::as_str) != Some("success") {
            return Err(Error::Rejected);
        }
        let verification = value
            .get("verification")
            .filter(|v| !v.is_null())
            .ok_or(Error::Pending)?;
        if verification.get("id").and_then(Value::as_str) != Some(session)
            || verification.get("vendorData").and_then(Value::as_str) != Some(&context.challenge)
        {
            return Err(Error::Rejected);
        }
        match verification.get("status").and_then(Value::as_str) {
            Some("approved") if verification.get("code").and_then(Value::as_u64) == Some(9001) => {}
            Some("resubmission_requested" | "review") => return Err(Error::Pending),
            _ => return Err(Error::Rejected),
        }
        let date = verification
            .get("decisionTime")
            .and_then(Value::as_str)
            .ok_or(Error::Rejected)?;
        let at = time::OffsetDateTime::parse(date, &time::format_description::well_known::Rfc3339)
            .map_err(|_| Error::Rejected)?
            .unix_timestamp();
        let at = u64::try_from(at).map_err(|_| Error::Rejected)?;
        if at > now || now - at > max_age || context.expires_at > at.saturating_add(max_age) {
            return Err(Error::Rejected);
        }
        // Session/endUserId/vendorData are caller bookkeeping, not person identity.
        // Only an authenticated document number within its issuer jurisdiction/type
        // supports comparison, and it establishes document reuse, not personhood.
        let identity = verification
            .get("document")
            .and_then(|d| {
                Some((
                    d.get("country")?.as_str()?,
                    d.get("type")?.as_str()?,
                    d.get("number")?.as_str()?,
                ))
            })
            .map(|(country, kind, number)| {
                for s in [country, kind, number] {
                    identifier(s)?;
                }
                Ok((
                    serde_json::to_string(&("veriff-document", &self.account, country, kind))
                        .map_err(|_| Error::Configuration)?,
                    number.to_owned(),
                ))
            })
            .transpose()?;
        Ok(VerifiedIdentity {
            context: context.clone(),
            provider: "veriff".into(),
            attributes: verification.clone(),
            original: Private::new(body.to_vec()),
            identity,
        })
    }
}
impl std::fmt::Debug for Veriff {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Veriff([redacted])")
    }
}
