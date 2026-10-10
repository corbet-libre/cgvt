use crate::{Context, Error, IdentityKey, Private, ScopedIdentity, identifier};
use serde_json::Value;
use std::collections::BTreeMap;

/// Caller-selected transformation, never a built-in admission policy.
pub enum Predicate {
    /// Equality against a specifically requested verified claim.
    Equals {
        /// JSON pointer into authenticated claims.
        path: String,
        /// Required value.
        value: Value,
    },
    /// Date claim must be no later than the explicit cutoff. Caller owns legal
    /// age/calendar policy; the library does not choose a minimum age.
    DateOnOrBefore {
        /// JSON pointer into authenticated claims.
        path: String,
        /// Canonical YYYY-MM-DD cutoff.
        cutoff: String,
    },
}
/// Requested information; complete results are opt-in.
#[derive(Default)]
pub struct Request {
    /// Explicit JSON pointers whose authenticated values the caller needs.
    pub attributes: Vec<String>,
    /// Named predicates to evaluate, without exposing their input values.
    pub predicates: BTreeMap<String, Predicate>,
    /// Return the complete upstream representation, including extensions.
    pub complete: bool,
}
/// Authenticated private result. JSON alone cannot construct it.
pub struct VerifiedIdentity {
    pub(crate) context: Context,
    pub(crate) provider: String,
    pub(crate) attributes: Value,
    pub(crate) original: Private,
    pub(crate) identity: Option<(String, String)>,
}
impl VerifiedIdentity {
    /// Project only requested attributes and predicates; no persistence occurs.
    pub fn project(
        &self,
        request: &Request,
        context: &Context,
        now: u64,
    ) -> Result<Projection, Error> {
        context.validate(now)?;
        if context != &self.context {
            return Err(Error::Rejected);
        }
        if request.attributes.len() > 64 || request.predicates.len() > 64 {
            return Err(Error::Configuration);
        }
        let mut attributes = BTreeMap::new();
        let mut predicates = BTreeMap::new();
        for path in &request.attributes {
            identifier(path)?;
            attributes.insert(
                path.clone(),
                self.attributes
                    .pointer(path)
                    .ok_or(Error::Unsupported)?
                    .clone(),
            );
        }
        for (name, predicate) in &request.predicates {
            identifier(name)?;
            let value = match predicate {
                Predicate::Equals { path, value } => {
                    self.attributes.pointer(path).ok_or(Error::Unsupported)? == value
                }
                Predicate::DateOnOrBefore { path, cutoff } => {
                    let raw = self
                        .attributes
                        .pointer(path)
                        .and_then(Value::as_str)
                        .ok_or(Error::Unsupported)?;
                    date(raw)? <= date(cutoff)?
                }
            };
            predicates.insert(name.clone(), value);
        }
        Ok(Projection {
            provider: self.provider.clone(),
            expires_at: self.context.expires_at,
            attributes,
            predicates,
            complete: request
                .complete
                .then(|| Private::new(self.original.expose().to_vec())),
        })
    }
    /// Supported provider/issuer identity only. Session IDs, names and birth dates
    /// are never substituted for a stable verified underlying identity.
    pub fn comparison(&self, key: &IdentityKey, scope: &str) -> Result<ScopedIdentity, Error> {
        let (domain, id) = self.identity.as_ref().ok_or(Error::Unsupported)?;
        key.derive(domain, id, scope)
    }
}
/// Private requested result. Consumers explicitly choose which fields to disclose.
pub struct Projection {
    /// Adapter identity, never the member's government identifier.
    pub provider: String,
    /// Exclusive maximum validity selected during authentication.
    pub expires_at: u64,
    /// Requested verified attributes, empty for cvld's predicate-only path.
    pub attributes: BTreeMap<String, Value>,
    /// Requested derived facts, with original values discarded from this output.
    pub predicates: BTreeMap<String, bool>,
    /// Original upstream representation only when requested.
    pub complete: Option<Private>,
}
impl std::fmt::Debug for VerifiedIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("VerifiedIdentity([redacted])")
    }
}
impl std::fmt::Debug for Projection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Projection([redacted])")
    }
}
fn date(s: &str) -> Result<time::Date, Error> {
    time::Date::parse(s, time::macros::format_description!("[year]-[month]-[day]"))
        .map_err(|_| Error::Unsupported)
}
