//! Government identity results, selective disclosure and scoped identity limits.
#![forbid(unsafe_code)]

mod identity;
mod planning;
mod projection;
pub use planning::Simulation;
pub mod veriff;
pub mod wallet;
pub use identity::{IdentityKey, Registration, RegistrationStore, ScopedIdentity};
pub use projection::{Predicate, Projection, Request, VerifiedIdentity};
use std::fmt;
use zeroize::Zeroizing;

/// Bounded, redacted verification failures.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Error {
    /// Invalid trusted context/configuration or request.
    #[error("invalid identity configuration")]
    Configuration,
    /// Evidence failed authentication, binding or time checks.
    #[error("identity evidence rejected")]
    Rejected,
    /// Provider has not completed the requested check.
    #[error("identity verification pending")]
    Pending,
    /// Authenticated evidence lacks a requested attribute or identity guarantee.
    #[error("identity capability unavailable")]
    Unsupported,
    /// Caller-owned atomic registration refused or failed.
    #[error("registration refused")]
    Registration,
}
/// Explicit private in-memory bytes. No implicit serialization or value Debug.
pub struct Private(Zeroizing<Vec<u8>>);
impl Private {
    /// Own a private buffer; caller copies remain caller-owned.
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(Zeroizing::new(bytes))
    }
    /// Deliberate access to the complete upstream representation.
    pub fn expose(&self) -> &[u8] {
        &self.0
    }
}
impl fmt::Debug for Private {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Private([redacted])")
    }
}
/// Caller-authenticated presentation/session binding. Never accept this as member evidence.
#[derive(Clone, PartialEq, Eq)]
pub struct Context {
    /// Caller-defined relying scope.
    pub scope: String,
    /// Authenticated opaque subject.
    pub subject: String,
    /// Exact requested action.
    pub action: String,
    /// Fresh challenge/vendorData independently bound by the caller.
    pub challenge: String,
    /// Exclusive caller upper bound for this verification.
    pub expires_at: u64,
}
impl Context {
    pub(crate) fn validate(&self, now: u64) -> Result<(), Error> {
        for v in [&self.scope, &self.subject, &self.action, &self.challenge] {
            identifier(v)?;
        }
        if now >= self.expires_at {
            return Err(Error::Rejected);
        }
        Ok(())
    }
}
impl fmt::Debug for Context {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Context([redacted])")
    }
}
pub(crate) fn identifier(v: &str) -> Result<(), Error> {
    if v.is_empty() || v.len() > 1024 || v.chars().any(char::is_control) {
        Err(Error::Configuration)
    } else {
        Ok(())
    }
}
#[cfg(test)]
#[path = "tests/mod.rs"]
mod tests;
