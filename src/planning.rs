use crate::Context;
use cfbk::cost::{Amount, Mode, Price, Quote, Unit};
use sha2::{Digest, Sha256};

/// Local fixture result. This type cannot construct an authenticated identity.
#[derive(Debug, PartialEq, Eq)]
pub struct Simulation {
    /// Real local authentication and requested transformation succeeded.
    pub accepted: bool,
}
pub(crate) fn quote(parts: &[&[u8]], context: &Context, mode: Mode) -> Quote {
    let mut hash = Sha256::new();
    hash.update(b"cgvt:local-verification:v1\0");
    for part in parts.iter().copied().chain([
        context.scope.as_bytes(),
        context.subject.as_bytes(),
        context.action.as_bytes(),
        context.challenge.as_bytes(),
    ]) {
        hash.update((part.len() as u64).to_be_bytes());
        hash.update(part);
    }
    hash.update(context.expires_at.to_be_bytes());
    hash.update([match mode {
        Mode::Simulation => 0,
        Mode::Sandbox => 1,
        Mode::Production => 2,
    }]);
    Quote{price:Price::Exact(Amount{unit:Unit{code:"provider-api-calls".into(),scale:0},atoms:0}),source:"Local authenticated-result verification; upstream issuance/session fees and local compute excluded".into(),valid_until:context.expires_at,binding:format!("{:x}",hash.finalize())}
}
