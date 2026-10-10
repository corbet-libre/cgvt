//! Holder-bound SD-JWT VC verification using upstream disclosure and JWT libraries.
use crate::{Context, Error, Private, VerifiedIdentity, identifier};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header, jwk::Jwk};
use sd_jwt_payload::{Hasher, SdJwt, Sha256Hasher};
use serde_json::Value;
use std::collections::HashSet;

/// Independently authenticated issuer, credential semantics and relying party.
pub struct Config {
    /// Exact expected credential issuer.
    pub issuer: String,
    /// Trusted government credential type; generic signed JWTs are insufficient.
    pub credential_type: String,
    /// Exact relying-party audience for holder proof.
    pub audience: String,
    /// Explicit asymmetric issuer algorithm.
    pub issuer_algorithm: Algorithm,
    /// Explicit asymmetric holder algorithm.
    pub holder_algorithm: Algorithm,
    /// Maximum holder-proof age, seconds. No implicit clock skew.
    pub max_binding_age: u64,
    /// Verified subject claim JSON pointer, if this issuer defines a stable ID.
    /// Leave absent when the credential has no such documented identity.
    pub identity_claim: Option<String>,
}
/// No issuer discovery/network; caller imports the trusted issuer JWK.
pub struct WalletVerifier {
    config: Config,
    key: DecodingKey,
    key_wire: Vec<u8>,
}
impl WalletVerifier {
    /// Import authenticated issuer configuration. Private JWKs are unnecessary.
    pub fn new(config: Config, key: &Jwk) -> Result<Self, Error> {
        for s in [&config.issuer, &config.credential_type, &config.audience] {
            identifier(s)?;
        }
        if config.max_binding_age == 0 {
            return Err(Error::Configuration);
        }
        algorithm(config.issuer_algorithm)?;
        algorithm(config.holder_algorithm)?;
        if let Some(path) = &config.identity_claim {
            identifier(path)?;
            if !path.starts_with('/') {
                return Err(Error::Configuration);
            }
        }
        Ok(Self {
            key_wire: serde_json::to_vec(key).map_err(|_| Error::Configuration)?,
            config,
            key: DecodingKey::from_jwk(key).map_err(|_| Error::Configuration)?,
        })
    }
    /// Inert preview for this exact local verification; no provider I/O.
    pub fn preview(
        &self,
        presentation: &str,
        context: &Context,
        mode: cfbk::cost::Mode,
    ) -> cfbk::cost::Quote {
        let algorithms = format!(
            "{:?}:{:?}:{}:{:?}",
            self.config.issuer_algorithm,
            self.config.holder_algorithm,
            self.config.max_binding_age,
            self.config.identity_claim
        );
        crate::planning::quote(
            &[
                b"sd-jwt-vc",
                self.config.issuer.as_bytes(),
                self.config.credential_type.as_bytes(),
                self.config.audience.as_bytes(),
                algorithms.as_bytes(),
                &self.key_wire,
                presentation.as_bytes(),
            ],
            context,
            mode,
        )
    }
    /// Local fixture path, with no production-proof output or caller-state writes.
    pub fn simulate(
        &self,
        presentation: &str,
        context: &Context,
        request: &crate::Request,
        now: u64,
    ) -> crate::Simulation {
        crate::Simulation {
            accepted: self
                .verify(presentation, context, now)
                .and_then(|result| result.project(request, context, now))
                .is_ok(),
        }
    }
    /// Authenticate issuer, disclosures, holder key, audience, nonce, SD hash and
    /// strict times. Context is supplied independently of the presented credential.
    pub fn verify(
        &self,
        presentation: &str,
        context: &Context,
        now: u64,
    ) -> Result<VerifiedIdentity, Error> {
        context.validate(now)?;
        if presentation.len() > 1024 * 1024 {
            return Err(Error::Rejected);
        }
        let (issuer_jwt, _) = presentation.split_once('~').ok_or(Error::Rejected)?;
        let (sd_part, kb) = presentation.rsplit_once('~').ok_or(Error::Rejected)?;
        if kb.is_empty() {
            return Err(Error::Rejected);
        }
        let issuer_header = decode_header(issuer_jwt).map_err(|_| Error::Rejected)?;
        if issuer_header.typ.as_deref() != Some("dc+sd-jwt")
            || issuer_header.crit.as_ref().is_some_and(|v| !v.is_empty())
        {
            return Err(Error::Rejected);
        }
        let claims = decode::<Value>(
            issuer_jwt,
            &self.key,
            &validation(self.config.issuer_algorithm),
        )
        .map_err(|_| Error::Rejected)?
        .claims;
        if claims.get("iss").and_then(Value::as_str) != Some(&self.config.issuer)
            || claims.get("vct").and_then(Value::as_str) != Some(&self.config.credential_type)
        {
            return Err(Error::Rejected);
        }
        let exp = claims
            .get("exp")
            .and_then(Value::as_u64)
            .ok_or(Error::Rejected)?;
        if exp <= now
            || context.expires_at > exp
            || claims
                .get("nbf")
                .is_some_and(|v| v.as_u64().is_none_or(|n| n > now))
            || claims
                .get("iat")
                .is_some_and(|v| v.as_u64().is_none_or(|n| n > now))
        {
            return Err(Error::Rejected);
        }
        let holder: Jwk =
            serde_json::from_value(claims.pointer("/cnf/jwk").ok_or(Error::Rejected)?.clone())
                .map_err(|_| Error::Rejected)?;
        let key = DecodingKey::from_jwk(&holder).map_err(|_| Error::Rejected)?;
        let header = decode_header(kb).map_err(|_| Error::Rejected)?;
        if header.typ.as_deref() != Some("kb+jwt")
            || header.crit.as_ref().is_some_and(|v| !v.is_empty())
        {
            return Err(Error::Rejected);
        }
        let binding = decode::<Value>(kb, &key, &validation(self.config.holder_algorithm))
            .map_err(|_| Error::Rejected)?
            .claims;
        let issued = binding
            .get("iat")
            .and_then(Value::as_u64)
            .ok_or(Error::Rejected)?;
        let sd_hash = Sha256Hasher::new().encoded_digest(&format!("{sd_part}~"));
        if issued > now
            || now - issued > self.config.max_binding_age
            || binding.get("aud").and_then(Value::as_str) != Some(&self.config.audience)
            || binding.get("nonce").and_then(Value::as_str) != Some(&context.challenge)
            || binding.get("sd_hash").and_then(Value::as_str) != Some(&sd_hash)
        {
            return Err(Error::Rejected);
        }
        let parsed = SdJwt::parse(presentation).map_err(|_| Error::Rejected)?;
        if parsed.claims()._sd_alg.as_deref().unwrap_or("sha-256") != "sha-256" {
            return Err(Error::Rejected);
        }
        let mut seen = HashSet::new();
        for disclosure in parsed.disclosures() {
            if !seen.insert(disclosure.as_str()) {
                return Err(Error::Rejected);
            }
            // Reject alternate encodings and oversized individual disclosures.
            if disclosure.as_str().len() > 65536
                || URL_SAFE_NO_PAD.decode(disclosure.as_str()).is_err()
            {
                return Err(Error::Rejected);
            }
        }
        let attributes = Value::Object(
            parsed
                .into_disclosed_object(&Sha256Hasher::new())
                .map_err(|_| Error::Rejected)?,
        );
        let identity = self
            .config
            .identity_claim
            .as_ref()
            .map(|path| {
                let id = attributes
                    .pointer(path)
                    .and_then(Value::as_str)
                    .ok_or(Error::Unsupported)?;
                identifier(id)?;
                Ok((
                    format!(
                        "sd-jwt:{}:{}",
                        self.config.issuer, self.config.credential_type
                    ),
                    id.into(),
                ))
            })
            .transpose()?;
        Ok(VerifiedIdentity {
            context: context.clone(),
            provider: "sd-jwt-vc".into(),
            attributes,
            original: Private::new(presentation.as_bytes().to_vec()),
            identity,
        })
    }
}
fn algorithm(a: Algorithm) -> Result<(), Error> {
    if matches!(
        a,
        Algorithm::ES256 | Algorithm::EdDSA | Algorithm::RS256 | Algorithm::PS256
    ) {
        Ok(())
    } else {
        Err(Error::Configuration)
    }
}
fn validation(a: Algorithm) -> Validation {
    let mut v = Validation::new(a);
    // The complete caller-supplied clock is applied above, rather than reading
    // process wall time. Signature validation remains enabled in jsonwebtoken.
    v.required_spec_claims.clear();
    v.validate_exp = false;
    v.validate_nbf = false;
    v.validate_aud = false;
    v.leeway = 0;
    v
}
