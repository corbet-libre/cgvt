use super::*;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use futures::executor::block_on;
use hmac::{Hmac, KeyInit, Mac};
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use sd_jwt_payload::{Hasher, Sha256Hasher};
use serde_json::{Value, json};
use sha2::Sha256;
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};

fn context() -> Context {
    Context {
        scope: "application".into(),
        subject: "member".into(),
        action: "register".into(),
        challenge: "fresh-session-challenge".into(),
        expires_at: 1500,
    }
}
fn config() -> wallet::Config {
    wallet::Config {
        issuer: "https://issuer.example".into(),
        credential_type: "urn:example:government-id".into(),
        audience: "https://verifier.example".into(),
        issuer_algorithm: Algorithm::EdDSA,
        holder_algorithm: Algorithm::EdDSA,
        max_binding_age: 300,
        identity_claim: Some("/sub".into()),
    }
}
fn wallet() -> wallet::WalletVerifier {
    wallet::WalletVerifier::new(
        config(),
        &serde_json::from_str(include_str!("fixtures/issuer.json")).unwrap(),
    )
    .unwrap()
}
fn claims() -> Value {
    json!({"iss":"https://issuer.example","vct":"urn:example:government-id","exp":2000,"iat":900,"sub":"government-subject-7","cnf":{"jwk":serde_json::from_str::<Value>(include_str!("fixtures/holder.json")).unwrap()}})
}
fn binding() -> Value {
    json!({"aud":"https://verifier.example","nonce":"fresh-session-challenge","iat":1000})
}
fn disclosure() -> String {
    URL_SAFE_NO_PAD.encode(br#"["inert-random-salt","birthdate","2000-01-01"]"#)
}
fn sign(claims: Value, bind: Value, disclosures: &[String]) -> String {
    let mut issuer = Header::new(Algorithm::EdDSA);
    issuer.typ = Some("dc+sd-jwt".into());
    let mut holder = Header::new(Algorithm::EdDSA);
    holder.typ = Some("kb+jwt".into());
    sign_headers(claims, bind, disclosures, issuer, holder)
}
fn sign_headers(
    mut claims: Value,
    mut bind: Value,
    disclosures: &[String],
    header: Header,
    holder: Header,
) -> String {
    if !disclosures.is_empty() {
        claims["_sd"] = json!(
            disclosures
                .iter()
                .map(|d| Sha256Hasher::new().encoded_digest(d))
                .collect::<Vec<_>>()
        );
    }
    let issuer = encode(
        &header,
        &claims,
        &EncodingKey::from_ed_pem(include_bytes!("fixtures/issuer.pem")).unwrap(),
    )
    .unwrap();
    let prefix = if disclosures.is_empty() {
        format!("{issuer}~")
    } else {
        format!("{issuer}~{}~", disclosures.join("~"))
    };
    bind["sd_hash"] = json!(Sha256Hasher::new().encoded_digest(&prefix));
    let kb = encode(
        &holder,
        &bind,
        &EncodingKey::from_ed_pem(include_bytes!("fixtures/holder.pem")).unwrap(),
    )
    .unwrap();
    format!("{prefix}{kb}")
}
#[test]
fn real_wallet_signatures_disclosures_projection_and_context() {
    let w = wallet();
    let ctx = context();
    let jwt = sign(claims(), binding(), &[disclosure()]);
    let verified = w.verify(&jwt, &ctx, 1100).unwrap();
    let request = Request {
        attributes: vec!["/birthdate".into()],
        predicates: BTreeMap::from([
            (
                "old_enough".into(),
                Predicate::DateOnOrBefore {
                    path: "/birthdate".into(),
                    cutoff: "2008-01-01".into(),
                },
            ),
            (
                "exact".into(),
                Predicate::Equals {
                    path: "/birthdate".into(),
                    value: json!("2000-01-01"),
                },
            ),
        ]),
        complete: true,
    };
    let p = verified.project(&request, &ctx, 1100).unwrap();
    assert!(p.predicates.values().all(|v| *v));
    assert_eq!(p.attributes["/birthdate"], "2000-01-01");
    assert_eq!(p.complete.as_ref().unwrap().expose(), jwt.as_bytes());
    assert_eq!(p.provider, "sd-jwt-vc");
    assert_eq!(p.expires_at, 1500);
    let minimal = verified.project(&Request::default(), &ctx, 1100).unwrap();
    assert!(minimal.attributes.is_empty());
    assert!(minimal.complete.is_none());
    for private in [
        format!("{ctx:?}"),
        format!("{verified:?}"),
        format!("{p:?}"),
        format!("{:?}", p.complete.unwrap()),
    ] {
        assert!(private.contains("redacted"));
        assert!(!private.contains("government-subject"));
    }
    let mut other = ctx.clone();
    other.action = "different".into();
    assert!(verified.project(&request, &other, 1100).is_err());
    assert!(verified.project(&request, &ctx, 1500).is_err());
    assert_eq!(verified.upstream().expose(), jwt.as_bytes());
    assert!(
        verified
            .project(
                &Request {
                    attributes: vec!["/unsupported-private-field".into()],
                    ..Request::default()
                },
                &ctx,
                1100
            )
            .is_err()
    );
    assert_eq!(verified.upstream().expose(), jwt.as_bytes());
    let key = IdentityKey::new([7; 32]).unwrap();
    let id = verified.comparison(&key, "scope").unwrap();
    assert_ne!(id, verified.comparison(&key, "other").unwrap());
    assert_ne!(
        id,
        verified
            .comparison(&IdentityKey::new([8; 32]).unwrap(), "scope")
            .unwrap()
    );
    assert!(format!("{key:?}{id:?}").contains("redacted"));
    assert_ne!(id.bytes(), &[0; 32]);
}
#[test]
fn wallet_rejects_forgery_and_wrong_issuer_holder_bindings() {
    let w = wallet();
    let ctx = context();
    for (name, value) in [
        ("iss", json!("other")),
        ("vct", json!("wrong")),
        ("exp", json!(1000)),
        ("exp", json!("2000")),
        ("iat", json!(1200)),
        ("nbf", json!(1200)),
        ("nbf", json!("later")),
        ("cnf", json!({})),
        ("_sd_alg", json!("sha-512")),
    ] {
        let mut c = claims();
        c[name] = value;
        assert!(
            w.verify(&sign(c, binding(), &[]), &ctx, 1100).is_err(),
            "{name}"
        );
    }
    for (name, value) in [
        ("aud", json!("wrong")),
        ("nonce", json!("wrong")),
        ("iat", json!(1200)),
        ("iat", json!(1)),
        ("iat", json!("1000")),
    ] {
        let mut b = binding();
        b[name] = value;
        assert!(
            w.verify(&sign(claims(), b, &[]), &ctx, 1100).is_err(),
            "{name}"
        );
    }
    let jwt = sign(claims(), binding(), &[disclosure()]);
    for bad in [
        "".into(),
        "bad~bad".into(),
        "x".repeat(1024 * 1024 + 1),
        format!("{}~", jwt.split('~').next().unwrap()),
        format!("{jwt}x"),
    ] {
        assert!(w.verify(&bad, &ctx, 1100).is_err());
    }
    let mut c = claims();
    c["cnf"]["jwk"] = serde_json::from_str(include_str!("fixtures/issuer.json")).unwrap();
    assert!(w.verify(&sign(c, binding(), &[]), &ctx, 1100).is_err());
    let mut c = claims();
    c["exp"] = json!(1400);
    assert!(w.verify(&sign(c, binding(), &[]), &ctx, 1100).is_err());
    let duplicate = disclosure();
    assert!(
        w.verify(
            &sign(claims(), binding(), &[duplicate.clone(), duplicate]),
            &ctx,
            1100
        )
        .is_err()
    );
    let mut c = claims();
    c.as_object_mut().unwrap().remove("sub");
    assert!(w.verify(&sign(c, binding(), &[]), &ctx, 1100).is_err());
}
fn decision() -> Value {
    json!({"status":"success","verification":{"id":"session-id","vendorData":"fresh-session-challenge","status":"approved","code":9001,"decisionTime":"1970-01-01T00:16:40Z","person":{"dateOfBirth":"2000-01-01"},"document":{"country":"EE","type":"PASSPORT","number":"TEST-0007"}},"providerExtension":{"future":true}})
}
fn authenticate(value: &Value) -> (Vec<u8>, String) {
    let bytes = serde_json::to_vec(value).unwrap();
    let mut h = <Hmac<Sha256> as KeyInit>::new_from_slice(&[7; 32]).unwrap();
    h.update(&bytes);
    let signature = hex::encode(h.finalize().into_bytes());
    (bytes, signature)
}
#[test]
fn veriff_exact_body_signature_full_extensions_and_document_identity() {
    let v = veriff::Veriff::new("account".into(), vec![7; 32]).unwrap();
    let ctx = context();
    let (body, sig) = authenticate(&decision());
    let result = v
        .verify(&body, &sig, "session-id", &ctx, 1100, 1000)
        .unwrap();
    let p = result
        .project(
            &Request {
                complete: true,
                ..Request::default()
            },
            &ctx,
            1100,
        )
        .unwrap();
    assert_eq!(p.complete.unwrap().expose(), body);
    assert!(
        result
            .comparison(&IdentityKey::new([8; 32]).unwrap(), "scope")
            .is_ok()
    );
    assert!(format!("{v:?}").contains("redacted"));
    let mut missing = decision();
    missing["verification"]
        .as_object_mut()
        .unwrap()
        .remove("document");
    let (b, s) = authenticate(&missing);
    assert_eq!(
        v.verify(&b, &s, "session-id", &ctx, 1100, 1000)
            .unwrap()
            .comparison(&IdentityKey::new([8; 32]).unwrap(), "scope")
            .unwrap_err(),
        Error::Unsupported
    );
    let mut appended = body.clone();
    appended.push(b' ');
    assert!(
        v.verify(&appended, &sig, "session-id", &ctx, 1100, 1000)
            .is_err()
    );
    for signature in ["", "zz", &"a".repeat(64), &"z".repeat(64)] {
        assert!(
            v.verify(&body, signature, "session-id", &ctx, 1100, 1000)
                .is_err()
        );
    }
    for (path, value) in [
        ("/status", json!("failed")),
        ("/verification/id", json!("wrong")),
        ("/verification/vendorData", json!("other")),
        ("/verification/status", json!("declined")),
        ("/verification/status", json!("review")),
        ("/verification/code", json!(1)),
        ("/verification/decisionTime", json!("bad")),
        ("/verification/decisionTime", json!("1970-01-01T01:00:00Z")),
    ] {
        let mut d = decision();
        *d.pointer_mut(path).unwrap() = value;
        let (b, s) = authenticate(&d);
        assert!(
            v.verify(&b, &s, "session-id", &ctx, 1100, 1000).is_err(),
            "{path}"
        );
    }
    let (b, s) = authenticate(&json!({"status":"success","verification":null}));
    assert_eq!(
        v.verify(&b, &s, "session-id", &ctx, 1100, 1000)
            .unwrap_err(),
        Error::Pending
    );
    assert!(v.verify(&body, &sig, "session-id", &ctx, 1100, 0).is_err());
    assert!(v.verify(&body, &sig, "session-id", &ctx, 1100, 50).is_err());
}
type RegistryState = BTreeMap<([u8; 32], String), BTreeMap<String, u64>>;
#[derive(Default)]
struct Registry(Mutex<RegistryState>);
impl RegistrationStore for Registry {
    async fn reserve(
        &self,
        id: &ScopedIdentity,
        scope: &str,
        max: u64,
        op: &str,
    ) -> Result<(), Error> {
        let mut map = self.0.lock().unwrap();
        let row = map.entry((*id.bytes(), scope.into())).or_default();
        if let Some(old) = row.get(op) {
            return if *old == max {
                Ok(())
            } else {
                Err(Error::Registration)
            };
        }
        if row.len() as u64 >= max {
            return Err(Error::Registration);
        }
        row.insert(op.into(), max);
        Ok(())
    }
}
#[test]
fn general_registration_limits_and_atomic_competitors() {
    let result = wallet()
        .verify(&sign(claims(), binding(), &[]), &context(), 1100)
        .unwrap();
    let id = Arc::new(
        result
            .comparison(&IdentityKey::new([7; 32]).unwrap(), "scope")
            .unwrap(),
    );
    let registry = Arc::new(Registry::default());
    let handles: Vec<_> = (0..4)
        .map(|i| {
            let id = id.clone();
            let registry = registry.clone();
            std::thread::spawn(move || {
                block_on(id.register(
                    &*registry,
                    &Registration {
                        policy_scope: "window-1".into(),
                        maximum: 2,
                        operation: format!("op-{i}"),
                    },
                    1100,
                ))
                .is_ok()
            })
        })
        .collect();
    assert_eq!(
        handles
            .into_iter()
            .map(|h| h.join().unwrap() as usize)
            .sum::<usize>(),
        2
    );
    let request = Registration {
        policy_scope: "window-2".into(),
        maximum: 1,
        operation: "same".into(),
    };
    assert!(block_on(id.register(&*registry, &request, 1100)).is_ok());
    assert!(block_on(id.register(&*registry, &request, 1100)).is_ok());
    assert!(
        block_on(id.register(
            &*registry,
            &Registration {
                maximum: 2,
                ..request
            },
            1100
        ))
        .is_err()
    );
    assert!(
        block_on(id.register(
            &*registry,
            &Registration {
                policy_scope: "p".into(),
                maximum: 0,
                operation: "op".into()
            },
            1100
        ))
        .is_err()
    );
}
#[test]
fn configuration_and_projection_fail_closed() {
    assert!(IdentityKey::new([0; 32]).is_err());
    for secret in [vec![], vec![1; 4097]] {
        assert!(veriff::Veriff::new("account".into(), secret).is_err());
    }
    for bad in ["".into(), "x".repeat(1025), "\n".into()] {
        let mut ctx = context();
        ctx.scope = bad;
        assert!(ctx.validate(1100).is_err());
    }
    let key = serde_json::from_str(include_str!("fixtures/issuer.json")).unwrap();
    let mut c = config();
    c.max_binding_age = 0;
    assert!(wallet::WalletVerifier::new(c, &key).is_err());
    let mut c = config();
    c.issuer_algorithm = Algorithm::HS256;
    assert!(wallet::WalletVerifier::new(c, &key).is_err());
    let mut c = config();
    c.identity_claim = Some("no-pointer".into());
    assert!(wallet::WalletVerifier::new(c, &key).is_err());
    let result = wallet()
        .verify(
            &sign(claims(), binding(), &[disclosure()]),
            &context(),
            1100,
        )
        .unwrap();
    for request in [
        Request {
            attributes: vec!["/missing".into()],
            ..Request::default()
        },
        Request {
            attributes: vec!["/sub".into(); 65],
            ..Request::default()
        },
        Request {
            predicates: BTreeMap::from([(
                "bad".into(),
                Predicate::DateOnOrBefore {
                    path: "/birthdate".into(),
                    cutoff: "bad".into(),
                },
            )]),
            ..Request::default()
        },
    ] {
        assert!(result.project(&request, &context(), 1100).is_err());
    }
}

#[test]
fn previews_and_local_simulation_never_dispatch() {
    use cfbk::cost::{Mode, Price};
    let wallet = wallet();
    let ctx = context();
    let token = sign(claims(), binding(), &[]);
    let preview = wallet.preview(&token, &ctx, Mode::Simulation);
    assert!(matches!(preview.price,Price::Exact(ref a) if a.atoms==0));
    assert_ne!(
        preview.binding,
        wallet.preview(&token, &ctx, Mode::Production).binding
    );
    assert_ne!(
        preview.binding,
        wallet.preview(&token, &ctx, Mode::Sandbox).binding
    );
    assert_ne!(
        preview.binding,
        wallet.preview("different", &ctx, Mode::Simulation).binding
    );
    assert!(
        wallet
            .simulate(&token, &ctx, &Request::default(), 1100)
            .accepted
    );
    assert!(
        !wallet
            .simulate("bad", &ctx, &Request::default(), 1100)
            .accepted
    );
    let v = veriff::Veriff::new("account".into(), vec![7; 32]).unwrap();
    assert_ne!(
        v.preview(b"a", "session", &ctx, Mode::Production).binding,
        v.preview(b"b", "session", &ctx, Mode::Production).binding
    );
}

#[test]
fn signed_header_extensions_and_invalid_disclosures_never_become_claims() {
    let w = wallet();
    for which in 0..4 {
        let mut issuer = Header::new(Algorithm::EdDSA);
        issuer.typ = Some("dc+sd-jwt".into());
        let mut holder = Header::new(Algorithm::EdDSA);
        holder.typ = Some("kb+jwt".into());
        match which {
            0 => issuer.typ = Some("JWT".into()),
            1 => issuer.crit = Some(vec!["unknown".into()]),
            2 => holder.typ = Some("JWT".into()),
            _ => holder.crit = Some(vec!["unknown".into()]),
        }
        assert!(
            w.verify(
                &sign_headers(claims(), binding(), &[], issuer, holder),
                &context(),
                1100
            )
            .is_err()
        );
    }
    let mut c = claims();
    c["nbf"] = json!(900);
    c["iat"] = json!("900");
    assert!(
        w.verify(&sign(c, binding(), &[]), &context(), 1100)
            .is_err()
    );
    let mut c = claims();
    c["nbf"] = json!(900);
    c.as_object_mut().unwrap().remove("iat");
    assert!(w.verify(&sign(c, binding(), &[]), &context(), 1100).is_ok());
    // Oversized but correctly hashed disclosure still refuses before projection.
    let huge = URL_SAFE_NO_PAD
        .encode(serde_json::to_vec(&json!(["salt", "large", "x".repeat(50000)])).unwrap());
    assert!(
        w.verify(&sign(claims(), binding(), &[huge]), &context(), 1100)
            .is_err()
    );
    let collision = URL_SAFE_NO_PAD.encode(br#"["salt","sub","different"]"#);
    assert!(
        w.verify(&sign(claims(), binding(), &[collision]), &context(), 1100)
            .is_err()
    );
    // Binding hash was signed for different disclosure bytes.
    let jwt = sign(claims(), binding(), &[disclosure()]);
    let altered = jwt.replace(
        &disclosure(),
        &URL_SAFE_NO_PAD.encode(br#"["salt","birthdate","1999-01-01"]"#),
    );
    assert!(w.verify(&altered, &context(), 1100).is_err());
    let key = serde_json::from_str(include_str!("fixtures/issuer.json")).unwrap();
    let mut cfg = config();
    cfg.identity_claim = None;
    let without = wallet::WalletVerifier::new(cfg, &key)
        .unwrap()
        .verify(&sign(claims(), binding(), &[]), &context(), 1100)
        .unwrap();
    assert!(
        without
            .comparison(&IdentityKey::new([1; 32]).unwrap(), "scope")
            .is_err()
    );
}
#[test]
fn requested_predicates_and_vendor_lifetimes_fail_closed() {
    let result = wallet()
        .verify(
            &sign(claims(), binding(), &[disclosure()]),
            &context(),
            1100,
        )
        .unwrap();
    let predicates = BTreeMap::from([
        (
            "not_old_enough".into(),
            Predicate::DateOnOrBefore {
                path: "/birthdate".into(),
                cutoff: "1999-01-01".into(),
            },
        ),
        (
            "not_equal".into(),
            Predicate::Equals {
                path: "/sub".into(),
                value: json!("other"),
            },
        ),
    ]);
    assert!(
        result
            .project(
                &Request {
                    predicates,
                    ..Request::default()
                },
                &context(),
                1100
            )
            .unwrap()
            .predicates
            .values()
            .all(|v| !*v)
    );
    let too_many = (0..65)
        .map(|n| {
            (
                n.to_string(),
                Predicate::Equals {
                    path: "/sub".into(),
                    value: json!("other"),
                },
            )
        })
        .collect();
    assert!(
        result
            .project(
                &Request {
                    predicates: too_many,
                    ..Request::default()
                },
                &context(),
                1100
            )
            .is_err()
    );
    let v = veriff::Veriff::new("account".into(), vec![7; 32]).unwrap();
    for at in ["1969-12-31T23:59:59Z", "1970-01-01T00:16:40Z"] {
        let mut d = decision();
        d["verification"]["decisionTime"] = json!(at);
        let (b, s) = authenticate(&d);
        assert!(
            v.verify(&b, &s, "session-id", &context(), 1100, 200)
                .is_err()
        );
    }
    assert!(
        v.verify(
            &vec![0; 1_048_577],
            &"a".repeat(64),
            "session-id",
            &context(),
            1100,
            1000
        )
        .is_err()
    );
    let quote = v.preview(
        b"fixture",
        "session-id",
        &context(),
        cfbk::cost::Mode::Production,
    );
    assert!(!quote.binding.contains("fixture"));
}

#[test]
fn malformed_signed_inputs_cover_parser_and_document_failures() {
    let w = wallet();
    let mut c = claims();
    c["cnf"]["jwk"] = json!(null);
    assert!(
        w.verify(&sign(c, binding(), &[]), &context(), 1100)
            .is_err()
    );
    assert!(
        w.verify(
            &sign(claims(), binding(), &["%%%".into()]),
            &context(),
            1100
        )
        .is_err()
    );
    let mut jwt = sign(claims(), binding(), &[]).into_bytes();
    let dot = jwt.iter().position(|b| *b == b'.').unwrap();
    jwt[dot + 1] = if jwt[dot + 1] == b'a' { b'b' } else { b'a' };
    assert!(
        w.verify(std::str::from_utf8(&jwt).unwrap(), &context(), 1100)
            .is_err()
    );
    let v = veriff::Veriff::new("account".into(), vec![7; 32]).unwrap();
    let mut d = decision();
    d["verification"]["document"]["number"] = json!("");
    let (b, s) = authenticate(&d);
    assert!(
        v.verify(&b, &s, "session-id", &context(), 1100, 1000)
            .is_err()
    );
}

#[test]
fn retained_comparison_handles_do_not_register_after_evidence_expiry() {
    let id = wallet()
        .verify(&sign(claims(), binding(), &[]), &context(), 1100)
        .unwrap()
        .comparison(&IdentityKey::new([1; 32]).unwrap(), "scope")
        .unwrap();
    let request = Registration {
        policy_scope: "window".into(),
        maximum: 1,
        operation: "op".into(),
    };
    let store = Registry::default();
    assert_eq!(
        block_on(id.register(&store, &request, 1500)),
        Err(Error::Rejected)
    );
}
