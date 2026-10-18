//! Capability tokens.
//!
//! When the broker verdict is `allow`, the broker mints a signed token that
//! binds the decision to a specific intent. The token is the *only* thing
//! the agent ever receives that could be mistaken for authority. It is:
//!
//! - **Signed** by the broker's ed25519 key (agent never sees the key).
//! - **Bound** to `intent_id` + `action` + a hash of `params`.
//! - **Time-limited** by `expires_at`.
//! - **Single-use** by a fresh random `nonce` per mint.
//!
//! The agent can present the token later, but only the broker can verify it.
//! Tampering with any field invalidates the signature. Replaying a token past
//! its TTL fails verification. Using a token for a different action or params
//! fails the params-hash check the caller performs after verification.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use intent::Intent;
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

pub use ed25519_dalek;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityPayload {
    /// Echo of the intent this token was minted for.
    pub intent_id: String,
    /// Action name, mirroring `intent::Action` as a snake_case string.
    pub action: String,
    /// Hex sha256 of the canonical JSON of the intent's `params`.
    pub params_hash: String,
    /// Unix seconds at mint time.
    pub issued_at: i64,
    /// Unix seconds after which the token is invalid.
    pub expires_at: i64,
    /// Fresh random nonce (UUID v4). Enforces single-use on the broker side.
    pub nonce: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedToken {
    pub payload: CapabilityPayload,
    /// Hex-encoded 64-byte ed25519 signature over the canonical JSON of `payload`.
    pub signature: String,
}

#[derive(Debug)]
pub enum VerifyError {
    BadBase64,
    BadJson,
    BadSignature,
    Expired { now: i64, expires_at: i64 },
    IntentMismatch { expected: String, got: String },
    ActionMismatch { expected: String, got: String },
    ParamsMismatch,
}

impl std::fmt::Display for VerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VerifyError::BadBase64 => write!(f, "token is not valid base64"),
            VerifyError::BadJson => write!(f, "token payload is not valid json"),
            VerifyError::BadSignature => write!(f, "token signature does not verify"),
            VerifyError::Expired { now, expires_at } => {
                write!(f, "token expired (now={now}, expires_at={expires_at})")
            }
            VerifyError::IntentMismatch { expected, got } => {
                write!(f, "intent_id mismatch (expected {expected}, got {got})")
            }
            VerifyError::ActionMismatch { expected, got } => {
                write!(f, "action mismatch (expected {expected}, got {got})")
            }
            VerifyError::ParamsMismatch => write!(f, "params hash mismatch"),
        }
    }
}

impl std::error::Error for VerifyError {}

/// Generate a fresh signing key from OS randomness.
pub fn generate_signing_key() -> SigningKey {
    SigningKey::generate(&mut OsRng)
}

/// Canonical hash of params. serde_json::Value uses BTreeMap internally, so
/// key order is deterministic — the same logical object always hashes the same.
pub fn hash_params(params: &serde_json::Value) -> String {
    let s = serde_json::to_string(params).expect("params serialize");
    let mut h = Sha256::new();
    h.update(s.as_bytes());
    hex::encode(h.finalize())
}

fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock before epoch")
        .as_secs() as i64
}

/// Mint a signed capability token for an intent.
///
/// `ttl_secs` is added to the current wall-clock time to compute `expires_at`.
pub fn mint(sk: &SigningKey, intent: &Intent, ttl_secs: i64) -> SignedToken {
    let now = now_secs();
    let payload = CapabilityPayload {
        intent_id: intent.id.clone(),
        action: action_name(intent.action),
        params_hash: hash_params(&intent.params),
        issued_at: now,
        expires_at: now + ttl_secs,
        nonce: uuid_v4(),
    };
    let sig = sign_payload(sk, &payload);
    SignedToken {
        payload,
        signature: hex::encode(sig),
    }
}

/// Serialize a signed token to a compact base64 string suitable for the wire.
pub fn encode(token: &SignedToken) -> String {
    let json = serde_json::to_vec(token).expect("token serialize");
    base64::Engine::encode(&base64::engine::general_purpose::STANDARD, json)
}

/// Parse a token from its base64 wire form.
pub fn decode(s: &str) -> Result<SignedToken, VerifyError> {
    let bytes = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, s)
        .map_err(|_| VerifyError::BadBase64)?;
    serde_json::from_slice(&bytes).map_err(|_| VerifyError::BadJson)
}

/// Verify a signed token against a verifying key, expiry, and an optional
/// intent to bind against.
pub fn verify(
    vk: &VerifyingKey,
    token: &SignedToken,
    intent: Option<&Intent>,
) -> Result<(), VerifyError> {
    // 1. Signature
    let sig_bytes = hex::decode(&token.signature).map_err(|_| VerifyError::BadSignature)?;
    let sig_arr: [u8; 64] = sig_bytes
        .as_slice()
        .try_into()
        .map_err(|_| VerifyError::BadSignature)?;
    let sig = Signature::from_bytes(&sig_arr);
    let msg = canonical_payload_bytes(&token.payload);
    vk.verify(&msg, &sig)
        .map_err(|_| VerifyError::BadSignature)?;

    // 2. Expiry
    let now = now_secs();
    if now > token.payload.expires_at {
        return Err(VerifyError::Expired {
            now,
            expires_at: token.payload.expires_at,
        });
    }

    // 3. Binding
    if let Some(i) = intent {
        if token.payload.intent_id != i.id {
            return Err(VerifyError::IntentMismatch {
                expected: i.id.clone(),
                got: token.payload.intent_id.clone(),
            });
        }
        if token.payload.action != action_name(i.action) {
            return Err(VerifyError::ActionMismatch {
                expected: action_name(i.action),
                got: token.payload.action.clone(),
            });
        }
        if token.payload.params_hash != hash_params(&i.params) {
            return Err(VerifyError::ParamsMismatch);
        }
    }

    Ok(())
}

fn sign_payload(sk: &SigningKey, payload: &CapabilityPayload) -> [u8; 64] {
    let msg = canonical_payload_bytes(payload);
    sk.sign(&msg).to_bytes()
}

fn canonical_payload_bytes(payload: &CapabilityPayload) -> Vec<u8> {
    // Stable, field-ordered serialization. serde on a struct is field-ordered
    // and deterministic, so this is safe to use as the signed message.
    serde_json::to_vec(payload).expect("payload serialize")
}

fn action_name(a: intent::Action) -> String {
    match a {
        intent::Action::ReadFile => "read_file",
        intent::Action::WriteFile => "write_file",
        intent::Action::HttpGet => "http_get",
        intent::Action::Exec => "exec",
        intent::Action::LlmChat => "llm_chat",
        intent::Action::SendMessage => "send_message",
        intent::Action::RecvMessage => "recv_message",
        intent::Action::SpawnAgent => "spawn_agent",
    }
    .to_string()
}

fn uuid_v4() -> String {
    // Reuse uuid crate via intent's transitive dep is not exposed; make one here.
    // We rely on the intent crate's uuid re-export via a small helper below.
    uuid_shim::new_v4()
}

// Tiny module to avoid adding uuid as a direct dep when it already comes in
// through intent. If you'd rather add it explicitly, replace this with
// `uuid::Uuid::new_v4().to_string()` and add `uuid = { version = "1", features=["v4"] }`.
mod uuid_shim {
    pub fn new_v4() -> String {
        // Import through intent's re-export if present; else fall back to a
        // strong RNG-based hex. We use ed25519_dalek's OsRng via rand_core.
        use rand_core::RngCore;
        let mut b = [0u8; 16];
        rand_core::OsRng.fill_bytes(&mut b);
        // Format as UUID v4 (set version + variant bits).
        b[6] = (b[6] & 0x0f) | 0x40;
        b[8] = (b[8] & 0x3f) | 0x80;
        format!(
            "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            b[0],
            b[1],
            b[2],
            b[3],
            b[4],
            b[5],
            b[6],
            b[7],
            b[8],
            b[9],
            b[10],
            b[11],
            b[12],
            b[13],
            b[14],
            b[15]
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use intent::Action;
    use serde_json::json;

    fn sample_intent() -> Intent {
        Intent::new(Action::ReadFile, json!({"path": "/tmp/safe/x.txt"}))
    }

    #[test]
    fn mint_and_verify_roundtrip() {
        let sk = generate_signing_key();
        let vk = sk.verifying_key();
        let i = sample_intent();
        let tok = mint(&sk, &i, 60);
        verify(&vk, &tok, Some(&i)).expect("should verify");
    }

    #[test]
    fn encode_decode_roundtrip() {
        let sk = generate_signing_key();
        let vk = sk.verifying_key();
        let i = sample_intent();
        let tok = mint(&sk, &i, 60);
        let wire = encode(&tok);
        let back = decode(&wire).unwrap();
        verify(&vk, &back, Some(&i)).expect("should verify after decode");
    }

    #[test]
    fn tampered_params_fail_verification() {
        let sk = generate_signing_key();
        let vk = sk.verifying_key();
        let i = sample_intent();
        let mut tok = mint(&sk, &i, 60);
        tok.payload.params_hash = "00".repeat(32);
        match verify(&vk, &tok, None) {
            Err(VerifyError::BadSignature) => {}
            other => panic!("expected BadSignature, got {other:?}"),
        }
    }

    #[test]
    fn wrong_intent_fails_binding() {
        let sk = generate_signing_key();
        let vk = sk.verifying_key();
        let i = sample_intent();
        let tok = mint(&sk, &i, 60);
        let other = Intent::new(Action::ReadFile, json!({"path": "/tmp/other"}));
        match verify(&vk, &tok, Some(&other)) {
            Err(VerifyError::IntentMismatch { .. }) => {}
            other => panic!("expected IntentMismatch, got {other:?}"),
        }
    }

    #[test]
    fn expired_token_fails() {
        let sk = generate_signing_key();
        let vk = sk.verifying_key();
        let i = sample_intent();
        let mut tok = mint(&sk, &i, 60);
        // Force expiry into the past without touching the signature check first.
        tok.payload.expires_at = now_secs() - 1;
        // Signature is over payload bytes, so we must re-sign to isolate the
        // expiry failure from a signature failure.
        let sig = sign_payload(&sk, &tok.payload);
        tok.signature = hex::encode(sig);
        match verify(&vk, &tok, None) {
            Err(VerifyError::Expired { .. }) => {}
            other => panic!("expected Expired, got {other:?}"),
        }
    }

    #[test]
    fn different_key_fails_signature() {
        let sk1 = generate_signing_key();
        let sk2 = generate_signing_key();
        let i = sample_intent();
        let tok = mint(&sk1, &i, 60);
        match verify(&sk2.verifying_key(), &tok, None) {
            Err(VerifyError::BadSignature) => {}
            other => panic!("expected BadSignature, got {other:?}"),
        }
    }
}
