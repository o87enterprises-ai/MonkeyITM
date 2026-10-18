//! The executor. The only code in the system that touches the real world
//! on the agent's behalf.
//!
//! It refuses to run unless:
//!   1. the capability token verifies against the broker's key and is bound
//!      to this exact intent (id, action, params hash, TTL), and
//!   2. for path actions, the *canonical* path (symlinks resolved) still gets
//!      the same policy verdict the original request got. This closes the
//!      "/tmp/safe/link -> /etc" symlink escape.

use capability::ed25519_dalek::VerifyingKey;
use capability::{decode, verify};
use intent::{Action, Intent, VerdictKind};
use policy::Policy;
use serde_json::{Value, json};
use std::collections::HashSet;
use std::io::Read;
use std::os::unix::fs::OpenOptionsExt;
use std::sync::Mutex;

use crate::workbench;

/// Max bytes returned from a single read_file. Keeps the agent from
/// slurping huge files through the broker.
pub const MAX_READ_BYTES: u64 = 64 * 1024;

/// Upper bound on what one llm_chat intent may carry into the model.
pub const MAX_LLM_INPUT_BYTES: usize = 256 * 1024;
/// Retries (with doubling waits from 5 s) when the model provider answers 429/502/503/504.
const LLM_RETRIES: u32 = 4;
const LLM_TRANSPORT_RETRIES: u32 = 2;

/// Reply limit per model call: `BROKER_LLM_MAX_TOKENS` (default 1024). Reasoning
/// models can spend all of it thinking and return no text, so raise it for them.
fn llm_max_tokens() -> u64 {
    std::env::var("BROKER_LLM_MAX_TOKENS")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .filter(|n| *n > 0)
        .unwrap_or(1024)
}

/// Model settings live with the broker, never with the agent.
///   BROKER_LLM_URL    OpenAI-compatible chat endpoint
///                     (default: Ollama at http://127.0.0.1:11434/v1/chat/completions)
///   BROKER_LLM_MODEL  model name (default: llama3.2)
///   BROKER_LLM_KEY    optional bearer token
fn llm_config() -> (String, String, Option<String>) {
    let url = std::env::var("BROKER_LLM_URL")
        .unwrap_or_else(|_| "http://127.0.0.1:11434/v1/chat/completions".into());
    let model = std::env::var("BROKER_LLM_MODEL").unwrap_or_else(|_| "llama3.2".into());
    let key = std::env::var("BROKER_LLM_KEY")
        .ok()
        .filter(|k| !k.is_empty());
    (url, model, key)
}

/// params: { "messages": [ {"role": "...", "content": "..."} , ... ] }
/// The agent chooses only the messages. The broker pins endpoint, model,
/// key, and output cap.
fn llm_chat(intent: &Intent) -> Result<Value, String> {
    let msgs = intent
        .params
        .get("messages")
        .and_then(Value::as_array)
        .ok_or("llm_chat needs a `messages` array")?;

    let mut clean = Vec::with_capacity(msgs.len());
    let mut total = 0usize;
    for m in msgs {
        let role = m
            .get("role")
            .and_then(Value::as_str)
            .ok_or("message missing role")?;
        if !matches!(role, "system" | "user" | "assistant") {
            return Err(format!("role `{role}` not allowed"));
        }
        let content = m
            .get("content")
            .and_then(Value::as_str)
            .ok_or("message missing content")?;
        total += content.len();
        clean.push(json!({ "role": role, "content": content }));
    }
    if total > MAX_LLM_INPUT_BYTES {
        return Err(format!("messages too large ({total} bytes)"));
    }

    let (url, model, key) = llm_config();
    let body = json!({ "model": model, "messages": clean, "max_tokens": llm_max_tokens(), "stream": false });

    // A provider that says "slow down" (429) or is briefly down (502/503/504) gets a
    // few patient retries; anything else, or running out of retries, fails closed.
    let mut wait = std::time::Duration::from_secs(5);
    let mut attempt = 0;
    // On a shared runner the model URL is the customer's: BROKER_LLM_PUBLIC_ONLY=1 makes the call refuse
    // internal addresses, pin the resolved address and never follow a redirect (see web::public_agent).
    let agent = if std::env::var("BROKER_LLM_PUBLIC_ONLY").is_ok_and(|v| v == "1") {
        crate::web::public_agent(&url)?
    } else {
        ureq::agent()
    };
    let sent = loop {
        let mut req = agent.post(&url).timeout(std::time::Duration::from_secs(120));
        if let Some(k) = &key {
            req = req.set("Authorization", &format!("Bearer {k}"));
        }
        match req.send_json(body.clone()) {
            Err(ureq::Error::Status(code, r))
                if matches!(code, 429 | 502 | 503 | 504) && attempt < LLM_RETRIES =>
            {
                let asked = r.header("retry-after").and_then(|v| v.parse::<u64>().ok());
                std::thread::sleep(
                    asked.map_or(wait, |s| std::time::Duration::from_secs(s.min(60))),
                );
                wait *= 2;
                attempt += 1;
            }
            // A timeout or dropped connection (no reply at all) is retried too, but only
            // twice: each try can wait up to the 120 s timeout.
            Err(ureq::Error::Transport(_)) if attempt < LLM_TRANSPORT_RETRIES => {
                std::thread::sleep(wait);
                wait *= 2;
                attempt += 1;
            }
            other => break other,
        }
    };
    let resp: Value = sent
        .map_err(|e| format!("model call failed: {e}"))?
        .into_json()
        .map_err(|e| format!("model reply not JSON: {e}"))?;

    let text = resp
        .pointer("/choices/0/message/content")
        .and_then(Value::as_str)
        .ok_or("model reply had no choices[0].message.content")?;

    Ok(json!({ "content": text, "model": model }))
}

/// What goes in the log for an executed action. File contents read by the
/// agent are summarized by size and hash; command output and model replies
/// are kept (already size-capped), since they are what the agent acted on.
pub fn log_view(intent: &Intent, result: &Value) -> Value {
    match intent.action {
        Action::ReadFile => {
            let content = result["content"].as_str().unwrap_or_default();
            json!({
                "path": result["path"],
                "bytes": content.len(),
                "sha256": workbench::sha256_hex(content.as_bytes()),
                "truncated": result["truncated"],
            })
        }
        Action::HttpGet => {
            let body = result["body"].as_str().unwrap_or_default();
            json!({
                "url": result["url"],
                "status": result["status"],
                "redirects": result["redirects"],
                "bytes": body.len(),
                "sha256": workbench::sha256_hex(body.as_bytes()),
                "truncated": result["truncated"],
            })
        }
        _ => result.clone(),
    }
}

/// Every nonce the executor has ever accepted. A token runs at most once.
pub type UsedNonces = Mutex<HashSet<String>>;

pub fn execute(
    vk: &VerifyingKey,
    used: &UsedNonces,
    token: &str,
    intent: &Intent,
    policy: &Policy,
    policy_kind: VerdictKind,
) -> Result<Value, String> {
    let tok = decode(token).map_err(|e| format!("token decode failed: {e}"))?;
    verify(vk, &tok, Some(intent)).map_err(|e| format!("token rejected: {e}"))?;
    if !used
        .lock()
        .map_err(|_| "nonce set poisoned")?
        .insert(tok.payload.nonce.clone())
    {
        return Err("token already used (replay)".into());
    }

    match intent.action {
        Action::ReadFile => match workbench::Workbench::from_env()
            .filter(|_| workbench::is_workspace_path(intent))
        {
            Some(wb) => wb.read_file(intent, policy, policy_kind),
            None => read_file(intent, policy, policy_kind),
        },
        Action::WriteFile => workbench::Workbench::from_env()
            .ok_or(
                "write_file needs a workbench (BROKER_WORKBENCH); host writes are never allowed",
            )?
            .write_file(intent, policy, policy_kind),
        Action::Exec => workbench::Workbench::from_env()
            .ok_or("exec needs a workbench (BROKER_WORKBENCH); host commands are never allowed")?
            .exec(intent),
        Action::HttpGet => crate::web::http_get(intent, policy, policy_kind),
        Action::LlmChat => llm_chat(intent),
        Action::SendMessage | Action::RecvMessage | Action::SpawnAgent => {
            Err("group actions are carried out by the broker, not the executor".into())
        }
    }
}

fn read_file(intent: &Intent, policy: &Policy, policy_kind: VerdictKind) -> Result<Value, String> {
    let raw = intent
        .params
        .get("path")
        .and_then(Value::as_str)
        .ok_or("read_file needs a string `path` param")?;
    if raw.starts_with(workbench::WORKSPACE) {
        return Err("no workbench is running, so /workspace does not exist".into());
    }

    let canon = std::fs::canonicalize(raw).map_err(|e| format!("cannot resolve path: {e}"))?;
    let canon_str = canon.to_str().ok_or("path is not valid UTF-8")?.to_string();

    // Re-ask the policy about where the path REALLY points.
    let mut probe = intent.clone();
    probe.params = json!({ "path": canon_str });
    let recheck = policy.decide(&probe).verdict;
    if recheck != policy_kind {
        return Err(format!(
            "path resolves to {canon_str}, which policy treats as {recheck:?}, not {policy_kind:?}"
        ));
    }

    // O_NONBLOCK so a FIFO under an allowed prefix cannot block a
    // blocking-pool thread forever. Regular files ignore the flag; anything
    // that is not a regular file is refused by the metadata check below.
    let f = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(&canon)
        .map_err(|e| format!("open failed: {e}"))?;
    if !f.metadata().map_err(|e| e.to_string())?.is_file() {
        return Err("not a regular file".into());
    }
    let mut buf = Vec::new();
    f.take(MAX_READ_BYTES + 1)
        .read_to_end(&mut buf)
        .map_err(|e| format!("read failed: {e}"))?;
    let truncated = buf.len() as u64 > MAX_READ_BYTES;
    buf.truncate(MAX_READ_BYTES as usize);

    Ok(json!({
        "path": canon_str,
        "content": String::from_utf8_lossy(&buf),
        "truncated": truncated,
    }))
}
