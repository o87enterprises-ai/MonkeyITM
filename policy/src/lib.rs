//! Policy kernel: loads YAML rules and evaluates intents against them.
//!
//! Rules are evaluated top-to-bottom. First match wins. If no rule matches,
//! the caller's default (typically deny) applies.
//!
//! The kernel is deliberately small and pure: it never performs IO, never
//! touches the clock, never consults the network. It takes an `Intent` and
//! returns a `Verdict`. That's the whole contract.

use intent::{Action, Intent, Verdict, VerdictKind};
use serde::Deserialize;
use std::path::Path;

#[derive(Debug, Deserialize)]
pub struct Policy {
    #[serde(default)]
    pub rules: Vec<Rule>,
}

#[derive(Debug, Deserialize)]
pub struct Rule {
    pub name: String,
    #[serde(default)]
    pub action: ActionFilter,
    #[serde(default)]
    pub r#match: Match,
    pub verdict: RuleVerdict,
    #[serde(default)]
    pub reason: Option<String>,
    /// How much a refusal by this rule counts toward the tripwire (default 1). A rule
    /// for something that must never happen can carry the whole limit, so its first hit
    /// halts the run; a rule for an everyday mistake can carry 0.
    #[serde(default)]
    pub weight: Option<u32>,
}

#[derive(Debug, Deserialize, Default, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ActionFilter {
    #[default]
    Any,
    ReadFile,
    WriteFile,
    HttpGet,
    Exec,
    LlmChat,
    SendMessage,
    RecvMessage,
    SpawnAgent,
}

impl ActionFilter {
    fn matches(self, a: Action) -> bool {
        matches!(
            (self, a),
            (ActionFilter::Any, _)
                | (ActionFilter::ReadFile, Action::ReadFile)
                | (ActionFilter::WriteFile, Action::WriteFile)
                | (ActionFilter::HttpGet, Action::HttpGet)
                | (ActionFilter::Exec, Action::Exec)
                | (ActionFilter::LlmChat, Action::LlmChat)
                | (ActionFilter::SendMessage, Action::SendMessage)
                | (ActionFilter::RecvMessage, Action::RecvMessage)
                | (ActionFilter::SpawnAgent, Action::SpawnAgent)
        )
    }
}

#[derive(Debug, Deserialize, Default)]
pub struct Match {
    /// `params.path` must start with this string.
    pub path_prefix: Option<String>,
    /// `params.path` must equal this string exactly.
    pub path_exact: Option<String>,
    /// `params.url` must parse and its host must equal this string.
    pub url_host: Option<String>,
    /// `params.url`'s host must be on this list. An entry starting with a dot
    /// (".wikipedia.org") matches that domain and every subdomain of it.
    pub url_hosts: Option<Vec<String>>,
    /// exec only: the basename of `params.argv[0]` must be one of these.
    pub program: Option<Vec<String>>,
    /// exec only: `params.cwd` (default `/workspace`) must start with this.
    pub cwd_prefix: Option<String>,
}

#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RuleVerdict {
    Allow,
    Deny,
    ApproveRequired,
    DryRun,
}

impl Policy {
    /// Evaluate an intent. First matching rule wins. No match → deny.
    pub fn decide(&self, intent: &Intent) -> Verdict {
        self.decide_weighted(intent).0
    }

    /// Like `decide`, and also the weight of the rule that decided (1 if it set none or
    /// if no rule matched): what a refusal counts toward the tripwire.
    pub fn decide_weighted(&self, intent: &Intent) -> (Verdict, u32) {
        for rule in &self.rules {
            if rule.matches(intent) {
                return (rule.to_verdict(intent), rule.weight.unwrap_or(1));
            }
        }
        (
            Verdict {
                id: intent.id.clone(),
                verdict: VerdictKind::Deny,
                result: serde_json::Value::Null,
                reason: "no policy rule matched".into(),
                token: None,
            },
            1,
        )
    }
}

impl Rule {
    fn matches(&self, intent: &Intent) -> bool {
        if !self.action.matches(intent.action) {
            return false;
        }
        if let Some(p) = &self.r#match.path_prefix {
            match param_str(intent, "path").and_then(normalize_path) {
                Some(actual) if actual.starts_with(p.as_str()) => {}
                _ => return false,
            }
        }
        if let Some(p) = &self.r#match.path_exact {
            match param_str(intent, "path").and_then(normalize_path) {
                Some(actual) if actual == p.as_str() => {}
                _ => return false,
            }
        }
        if let Some(h) = &self.r#match.url_host {
            match url_host_of(intent) {
                Some(actual) if actual == *h => {}
                _ => return false,
            }
        }
        if let Some(list) = &self.r#match.url_hosts {
            match url_host_of(intent) {
                Some(actual) if host_allowed(&actual, list) => {}
                _ => return false,
            }
        }
        if let Some(progs) = &self.r#match.program {
            match exec_program(intent) {
                Some(p) if progs.iter().any(|x| x == p) => {}
                _ => return false,
            }
        }
        if let Some(p) = &self.r#match.cwd_prefix {
            match exec_cwd(intent) {
                Some(actual) if actual.starts_with(p.as_str()) => {}
                _ => return false,
            }
        }
        true
    }

    fn to_verdict(&self, intent: &Intent) -> Verdict {
        let kind = match self.verdict {
            RuleVerdict::Allow => VerdictKind::Allow,
            RuleVerdict::Deny => VerdictKind::Deny,
            RuleVerdict::ApproveRequired => VerdictKind::ApproveRequired,
            RuleVerdict::DryRun => VerdictKind::DryRun,
        };
        Verdict {
            id: intent.id.clone(),
            verdict: kind,
            result: serde_json::Value::Null,
            reason: self
                .reason
                .clone()
                .unwrap_or_else(|| format!("rule: {}", self.name)),
            token: None,
        }
    }
}

fn param_str<'a>(intent: &'a Intent, key: &str) -> Option<&'a str> {
    intent.params.get(key)?.as_str()
}

/// Default working directory for `exec` when the intent doesn't name one.
pub const DEFAULT_EXEC_CWD: &str = "/workspace";

/// Basename of `params.argv[0]`, e.g. `/usr/bin/python3` -> `python3`.
pub fn exec_program(intent: &Intent) -> Option<&str> {
    let first = intent.params.get("argv")?.as_array()?.first()?.as_str()?;
    first.rsplit('/').next().filter(|s| !s.is_empty())
}

/// Normalized `params.cwd`, defaulting to `/workspace`.
pub fn exec_cwd(intent: &Intent) -> Option<String> {
    match intent.params.get("cwd") {
        None | Some(serde_json::Value::Null) => Some(DEFAULT_EXEC_CWD.to_string()),
        Some(v) => normalize_path(v.as_str()?),
    }
}

/// Lexically normalize an absolute path: collapse `//`, drop `.`, resolve `..`.
/// Returns `None` for relative paths or paths containing NUL, so path rules
/// never match them and they fall through to deny.
///
/// This stops `/tmp/safe/../../etc/shadow` from matching `/tmp/safe/`.
/// It does NOT resolve symlinks; the broker re-checks the canonical path
/// right before it executes.
pub fn normalize_path(raw: &str) -> Option<String> {
    if !raw.starts_with('/') || raw.contains('\0') {
        return None;
    }
    let mut parts: Vec<&str> = Vec::new();
    for c in raw.split('/') {
        match c {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            other => parts.push(other),
        }
    }
    let mut out = String::from("/");
    out.push_str(&parts.join("/"));
    if raw.ends_with('/') && !parts.is_empty() {
        out.push('/');
    }
    Some(out)
}

/// True when `host` is on the allowlist: exact entries match exactly; an entry
/// starting with "." matches that domain and its subdomains.
pub fn host_allowed(host: &str, list: &[String]) -> bool {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    list.iter().any(|entry| {
        let entry = entry.to_ascii_lowercase();
        match entry.strip_prefix('.') {
            Some(domain) => host == domain || host.ends_with(&format!(".{domain}")),
            None => host == entry,
        }
    })
}

fn url_host_of(intent: &Intent) -> Option<String> {
    let raw = param_str(intent, "url")?;
    url::Url::parse(raw).ok()?.host_str().map(String::from)
}

/// Load a policy from a YAML string.
pub fn load_from_str(s: &str) -> Result<Policy, serde_yaml_ng::Error> {
    serde_yaml_ng::from_str(s)
}

/// Load a policy from a file on disk.
pub fn load_from_path(p: impl AsRef<Path>) -> Result<Policy, Box<dyn std::error::Error>> {
    let s = std::fs::read_to_string(p)?;
    Ok(load_from_str(&s)?)
}

#[cfg(test)]
mod normalize_tests {
    use super::normalize_path;

    #[test]
    fn collapses_traversal() {
        assert_eq!(
            normalize_path("/tmp/safe/../../etc/shadow").unwrap(),
            "/etc/shadow"
        );
        assert_eq!(normalize_path("/tmp/./safe//x").unwrap(), "/tmp/safe/x");
        assert_eq!(normalize_path("/../../..").unwrap(), "/");
    }

    #[test]
    fn rejects_relative_and_nul() {
        assert!(normalize_path("tmp/safe/x").is_none());
        assert!(normalize_path("/tmp/safe/x\0").is_none());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn test_policy() -> Policy {
        load_from_str(
            r#"
rules:
  - name: allow-tmp
    action: read_file
    match: { path_prefix: "/tmp/safe/" }
    verdict: allow
    reason: "explicitly allowed"

  - name: approve-etc
    action: read_file
    match: { path_prefix: "/etc/" }
    verdict: approve_required
    reason: "system config needs a human"

  - name: deny-exec
    action: exec
    verdict: deny
    reason: "exec is off"
"#,
        )
        .unwrap()
    }

    #[test]
    fn allows_matching_prefix() {
        let p = test_policy();
        let i = Intent::new(Action::ReadFile, json!({"path": "/tmp/safe/x.txt"}));
        let v = p.decide(&i);
        assert_eq!(v.verdict, VerdictKind::Allow);
        assert_eq!(v.reason, "explicitly allowed");
    }

    #[test]
    fn escalates_for_etc() {
        let p = test_policy();
        let i = Intent::new(Action::ReadFile, json!({"path": "/etc/passwd"}));
        assert_eq!(p.decide(&i).verdict, VerdictKind::ApproveRequired);
    }

    #[test]
    fn denies_when_no_rule_matches() {
        let p = test_policy();
        let i = Intent::new(
            Action::ReadFile,
            json!({"path": "/home/x/.aws/credentials"}),
        );
        let v = p.decide(&i);
        assert_eq!(v.verdict, VerdictKind::Deny);
        assert_eq!(v.reason, "no policy rule matched");
    }

    #[test]
    fn denies_exec_explicitly() {
        let p = test_policy();
        let i = Intent::new(Action::Exec, json!({"cmd": "ls"}));
        let v = p.decide(&i);
        assert_eq!(v.verdict, VerdictKind::Deny);
        assert_eq!(v.reason, "exec is off");
    }

    fn bench_policy() -> Policy {
        load_from_str(
            r#"
rules:
  - name: no-container-tools
    action: exec
    match: { program: [docker, mount] }
    verdict: deny
  - name: exec-in-workspace
    action: exec
    match: { cwd_prefix: "/workspace" }
    verdict: allow
"#,
        )
        .unwrap()
    }

    #[test]
    fn program_matches_argv0_basename() {
        let p = bench_policy();
        let i = Intent::new(Action::Exec, json!({"argv": ["/usr/bin/docker", "ps"]}));
        assert_eq!(p.decide(&i).verdict, VerdictKind::Deny);
        let i = Intent::new(Action::Exec, json!({"argv": ["python3", "-V"]}));
        assert_eq!(p.decide(&i).verdict, VerdictKind::Allow);
    }

    #[test]
    fn cwd_defaults_to_workspace_and_is_normalized() {
        let p = bench_policy();
        let i = Intent::new(Action::Exec, json!({"argv": ["ls"]}));
        assert_eq!(p.decide(&i).verdict, VerdictKind::Allow);
        let i = Intent::new(
            Action::Exec,
            json!({"argv": ["ls"], "cwd": "/workspace/../etc"}),
        );
        assert_eq!(p.decide(&i).verdict, VerdictKind::Deny);
        let i = Intent::new(Action::Exec, json!({"argv": ["ls"], "cwd": "relative"}));
        assert_eq!(p.decide(&i).verdict, VerdictKind::Deny);
    }

    #[test]
    fn program_rule_does_not_match_without_argv() {
        let p = bench_policy();
        let i = Intent::new(Action::Exec, json!({"cmd": "docker ps"}));
        assert_eq!(
            p.decide(&i).verdict,
            VerdictKind::Allow,
            "falls to cwd rule; executor rejects missing argv"
        );
    }

    #[test]
    fn url_hosts_allowlist_exact_and_subdomains() {
        let p = load_from_str(
            r#"
rules:
  - name: web
    action: http_get
    match: { url_hosts: [".wikipedia.org", "docs.python.org"] }
    verdict: allow
"#,
        )
        .unwrap();
        let get = |u: &str| {
            p.decide(&Intent::new(Action::HttpGet, json!({"url": u})))
                .verdict
        };
        assert_eq!(get("https://en.wikipedia.org/wiki/DNS"), VerdictKind::Allow);
        assert_eq!(get("https://wikipedia.org/"), VerdictKind::Allow);
        assert_eq!(get("https://docs.python.org/3/"), VerdictKind::Allow);
        assert_eq!(get("https://evilwikipedia.org/"), VerdictKind::Deny);
        assert_eq!(
            get("https://wikipedia.org.evil.example/"),
            VerdictKind::Deny
        );
        assert_eq!(get("https://python.org/"), VerdictKind::Deny);
        assert_eq!(get("not a url"), VerdictKind::Deny);
    }

    #[test]
    fn first_match_wins() {
        // A later rule that also matches must not override an earlier one.
        let p = load_from_str(
            r#"
rules:
  - name: specific
    action: read_file
    match: { path_exact: "/tmp/safe/x" }
    verdict: deny
    reason: "specific deny wins"
  - name: broad
    action: read_file
    match: { path_prefix: "/tmp/safe/" }
    verdict: allow
"#,
        )
        .unwrap();
        let i = Intent::new(Action::ReadFile, json!({"path": "/tmp/safe/x"}));
        assert_eq!(p.decide(&i).verdict, VerdictKind::Deny);
        assert_eq!(p.decide(&i).reason, "specific deny wins");
    }

    #[test]
    fn message_filters_match_only_their_own_action() {
        let p = load_from_str(
            "rules:\n  - name: s\n    action: send_message\n    verdict: allow\n  - name: r\n    action: recv_message\n    verdict: allow\n",
        )
        .unwrap();
        let send = Intent::new(Action::SendMessage, json!({ "to": "a2", "body": "x" }));
        let recv = Intent::new(Action::RecvMessage, json!({}));
        let read = Intent::new(Action::ReadFile, json!({ "path": "/tmp/safe/x" }));
        assert!(matches!(p.decide(&send).verdict, VerdictKind::Allow));
        assert!(matches!(p.decide(&recv).verdict, VerdictKind::Allow));
        assert!(matches!(p.decide(&read).verdict, VerdictKind::Deny));
    }
}
