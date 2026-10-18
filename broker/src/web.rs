//! Brokered web fetch (`http_get`). The agent never has a network stack or a
//! DNS resolver; when policy allows a URL, the broker fetches it and returns
//! the page.
//!
//! On top of the policy's host allowlist, the executor:
//!   - only speaks HTTPS,
//!   - resolves the host itself, refuses private, loopback and link-local
//!     addresses (an allowlisted name pointed at an internal service), and pins
//!     the connection to the address it checked (no DNS rebinding),
//!   - follows redirects one hop at a time, re-asking the policy about each
//!     new URL, so an allowed site can't bounce the request somewhere else,
//!   - caps time and response size.

use intent::{Intent, VerdictKind};
use policy::Policy;
use serde_json::{Value, json};
use std::io::Read;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::time::Duration;

pub const MAX_BODY_BYTES: u64 = 64 * 1024;
pub const MAX_REDIRECTS: usize = 5;
const TIMEOUT: Duration = Duration::from_secs(15);

/// Relaxations used only by tests, which need a plain-HTTP server on localhost.
#[derive(Clone, Copy, Default)]
pub struct Limits {
    pub allow_http: bool,
    pub allow_private: bool,
}

pub fn http_get(intent: &Intent, policy: &Policy, kind: VerdictKind) -> Result<Value, String> {
    fetch(intent, policy, kind, Limits::default())
}

pub fn fetch(
    intent: &Intent,
    policy: &Policy,
    kind: VerdictKind,
    limits: Limits,
) -> Result<Value, String> {
    let raw = intent
        .params
        .get("url")
        .and_then(Value::as_str)
        .ok_or("http_get needs a string `url`")?;
    let mut url = url::Url::parse(raw).map_err(|e| format!("bad url: {e}"))?;
    if !url.username().is_empty() || url.password().is_some() {
        return Err("credentials in URLs are refused".into());
    }
    let mut hops = Vec::new();

    for _ in 0..=MAX_REDIRECTS {
        check_scheme(&url, limits)?;
        let resp = get_once(&url, limits)?;
        let status = resp.status();
        if (300..400).contains(&status) {
            let location = resp
                .header("location")
                .ok_or(format!("redirect {status} without a Location header"))?;
            let next = url
                .join(location)
                .map_err(|e| format!("bad redirect target: {e}"))?;
            // The new URL has to pass the same policy the original did.
            let mut probe = intent.clone();
            probe.params["url"] = json!(next.as_str());
            let again = policy.decide(&probe).verdict;
            if again != kind {
                return Err(format!(
                    "redirected to {next}, which policy treats as {again:?}, not {kind:?}"
                ));
            }
            hops.push(next.to_string());
            url = next;
            continue;
        }
        let content_type = resp.header("content-type").unwrap_or("").to_string();
        let mut body = Vec::new();
        resp.into_reader()
            .take(MAX_BODY_BYTES + 1)
            .read_to_end(&mut body)
            .map_err(|e| format!("read failed: {e}"))?;
        let truncated = body.len() as u64 > MAX_BODY_BYTES;
        body.truncate(MAX_BODY_BYTES as usize);
        return Ok(json!({
            "url": url.as_str(),
            "status": status,
            "content_type": content_type,
            "redirects": hops,
            "body": String::from_utf8_lossy(&body),
            "truncated": truncated,
        }));
    }
    Err(format!("more than {MAX_REDIRECTS} redirects"))
}

fn check_scheme(url: &url::Url, limits: Limits) -> Result<(), String> {
    match url.scheme() {
        "https" => Ok(()),
        "http" if limits.allow_http => Ok(()),
        other => Err(format!("only https:// is allowed, not {other}://")),
    }
}

fn get_once(url: &url::Url, limits: Limits) -> Result<ureq::Response, String> {
    let host = url.host_str().ok_or("url has no host")?.to_string();
    let port = url.port_or_known_default().ok_or("url has no port")?;
    let addrs = checked_addrs(&host, port, limits)?;
    let target = format!("{host}:{port}");
    // The operator's proxy (if any) is resolved normally; that is the only name besides the target
    // the resolver may be asked for. Anything else is refused rather than looked up.
    let proxy_url = if bypass_proxy(&host) {
        None
    } else {
        ["HTTPS_PROXY", "https_proxy"]
            .iter()
            .find_map(|k| std::env::var(k).ok())
    };
    let proxy = proxy_url.as_ref().and_then(|p| ureq::Proxy::new(p).ok());
    // The proxy is the operator's, but it gets the same internal-address check as the target unless the operator
    // says it is internal on purpose (a corporate proxy on 10.x): an internal proxy would fetch internal URLs.
    if let Some(p) = proxy_url.as_ref().filter(|_| proxy.is_some()) {
        let trusted = std::env::var("BROKER_TRUST_INTERNAL_PROXY").is_ok_and(|v| v == "1");
        check_proxy(p, limits, trusted)?;
    }
    let proxy_netloc: Option<String> = if proxy.is_some() {
        proxy_url
            .as_ref()
            .and_then(|p| url::Url::parse(p).ok())
            .and_then(|u| Some(format!("{}:{}", u.host_str()?, u.port_or_known_default()?)))
    } else {
        None
    };

    let mut agent = ureq::AgentBuilder::new()
        .redirects(0)
        .timeout(TIMEOUT)
        // Connect only to the addresses we just checked.
        .resolver(move |netloc: &str| -> std::io::Result<Vec<SocketAddr>> {
            if netloc == target {
                Ok(addrs.clone())
            } else if proxy_netloc.as_deref() == Some(netloc) {
                netloc.to_socket_addrs().map(Iterator::collect)
            } else {
                Err(std::io::Error::other(format!(
                    "resolver asked for {netloc}, not the checked host {target}; refused"
                )))
            }
        });
    if let Some(proxy) = proxy {
        agent = agent.proxy(proxy);
    }
    match agent.build().get(url.as_str()).call() {
        Ok(r) => Ok(r),
        Err(ureq::Error::Status(_, r)) => Ok(r),
        Err(e) => Err(format!("fetch failed: {e}")),
    }
}

/// An HTTP agent for calling a URL that someone else chose (a customer's model endpoint on a shared
/// runner): https only, no credentials in the URL, every address the host resolves to must be public,
/// the connection is pinned to the addresses just checked (DNS cannot change its answer between the
/// check and the connection), and redirects are never followed. `BROKER_LLM_PUBLIC_ONLY=1` makes the
/// broker call the model through this; an operator's own model (a local Ollama) does not need it.
pub fn public_agent(url_str: &str) -> Result<ureq::Agent, String> {
    public_agent_with(url_str, Limits::default())
}

fn public_agent_with(url_str: &str, limits: Limits) -> Result<ureq::Agent, String> {
    let url = url::Url::parse(url_str).map_err(|e| format!("bad model url: {e}"))?;
    if !url.username().is_empty() || url.password().is_some() {
        return Err("credentials in the model URL are refused".into());
    }
    check_scheme(&url, limits)?;
    let host = url.host_str().ok_or("the model url has no host")?.to_string();
    let port = url.port_or_known_default().ok_or("the model url has no port")?;
    let addrs = checked_addrs(&host, port, limits)?;
    let target = format!("{host}:{port}");
    Ok(ureq::AgentBuilder::new()
        .redirects(0)
        .timeout(Duration::from_secs(120))
        .resolver(move |netloc: &str| -> std::io::Result<Vec<SocketAddr>> {
            if netloc == target {
                Ok(addrs.clone())
            } else {
                Err(std::io::Error::other(format!(
                    "resolver asked for {netloc}, not the checked host {target}; refused"
                )))
            }
        })
        .build())
}

/// The operator's proxy must not resolve to an internal address unless the operator says it is internal on
/// purpose (`trusted`): a proxy on an internal address would fetch whatever it is asked to.
fn check_proxy(proxy_url: &str, limits: Limits, trusted: bool) -> Result<(), String> {
    if trusted {
        return Ok(());
    }
    let u = url::Url::parse(proxy_url).map_err(|e| format!("bad proxy url: {e}"))?;
    let host = u.host_str().ok_or("proxy url has no host")?;
    let port = u.port_or_known_default().ok_or("proxy url has no port")?;
    checked_addrs(host, port, limits)
        .map(|_| ())
        .map_err(|e| format!("proxy refused: {e} (set BROKER_TRUST_INTERNAL_PROXY=1 if this proxy is internal on purpose)"))
}

/// Honour NO_PROXY: "*", exact hosts, and domain suffixes (".corp" or "corp").
fn bypass_proxy(host: &str) -> bool {
    let list = ["NO_PROXY", "no_proxy"]
        .iter()
        .find_map(|k| std::env::var(k).ok())
        .unwrap_or_default();
    let host = host.to_ascii_lowercase();
    list.split(',')
        .map(|e| e.trim().to_ascii_lowercase())
        .filter(|e| !e.is_empty())
        .any(|e| {
            let e = e
                .split(':')
                .next()
                .unwrap_or_default()
                .trim_start_matches('.')
                .to_string();
            e == "*" || host == e || host.ends_with(&format!(".{e}"))
        })
}

fn checked_addrs(host: &str, port: u16, limits: Limits) -> Result<Vec<SocketAddr>, String> {
    let addrs: Vec<SocketAddr> = (host, port)
        .to_socket_addrs()
        .map_err(|e| format!("cannot resolve {host}: {e}"))?
        .collect();
    if addrs.is_empty() {
        return Err(format!("{host} has no addresses"));
    }
    if !limits.allow_private
        && let Some(bad) = addrs.iter().find(|a| is_internal(a.ip()))
    {
        return Err(format!(
            "{host} resolves to internal address {}; refused",
            bad.ip()
        ));
    }
    Ok(addrs)
}

/// Loopback, private, link-local (cloud metadata lives here), CGNAT,
/// unspecified, multicast and the IPv6 equivalents.
pub fn is_internal(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
                || v4.is_multicast()
                || v4.is_documentation()
                || o[0] == 0
                || (o[0] == 100 && (64..128).contains(&o[1]))
                || (o[0] == 198 && (18..20).contains(&o[1])) // RFC 2544 benchmarking
                || o[0] >= 240 // reserved
        }
        IpAddr::V6(v6) => {
            let s = v6.segments();
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || (s[0] & 0xfe00) == 0xfc00
                || (s[0] & 0xffc0) == 0xfe80
                || v6
                    .to_ipv4_mapped()
                    .is_some_and(|v4| is_internal(IpAddr::V4(v4)))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use intent::Action;
    use std::io::{BufRead, BufReader, Write};
    use std::net::TcpListener;

    #[test]
    fn public_agent_refuses_what_a_customer_must_not_reach() {
        for u in [
            "http://example.com/v1",
            "https://127.0.0.1/v1",
            "https://localhost/v1",
            "https://169.254.169.254/latest/meta-data",
            "https://[::1]/v1",
            "https://10.0.0.5/x",
            "https://192.168.1.1/x",
            "https://172.16.0.9/x",
            "https://100.64.0.1/x",
            "https://[fd00::1]/x",
            "https://user:pw@example.com/x",
            "https://0.0.0.0/x",
            "not a url",
        ] {
            assert!(public_agent(u).is_err(), "{u} should be refused");
        }
        let e = public_agent("https://169.254.169.254/x").err().unwrap();
        assert!(e.contains("internal address"), "{e}");
    }

    #[test]
    fn public_agent_accepts_a_public_address() {
        assert!(public_agent("https://93.184.216.34/v1/chat/completions").is_ok());
    }

    #[test]
    fn public_agent_never_follows_a_redirect() {
        // A server that answers 302 to a different place: the 302 comes back as it is.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            if let Ok((mut s, _)) = listener.accept() {
                let mut r = BufReader::new(s.try_clone().unwrap());
                let mut line = String::new();
                while r.read_line(&mut line).map(|n| n > 2).unwrap_or(false) {
                    line.clear();
                }
                let _ = s.write_all(b"HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:1/elsewhere\r\nContent-Length: 0\r\n\r\n");
            }
        });
        let agent = public_agent_with(
            &format!("http://127.0.0.1:{port}/v1"),
            Limits { allow_http: true, allow_private: true },
        )
        .unwrap();
        let resp = agent.post(&format!("http://127.0.0.1:{port}/v1")).send_json(json!({"x": 1}));
        let status = match resp {
            Ok(r) => r.status(),
            Err(ureq::Error::Status(c, _)) => c,
            Err(e) => panic!("{e}"),
        };
        assert_eq!(status, 302, "a redirect is returned, never followed");
    }

    fn policy_for(hosts: &str) -> Policy {
        policy::load_from_str(&format!(
            "rules:\n  - name: web\n    action: http_get\n    match: {{ url_hosts: [{hosts}] }}\n    verdict: allow\n"
        ))
        .unwrap()
    }

    fn get(url: &str) -> Intent {
        Intent::new(Action::HttpGet, json!({ "url": url }))
    }

    /// A one-shot HTTP server: answers each connection with the next canned
    /// response. Returns its port.
    fn serve(responses: Vec<String>) -> u16 {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        std::thread::spawn(move || {
            for (stream, resp) in l.incoming().zip(responses) {
                let mut s = stream.unwrap();
                let mut r = BufReader::new(s.try_clone().unwrap());
                let mut line = String::new();
                while r.read_line(&mut line).unwrap_or(0) > 2 {
                    line.clear();
                }
                s.write_all(resp.as_bytes()).unwrap();
            }
        });
        port
    }

    fn ok(body: &str) -> String {
        format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
    }

    const TEST: Limits = Limits {
        allow_http: true,
        allow_private: true,
    };

    #[test]
    fn refuses_plain_http_and_internal_addresses_by_default() {
        let p = policy_for("\"127.0.0.1\", \"localhost\"");
        let e = http_get(&get("http://127.0.0.1/"), &p, VerdictKind::Allow).unwrap_err();
        assert!(e.contains("only https"), "{e}");
        let e = http_get(&get("https://127.0.0.1/"), &p, VerdictKind::Allow).unwrap_err();
        assert!(e.contains("internal address"), "{e}");
        let e = http_get(&get("https://localhost/"), &p, VerdictKind::Allow).unwrap_err();
        assert!(e.contains("internal address"), "{e}");
    }

    #[test]
    fn refuses_credentials_in_urls() {
        let p = policy_for("\"example.com\"");
        let e = http_get(&get("https://user:pw@example.com/"), &p, VerdictKind::Allow).unwrap_err();
        assert!(e.contains("credentials"), "{e}");
    }

    #[test]
    fn an_internal_proxy_is_refused_unless_trusted() {
        let strict = Limits { allow_http: false, allow_private: false };
        for p in ["http://10.0.0.5:3128", "http://169.254.169.254:80", "http://127.0.0.1:8080", "http://[::1]:3128"] {
            let e = check_proxy(p, strict, false).unwrap_err();
            assert!(e.contains("proxy refused"), "{p}: {e}");
            assert!(check_proxy(p, strict, true).is_ok(), "{p} should pass when trusted");
        }
        assert!(check_proxy("http://1.1.1.1:3128", strict, false).is_ok());
    }

    #[test]
    fn internal_ranges() {
        for ip in [
            "10.0.0.1",
            "172.16.5.4",
            "192.168.1.1",
            "169.254.169.254",
            "100.64.0.1",
            "0.0.0.0",
            "::1",
            "fd00::1",
            "fe80::1",
            "::ffff:10.0.0.1",
            "198.18.0.1",
            "198.19.255.254",
            "240.0.0.1",
            "255.255.255.254",
        ] {
            assert!(is_internal(ip.parse().unwrap()), "{ip} should be internal");
        }
        for ip in ["1.1.1.1", "140.82.112.3", "2606:4700:4700::1111"] {
            assert!(!is_internal(ip.parse().unwrap()), "{ip} should be public");
        }
    }

    #[test]
    fn fetches_and_caps_the_body() {
        let port = serve(vec![ok(&"x".repeat(70_000))]);
        let p = policy_for("\"127.0.0.1\"");
        let r = fetch(
            &get(&format!("http://127.0.0.1:{port}/page")),
            &p,
            VerdictKind::Allow,
            TEST,
        )
        .unwrap();
        assert_eq!(r["status"], 200);
        assert_eq!(r["truncated"], true);
        assert_eq!(r["body"].as_str().unwrap().len(), MAX_BODY_BYTES as usize);
    }

    #[test]
    fn redirect_to_an_allowed_host_is_followed() {
        let port = serve(vec![
            "HTTP/1.1 302 Found\r\nLocation: /next\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".into(),
            ok("landed"),
        ]);
        let p = policy_for("\"127.0.0.1\"");
        let r = fetch(
            &get(&format!("http://127.0.0.1:{port}/start")),
            &p,
            VerdictKind::Allow,
            TEST,
        )
        .unwrap();
        assert_eq!(r["body"], "landed");
        assert_eq!(r["redirects"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn redirect_off_the_allowlist_is_refused() {
        let port = serve(vec![
            "HTTP/1.1 302 Found\r\nLocation: https://evil.example/collect?k=secret\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".into(),
        ]);
        let p = policy_for("\"127.0.0.1\"");
        let e = fetch(
            &get(&format!("http://127.0.0.1:{port}/start")),
            &p,
            VerdictKind::Allow,
            TEST,
        )
        .unwrap_err();
        assert!(e.contains("redirected to https://evil.example"), "{e}");
    }
}
