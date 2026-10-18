//! The workbench: a disposable task container the agent works in but can
//! never touch directly. Every command and file operation in it is an
//! intent the broker approved and the broker performs.
//!
//! Configured by the harness (see `scripts/run-bench.sh`):
//!   BROKER_WORKBENCH          container name or id (run with `--network none`)
//!   BROKER_WORKBENCH_DIR      host directory bind-mounted at /workspace
//!   BROKER_WORKBENCH_USER     optional user for `docker exec -u`
//!   BROKER_EXEC_MAX_TIMEOUT_S upper bound on a command's timeout (default 600)
//!   BROKER_DOCKER             container CLI (default `docker`; `podman` works)
//!
//! Containment comes from the container (no network, no secrets, no hidden
//! tests, thrown away afterwards), not from parsing command lines.

use intent::{Intent, VerdictKind};
use policy::{Policy, normalize_path};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

pub const WORKSPACE: &str = "/workspace";
pub const MAX_WRITE_BYTES: usize = 1024 * 1024;
pub const MAX_OUTPUT_BYTES: usize = 64 * 1024;
pub const DEFAULT_TIMEOUT_S: u64 = 60;

pub struct Workbench {
    container: String,
    dir: PathBuf,
    user: Option<String>,
    max_timeout_s: u64,
    docker: String,
}

pub fn is_workspace_path(intent: &Intent) -> bool {
    intent
        .params
        .get("path")
        .and_then(Value::as_str)
        .and_then(normalize_path)
        .is_some_and(|p| p == WORKSPACE || p.starts_with("/workspace/"))
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

impl Workbench {
    pub fn from_env() -> Option<Self> {
        let container = std::env::var("BROKER_WORKBENCH")
            .ok()
            .filter(|s| !s.is_empty())?;
        let dir = std::env::var("BROKER_WORKBENCH_DIR").ok()?;
        Some(Self::new(
            container,
            std::fs::canonicalize(dir).ok()?,
            std::env::var("BROKER_WORKBENCH_USER")
                .ok()
                .filter(|s| !s.is_empty()),
            std::env::var("BROKER_EXEC_MAX_TIMEOUT_S")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(600),
            std::env::var("BROKER_DOCKER").unwrap_or_else(|_| "docker".into()),
        ))
    }

    pub fn new(
        container: String,
        dir: PathBuf,
        user: Option<String>,
        max_timeout_s: u64,
        docker: String,
    ) -> Self {
        Self {
            container,
            dir,
            user,
            max_timeout_s,
            docker,
        }
    }

    /// Map a `/workspace/...` path to the host directory. Lexical only.
    fn host_path(&self, container_path: &str) -> Result<PathBuf, String> {
        let norm = normalize_path(container_path).ok_or("path must be absolute")?;
        let rest = norm
            .strip_prefix(WORKSPACE)
            .filter(|r| r.is_empty() || r.starts_with('/'))
            .ok_or("path is outside /workspace")?;
        Ok(self.dir.join(rest.trim_start_matches('/')))
    }

    /// Host path (already canonical) back to its `/workspace/...` form, or an
    /// error if symlinks carried it outside the workspace.
    fn contained(&self, canon: &Path) -> Result<String, String> {
        let rel = canon
            .strip_prefix(&self.dir)
            .map_err(|_| "path resolves outside /workspace (symlink escape refused)".to_string())?;
        let rel = rel.to_str().ok_or("path is not valid UTF-8")?;
        Ok(if rel.is_empty() {
            WORKSPACE.to_string()
        } else {
            format!("{WORKSPACE}/{rel}")
        })
    }

    /// Re-ask the policy about the path the operation will really touch.
    fn recheck(
        intent: &Intent,
        real: &str,
        policy: &Policy,
        kind: VerdictKind,
    ) -> Result<(), String> {
        let mut probe = intent.clone();
        probe.params["path"] = json!(real);
        let again = policy.decide(&probe).verdict;
        if again != kind {
            return Err(format!(
                "path resolves to {real}, which policy treats as {again:?}, not {kind:?}"
            ));
        }
        Ok(())
    }

    pub fn read_file(
        &self,
        intent: &Intent,
        policy: &Policy,
        kind: VerdictKind,
    ) -> Result<Value, String> {
        let raw = intent
            .params
            .get("path")
            .and_then(Value::as_str)
            .ok_or("read_file needs a string `path`")?;
        let canon = std::fs::canonicalize(self.host_path(raw)?)
            .map_err(|e| format!("cannot resolve path: {e}"))?;
        let real = self.contained(&canon)?;
        Self::recheck(intent, &real, policy, kind)?;

        let f = std::fs::File::open(&canon).map_err(|e| format!("open failed: {e}"))?;
        if !f.metadata().map_err(|e| e.to_string())?.is_file() {
            return Err("not a regular file".into());
        }
        let mut buf = Vec::new();
        f.take(crate::exec::MAX_READ_BYTES + 1)
            .read_to_end(&mut buf)
            .map_err(|e| format!("read failed: {e}"))?;
        let truncated = buf.len() as u64 > crate::exec::MAX_READ_BYTES;
        buf.truncate(crate::exec::MAX_READ_BYTES as usize);
        Ok(
            json!({ "path": real, "content": String::from_utf8_lossy(&buf), "truncated": truncated }),
        )
    }

    /// params: { "path": "/workspace/...", "content": "...", "mode": "overwrite" | "append" }
    pub fn write_file(
        &self,
        intent: &Intent,
        policy: &Policy,
        kind: VerdictKind,
    ) -> Result<Value, String> {
        let p = &intent.params;
        let raw = p
            .get("path")
            .and_then(Value::as_str)
            .ok_or("write_file needs a string `path`")?;
        let content = p
            .get("content")
            .and_then(Value::as_str)
            .ok_or("write_file needs a string `content`")?;
        if content.len() > MAX_WRITE_BYTES {
            return Err(format!(
                "content too large ({} bytes, max {MAX_WRITE_BYTES})",
                content.len()
            ));
        }
        let append = match p.get("mode").and_then(Value::as_str).unwrap_or("overwrite") {
            "overwrite" => false,
            "append" => true,
            other => return Err(format!("unknown mode `{other}` (use overwrite or append)")),
        };

        let host = self.host_path(raw)?;
        let name = host.file_name().ok_or("path must name a file")?.to_owned();
        let parent = std::fs::canonicalize(host.parent().ok_or("path has no parent")?)
            .map_err(|e| format!("parent directory does not exist: {e}"))?;
        let target = parent.join(name);
        let real = self.contained(&target)?;
        if let Ok(meta) = std::fs::symlink_metadata(&target) {
            if meta.file_type().is_symlink() {
                return Err("refusing to write through a symlink".into());
            }
            if !meta.is_file() {
                return Err("target exists and is not a regular file".into());
            }
        }
        Self::recheck(intent, &real, policy, kind)?;

        let mut f = open_for_write(&target, append).map_err(|e| format!("open failed: {e}"))?;
        f.write_all(content.as_bytes())
            .map_err(|e| format!("write failed: {e}"))?;
        Ok(json!({
            "path": real,
            "mode": if append { "append" } else { "overwrite" },
            "bytes_written": content.len(),
            "sha256": sha256_hex(content.as_bytes()),
        }))
    }

    /// Stop the container immediately (the tripwire's hard stop).
    pub fn kill(&self) -> Result<(), String> {
        let out = Command::new(&self.docker)
            .args(["kill", &self.container])
            .stdin(Stdio::null())
            .output()
            .map_err(|e| format!("could not run {}: {e}", self.docker))?;
        if out.status.success() {
            Ok(())
        } else {
            Err(String::from_utf8_lossy(&out.stderr).trim().to_string())
        }
    }

    /// params: { "argv": ["prog", "arg", ...], "cwd": "/workspace/...", "timeout_s": 60 }
    pub fn exec(&self, intent: &Intent) -> Result<Value, String> {
        let argv: Vec<String> = intent
            .params
            .get("argv")
            .and_then(Value::as_array)
            .ok_or("exec needs an `argv` list, e.g. [\"python3\", \"-V\"] (use [\"bash\", \"-c\", \"...\"] for shell syntax)")?
            .iter()
            .map(|a| a.as_str().filter(|s| !s.contains('\0')).map(str::to_owned))
            .collect::<Option<_>>()
            .ok_or("every argv entry must be a string without NUL bytes")?;
        if argv.is_empty() {
            return Err("argv is empty".into());
        }
        let cwd = policy::exec_cwd(intent).ok_or("cwd must be an absolute path")?;
        if cwd != WORKSPACE && !cwd.starts_with("/workspace/") {
            return Err(format!("cwd {cwd} is outside /workspace"));
        }
        let timeout_s = intent
            .params
            .get("timeout_s")
            .and_then(Value::as_u64)
            .unwrap_or(DEFAULT_TIMEOUT_S)
            .clamp(1, self.max_timeout_s);

        let mut cmd = Command::new(&self.docker);
        cmd.arg("exec").arg("-w").arg(&cwd);
        if let Some(u) = &self.user {
            cmd.arg("-u").arg(u);
        }
        // `timeout` runs inside the container so the command itself dies,
        // not just the docker client. The watchdog below is the backstop.
        cmd.arg(&self.container)
            .args(["timeout", "-k", "5", &timeout_s.to_string()])
            .args(&argv)
            .env_clear()
            .envs(
                [
                    "PATH",
                    "HOME",
                    "DOCKER_HOST",
                    "DOCKER_CONTEXT",
                    "XDG_RUNTIME_DIR",
                ]
                .iter()
                .filter_map(|k| std::env::var(k).ok().map(|v| (*k, v))),
            )
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        let started = Instant::now();
        let mut child = cmd
            .spawn()
            .map_err(|e| format!("could not start {}: {e}", self.docker))?;
        let out = capture(child.stdout.take().expect("piped"));
        let err = capture(child.stderr.take().expect("piped"));

        let deadline = started + Duration::from_secs(timeout_s + 15);
        let mut killed = false;
        let status = loop {
            match child.try_wait().map_err(|e| e.to_string())? {
                Some(s) => break s,
                None if Instant::now() >= deadline => {
                    let _ = child.kill();
                    killed = true;
                    break child.wait().map_err(|e| e.to_string())?;
                }
                None => std::thread::sleep(Duration::from_millis(20)),
            }
        };
        let (stdout, stdout_len, stdout_sha) = out.join().expect("reader thread");
        let (stderr, stderr_len, stderr_sha) = err.join().expect("reader thread");
        let exit_code = status.code();

        Ok(json!({
            "argv": argv,
            "cwd": cwd,
            "exit_code": exit_code,
            "timed_out": killed || exit_code == Some(124),
            "duration_ms": started.elapsed().as_millis() as u64,
            "stdout": String::from_utf8_lossy(&stdout),
            "stderr": String::from_utf8_lossy(&stderr),
            "stdout_bytes": stdout_len,
            "stderr_bytes": stderr_len,
            "stdout_sha256": stdout_sha,
            "stderr_sha256": stderr_sha,
            "truncated": stdout_len > MAX_OUTPUT_BYTES || stderr_len > MAX_OUTPUT_BYTES,
        }))
    }
}

/// Read a pipe to the end: keep the first MAX_OUTPUT_BYTES, hash all of it.
fn capture(mut r: impl Read + Send + 'static) -> std::thread::JoinHandle<(Vec<u8>, usize, String)> {
    std::thread::spawn(move || {
        let (mut kept, mut total, mut h, mut chunk) =
            (Vec::new(), 0usize, Sha256::new(), [0u8; 8192]);
        while let Ok(n) = r.read(&mut chunk) {
            if n == 0 {
                break;
            }
            h.update(&chunk[..n]);
            total += n;
            let room = MAX_OUTPUT_BYTES.saturating_sub(kept.len());
            kept.extend_from_slice(&chunk[..n.min(room)]);
        }
        (kept, total, hex(&h.finalize()))
    })
}

/// Open a write target without following a symlink at the final component,
/// so a link swapped in after the checks above cannot redirect the write.
fn open_for_write(target: &Path, append: bool) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .append(append)
        .truncate(!append)
        .custom_flags(libc::O_NOFOLLOW)
        .open(target)
}

#[cfg(test)]
mod tests {
    #[test]
    fn open_for_write_refuses_a_symlink() {
        let dir = tempfile::tempdir().unwrap();
        let outside = dir.path().join("outside.txt");
        std::fs::write(&outside, "keep").unwrap();
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&outside, &link).unwrap();
        assert!(super::open_for_write(&link, false).is_err());
        assert!(super::open_for_write(&link, true).is_err());
        assert_eq!(std::fs::read_to_string(&outside).unwrap(), "keep");
    }

    use super::*;
    use intent::Action;

    fn setup() -> (tempfile::TempDir, Workbench, Policy) {
        let tmp = tempfile::tempdir().unwrap();
        let dir = std::fs::canonicalize(tmp.path()).unwrap();
        std::fs::write(dir.join("ok.txt"), "hello").unwrap();
        std::fs::create_dir(dir.join("sub")).unwrap();
        std::os::unix::fs::symlink("/etc/passwd", dir.join("escape")).unwrap();
        std::os::unix::fs::symlink("/etc", dir.join("etcdir")).unwrap();
        let wb = Workbench::new("unused".into(), dir, None, 600, "docker".into());
        let policy = policy::load_from_str(
            "rules:\n  - name: ws\n    action: any\n    match: { path_prefix: \"/workspace/\" }\n    verdict: allow\n",
        )
        .unwrap();
        (tmp, wb, policy)
    }

    fn intent(action: Action, params: Value) -> Intent {
        Intent::new(action, params)
    }

    #[test]
    fn reads_inside_workspace() {
        let (_t, wb, p) = setup();
        let r = wb
            .read_file(
                &intent(Action::ReadFile, json!({"path": "/workspace/ok.txt"})),
                &p,
                VerdictKind::Allow,
            )
            .unwrap();
        assert_eq!(r["content"], "hello");
        assert_eq!(r["path"], "/workspace/ok.txt");
    }

    #[test]
    fn symlink_out_of_workspace_is_refused_for_read_and_write() {
        let (_t, wb, p) = setup();
        let e = wb
            .read_file(
                &intent(Action::ReadFile, json!({"path": "/workspace/escape"})),
                &p,
                VerdictKind::Allow,
            )
            .unwrap_err();
        assert!(e.contains("outside /workspace"), "{e}");
        let w = intent(
            Action::WriteFile,
            json!({"path": "/workspace/etcdir/pwned", "content": "x"}),
        );
        let e = wb.write_file(&w, &p, VerdictKind::Allow).unwrap_err();
        assert!(e.contains("outside /workspace"), "{e}");
        let w = intent(
            Action::WriteFile,
            json!({"path": "/workspace/escape", "content": "x"}),
        );
        assert!(wb.write_file(&w, &p, VerdictKind::Allow).is_err());
    }

    #[test]
    fn traversal_is_outside_workspace() {
        let (_t, wb, p) = setup();
        let e = wb
            .read_file(
                &intent(
                    Action::ReadFile,
                    json!({"path": "/workspace/../etc/passwd"}),
                ),
                &p,
                VerdictKind::Allow,
            )
            .unwrap_err();
        assert!(e.contains("outside /workspace"), "{e}");
    }

    #[test]
    fn writes_overwrite_and_append() {
        let (_t, wb, p) = setup();
        let w = intent(
            Action::WriteFile,
            json!({"path": "/workspace/sub/new.txt", "content": "a"}),
        );
        let r = wb.write_file(&w, &p, VerdictKind::Allow).unwrap();
        assert_eq!(r["bytes_written"], 1);
        let w = intent(
            Action::WriteFile,
            json!({"path": "/workspace/sub/new.txt", "content": "b", "mode": "append"}),
        );
        wb.write_file(&w, &p, VerdictKind::Allow).unwrap();
        let r = wb
            .read_file(
                &intent(Action::ReadFile, json!({"path": "/workspace/sub/new.txt"})),
                &p,
                VerdictKind::Allow,
            )
            .unwrap();
        assert_eq!(r["content"], "ab");
    }

    #[test]
    fn exec_rejects_bad_params_before_running_anything() {
        let (_t, wb, _p) = setup();
        assert!(
            wb.exec(&intent(Action::Exec, json!({"cmd": "ls"})))
                .unwrap_err()
                .contains("argv")
        );
        assert!(
            wb.exec(&intent(Action::Exec, json!({"argv": []})))
                .unwrap_err()
                .contains("empty")
        );
        assert!(
            wb.exec(&intent(
                Action::Exec,
                json!({"argv": ["ls"], "cwd": "/etc"})
            ))
            .unwrap_err()
            .contains("outside")
        );
    }
}
