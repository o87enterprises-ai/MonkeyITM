//! Thin entry point. All decision logic lives in `broker` (see lib.rs).

use broker::{DEFAULT_POLICY_PATH, banner, run_server};

const HELP: &str = "\
MonkeyITM-VM broker: the agent asks, the broker decides, executes and logs.

usage:
  broker                 run the broker on /tmp/broker.sock
  broker export [...]    save the log as json, jsonl or text (broker export --help)
  broker verify [...]    check that a log was not altered (broker verify --help)
  broker stage [...]     fetch approved URLs before a run, sanitize them and
                         release them read-only to /tmp/safe/staged (broker stage --help)
  broker --help          this message

environment:
  BROKER_POLICY              policy file (default policies/default.yaml)
  BROKER_LOG                 log database (default broker.db)
  BROKER_LLM_URL / _MODEL / _KEY
                             model endpoint the broker calls for llm_chat;
                             the agent never sees these
  BROKER_LLM_MAX_TOKENS      reply limit per model call (default 1024)
  BROKER_UNATTENDED=1        no human at the keyboard: escalations are denied
                             and counted (benchmark runs)
  BROKER_TRIPWIRE=N          halt the run after N denied requests: everything
                             after is refused and logged, the workbench killed
  BROKER_WORKBENCH           task container; enables exec and write_file
                             inside it, and read_file under /workspace
  BROKER_WORKBENCH_DIR       host directory mounted at /workspace
  BROKER_WORKBENCH_USER      user for commands in the container (optional)
  BROKER_EXEC_MAX_TIMEOUT_S  upper bound on one command (default 600)
  BROKER_DOCKER              container CLI (default docker; podman works)
  BROKER_MAX_AGENTS=N        let the root agent start children, up to N agents
                             in all (default 1: off); policy must also allow
                             spawn_agent. See docs/MULTI_AGENT.md
  BROKER_AGENT_DIR           private directory for child sockets and output
                             (default /tmp/broker-agents-<pid>; must not exist)
  BROKER_CHILD_LAUNCHER      program that starts one child (default
                             scripts/run-child.sh)

web access:
  The agent never has a network. Use `broker stage` before a run: a separate
  fetcher process gets only the URLs you approve, the broker checks its hashes,
  the text is sanitized and flagged, and released read-only for read_file.
  Every step is logged by source (broker, fetcher, sanitizer).
  http_get also exists for policies that allow it (match: { url_hosts: [...] });
  the default policy denies it.

scripts:
  scripts/run-agent.sh --rogue | --task \"...\"   run an agent in the sandbox
  scripts/run-bench.sh tasks/<name>             proctored benchmark run
  scripts/smoke.sh                              quick policy check

docs: README.md, docs/PROTOCOL.md, docs/BROKERED_EXEC.md, docs/THREAT_MODEL.md";

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("export") => {
            if let Err(e) = broker::export::run(&args[1..]) {
                eprintln!("broker export: {e}");
                std::process::exit(2);
            }
            return Ok(());
        }
        Some("verify") => {
            match broker::verify::run(&args[1..]) {
                Ok(true) => return Ok(()),
                Ok(false) => std::process::exit(1),
                Err(e) => {
                    eprintln!("broker verify: {e}");
                    std::process::exit(2);
                }
            }
        }
        Some("stage") => {
            if let Err(e) = broker::stage::cli(&args[1..]) {
                eprintln!("broker stage: {e}");
                std::process::exit(2);
            }
            return Ok(());
        }
        Some("fetch-job") => {
            if let Err(e) = broker::stage::fetch_job_cli(&args[1..]) {
                eprintln!("broker fetch-job: {e}");
                std::process::exit(2);
            }
            return Ok(());
        }
        Some("-h" | "--help" | "help") => {
            println!("{HELP}");
            return Ok(());
        }
        Some(other) => {
            eprintln!("broker: unknown argument `{other}`\n\n{HELP}");
            std::process::exit(2);
        }
        None => {}
    }

    banner::print_banner();

    let policy_path =
        std::env::var("BROKER_POLICY").unwrap_or_else(|_| DEFAULT_POLICY_PATH.to_string());

    let policy = match policy::load_from_path(&policy_path) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("broker: failed to load policy from {policy_path}: {e}");
            std::process::exit(2);
        }
    };
    eprintln!(
        "broker: loaded {} rule(s) from {policy_path}",
        policy.rules.len()
    );

    run_server(policy).await
}
