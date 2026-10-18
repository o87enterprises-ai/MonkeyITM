//! `broker verify`: check a log's hash chain (docs/LOG_CHAIN.md).

use eventlog::EventLog;

const HELP: &str = "\
broker verify: check that a log has not been altered.

usage: broker verify [--db FILE] [--head HASH] [--rows N]

  --db FILE    the log database (default: BROKER_LOG, else broker.db)
  --head HASH  the chain head you recorded elsewhere (the export summary's chain.head)
  --rows N     the number of chain entries you recorded elsewhere (chain.rows)

Without --head and --rows it finds an edited, deleted, inserted or re-ordered record. With them
it also finds a log that was cut short or rewritten from the start. Exit status: 0 intact,
1 problems found, 2 could not check.";

/// Ok(true) when the log is intact.
pub fn run(args: &[String]) -> Result<bool, String> {
    let mut db = std::env::var("BROKER_LOG").unwrap_or_else(|_| crate::DEFAULT_LOG_PATH.to_string());
    let (mut head, mut rows) = (None, None);
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--db" => db = it.next().ok_or("--db needs a file")?.clone(),
            "--head" => head = Some(it.next().ok_or("--head needs a hash")?.clone()),
            "--rows" => {
                rows = Some(
                    it.next()
                        .ok_or("--rows needs a number")?
                        .parse::<i64>()
                        .map_err(|_| "--rows must be a whole number".to_string())?,
                )
            }
            "-h" | "--help" => {
                println!("{HELP}");
                return Ok(true);
            }
            other => return Err(format!("unknown argument `{other}`\n\n{HELP}")),
        }
    }
    let log = EventLog::open_readonly(&db).map_err(|e| format!("cannot open {db}: {e}"))?;
    let r = log
        .verify_against(head.as_deref(), rows)
        .map_err(|e| format!("cannot read {db}: {e}"))?;
    println!("chain: {} entries, head {}", r.rows, r.head);
    if r.ok {
        println!("OK: every record is in the chain and unchanged");
    } else {
        println!("PROBLEMS:");
        for p in &r.problems {
            println!("  - {p}");
        }
    }
    Ok(r.ok)
}
