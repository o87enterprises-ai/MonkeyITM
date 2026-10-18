//! Startup banner and colorized status output. Hand-rolled ANSI escapes —
//! no crate dependency for something this small.

use intent::VerdictKind;

const RESET: &str = "\x1b[0m";
const BOLD: &str = "\x1b[1m";
const DIM: &str = "\x1b[2m";
const CYAN: &str = "\x1b[36m";
const BLUE: &str = "\x1b[34m";
const GREEN: &str = "\x1b[32m";
const RED: &str = "\x1b[31m";
const YELLOW: &str = "\x1b[33m";

const MONKEY: &str = r#"   .-"``"-.
  /  o  o  \
 |     <>   |
  \  \__/  /
   `.____.'"#;

const WORDMARK: &str = r#" __  __             _              ___ _____ __  __    __     ____  __
|  \/  | ___  _ __ | | _____ _   _|_ _|_   _|  \/  |   \ \   / /  \/  |
| |\/| |/ _ \| '_ \| |/ / _ \ | | || |  | | | |\/| |____\ \ / /| |\/| |
| |  | | (_) | | | |   <  __/ |_| || |  | | | |  | |_____\ V / | |  | |
|_|  |_|\___/|_| |_|_|\_\___|\__, |___| |_| |_|  |_|      \_/  |_|  |_|
                             |___/"#;

/// Prints the startup banner: monkey icon, then the wordmark, then the
/// tagline. Colors degrade gracefully to plain text on terminals that
/// ignore ANSI codes.
pub fn print_banner() {
    eprintln!();
    for line in MONKEY.lines() {
        eprintln!("{CYAN}{line}{RESET}");
    }
    eprintln!();
    for line in WORDMARK.lines() {
        eprintln!("{BLUE}{BOLD}{line}{RESET}");
    }
    eprintln!("{DIM}  broker-in-the-middle containment for AI agents{RESET}");
    eprintln!();
}

/// Colorizes a verdict label for terminal log lines.
pub fn colorize_verdict(kind: VerdictKind) -> String {
    match kind {
        VerdictKind::Allow => format!("{GREEN}{BOLD}ALLOW{RESET}"),
        VerdictKind::Deny => format!("{RED}{BOLD}DENY{RESET}"),
        VerdictKind::ApproveRequired => format!("{YELLOW}{BOLD}APPROVE_REQUIRED{RESET}"),
        VerdictKind::Transform => format!("{CYAN}{BOLD}TRANSFORM{RESET}"),
        VerdictKind::DryRun => format!("{DIM}{BOLD}DRY_RUN{RESET}"),
    }
}

/// Wraps the approval prompt box in a highlighted color.
pub fn approval_header() -> String {
    format!("{YELLOW}{BOLD}APPROVAL REQUIRED{RESET}")
}

pub fn dim(s: &str) -> String {
    format!("{DIM}{s}{RESET}")
}
