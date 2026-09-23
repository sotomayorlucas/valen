use std::env;
use std::process::Command;

// CWE-78: command injection via argv -> Command::new
fn main() {
    let arg = env::args().nth(1).unwrap_or_default();
    let _ = Command::new(&arg).output();

    if let Ok(cmd) = env::var("CMD") {
        let _ = Command::new("sh").arg("-c").arg(cmd).output();
    }
}
