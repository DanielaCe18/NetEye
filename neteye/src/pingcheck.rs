use std::process::Command;

pub fn ping_check(ip_address: &str) -> Result<bool, String> {
    let output = if cfg!(target_os = "windows") {
        // On Windows, use `-n` instead of `-c`
        Command::new("ping")
            .arg("-n")
            .arg("1")
            .arg(ip_address)
            .output()
            .map_err(|e| e.to_string())?
    } else {
        // On Unix-like systems, use `-c`
        Command::new("ping")
            .arg("-c")
            .arg("1")
            .arg(ip_address)
            .output()
            .map_err(|e| e.to_string())?
    };

    if output.status.success() {
        Ok(true)
    } else {
        Ok(false)
    }
}
