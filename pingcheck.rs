use std::env;
use std::process::Command;

fn main() {
    // Read the IP address from the command line arguments
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: {} <IP_ADDRESS>", args[0]);
        std::process::exit(1);
    }

    let ip_address = &args[1];

    // Call the function to perform the ping check
    match perform_ping(ip_address) {
        Ok(success) => {
            if success {
                println!("Ping to {} succeeded!", ip_address);
            } else {
                println!("Ping to {} failed!", ip_address);
            }
        },
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    }
}

fn perform_ping(ip_address: &str) -> Result<bool, String> {
    let output = Command::new("ping")
        .arg("-c")
        .arg("1")
        .arg(ip_address)
        .output()
        .map_err(|e| e.to_string())?;

    if output.status.success() {
        Ok(true)
    } else {
        Ok(false)
    }
}
