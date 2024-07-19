use reqwest::blocking::Client;
use serde::Deserialize;
use std::env;

const SHODAN_API_KEY: &str = "YOUR_API_KEY";

#[derive(Deserialize)]
struct ShodanHost {
    ip_str: String,
    org: Option<String>,
    os: Option<String>,
    data: Vec<ShodanData>,
}

#[derive(Deserialize)]
struct ShodanData {
    port: u16,
    data: String,
}

fn get_host_info(client: &Client, ip: &str) -> Result<ShodanHost, reqwest::Error> {
    let url = format!("https://api.shodan.io/shodan/host/{}?key={}", ip, SHODAN_API_KEY);
    let response = client.get(&url).send()?.json::<ShodanHost>()?;
    Ok(response)
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: {} <IP_ADDRESS>", args[0]);
        return;
    }

    let ip = &args[1];
    let client = Client::new();

    match get_host_info(&client, ip) {
        Ok(host) => {
            println!("IP: {}", host.ip_str);
            println!("Organization: {}", host.org.unwrap_or_else(|| "n/a".to_string()));
            println!("Operating System: {}", host.os.unwrap_or_else(|| "n/a".to_string()));

            for item in host.data {
                println!("Port: {}", item.port);
                println!("Banner: {}", item.data);
            }
        }
        Err(err) => eprintln!("Error: {}", err),
    }
}
