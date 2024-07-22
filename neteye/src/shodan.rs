use reqwest::blocking::Client;
use serde::Deserialize;
use std::error::Error;

const SHODAN_API_KEY: &str = "YOUR_SHODAN_API_KEY";

#[derive(Deserialize, Debug)]
struct ShodanHost {
    ip_str: Option<String>,
    org: Option<String>,
    os: Option<String>,
    data: Option<Vec<ShodanData>>,
    city: Option<String>,
    region_code: Option<String>,
    country_name: Option<String>,
    isp: Option<String>,
}

#[derive(Deserialize, Debug)]
struct ShodanData {
    port: u16,
    data: String,
}

#[derive(Deserialize, Debug)]
struct ShodanError {
    error: String,
}

fn get_host_info(client: &Client, ip: &str) -> Result<ShodanHost, Box<dyn Error>> {
    let url = format!("https://api.shodan.io/shodan/host/{}?key={}", ip, SHODAN_API_KEY);
    let response = client.get(&url).send()?.text()?; // Get the raw text response

    // Check if the response contains an error
    if let Ok(shodan_error) = serde_json::from_str::<ShodanError>(&response) {
        return Err(Box::new(std::io::Error::new(std::io::ErrorKind::Other, shodan_error.error)));
    }

    // Parse the response as ShodanHost
    let shodan_host = serde_json::from_str::<ShodanHost>(&response)?;
    Ok(shodan_host)
}

pub fn shodan_scan(ip: &str) -> Result<(), Box<dyn Error>> {
    let client = Client::new();

    match get_host_info(&client, ip) {
        Ok(host) => {
            println!("IP: {}", host.ip_str.unwrap_or_else(|| "n/a".to_string()));
            println!("Organization: {}", host.org.unwrap_or_else(|| "n/a".to_string()));
            println!("Operating System: {}", host.os.unwrap_or_else(|| "n/a".to_string()));
            println!("City: {}", host.city.unwrap_or_else(|| "n/a".to_string()));
            println!("Region: {}", host.region_code.unwrap_or_else(|| "n/a".to_string()));
            println!("Country: {}", host.country_name.unwrap_or_else(|| "n/a".to_string()));
            println!("ISP: {}", host.isp.unwrap_or_else(|| "n/a".to_string()));
            println!("Open Ports:");

            if let Some(data) = host.data {
                for item in data {
                    println!("  Port: {}", item.port);
                    println!("  Banner:\n  {}", item.data);
                }
            } else {
                println!("No data available for this IP.");
            }
        }
        Err(err) => eprintln!("Error: {}", err),
    }

    Ok(())
}
