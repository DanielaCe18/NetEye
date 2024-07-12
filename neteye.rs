use std::fs;
use std::process::Command;
use serde::Deserialize;
use serde_xml_rs::from_reader;
use std::path::Path;
use clap::{Arg, App, ArgEnum};

#[derive(Debug, Deserialize)]
struct NmapService {
    portid: u16,
    protocol: String,
    state: NmapState,
    service: NmapServiceDetails,
}

#[derive(Debug, Deserialize)]
struct NmapState {
    state: String,
}

#[derive(Debug, Deserialize)]
struct NmapServiceDetails {
    #[serde(rename = "name")]
    service: String,
    #[serde(rename = "product")]
    product: Option<String>,
    #[serde(rename = "version")]
    version: Option<String>,
}

#[derive(Debug, Deserialize)]
struct NmapHost {
    address: String,
    ports: Vec<NmapService>,
}

#[derive(Debug, Deserialize)]
struct NmapRun {
    #[serde(rename = "host")]
    hosts: Vec<NmapHost>,
}

fn run_nmap(address: &str, outdir: &str, srvname: &str, nmapparams: &str, ports: &str, protocol: Protocol) -> Vec<(String, i32, String)> {
    let out = format!("{}/{}{}", outdir, address, srvname);
    let scan_type = match protocol {
        Protocol::Tcp => "-sS",
        Protocol::Udp => "-sU",
    };

    let cmd = format!(
        "nmap -vv --reason -sV -sC {} {} -p {} -oN \"{}/0_{}_nmap.txt\" -oX \"{}/0_{}_nmap.xml\" {}",
        nmapparams, scan_type, ports, out, protocol, out, protocol, address
    );

    Command::new("sh")
        .arg("-c")
        .arg(&cmd)
        .output()
        .expect("Failed to execute command");

    let mut nmap_svcs = vec![];

    if Path::new(&format!("{}/0_{}_nmap.xml", out, protocol)).exists() {
        let file = fs::File::open(format!("{}/0_{}_nmap.xml", out, protocol)).expect("Failed to open Nmap XML file");
        let report: NmapRun = from_reader(file).expect("Failed to parse Nmap XML");
        for host in report.hosts {
            for service in host.ports {
                if service.state.state == "open" {
                    let service_name = format_service_name(&service);
                    let port = if protocol == Protocol::Udp { -(service.portid as i32) } else { service.portid as i32 };
                    nmap_svcs.push((address.to_string(), port, service_name));
                }
            }
        }
    }

    nmap_svcs.sort_by_key(|s| s.1);
    nmap_svcs
}

fn format_service_name(service: &NmapService) -> String {
    let mut service_name = service.service.service.clone();
    if let Some(product) = &service.service.product {
        service_name.push_str(&format!(" running {}", product));
    }
    if let Some(version) = &service.service.version {
        service_name.push_str(&format!(" version {}", version));
    }
    service_name
}

fn run_amap(services: Vec<(String, i32, String)>, only_unidentified: bool, outdir: &str, srvname: &str) -> Vec<(String, i32, String)> {
    let out = format!("{}/{}{}", outdir, services[0].0, srvname);

    let mut ports_tcp = String::new();
    let mut ports_udp = String::new();

    for service in &services {
        if only_unidentified && !service.2.contains("unknown") {
            continue;
        }

        if service.1 < 0 {
            ports_udp.push_str(&format!("{},", -service.1));
        } else {
            ports_tcp.push_str(&format!("{},", service.1));
        }
    }

    let cmds = if !ports_tcp.is_empty() || !ports_udp.is_empty() {
        let mut cmds = vec![];
        if !ports_tcp.is_empty() {
            let ports = ports_tcp.trim_end_matches(',');
            cmds.push(format!("amap -A -bqv -m -o \"{}/0_tcp_amap.txt\" {} {}", out, services[0].0, ports));
        }
        if !ports_udp.is_empty() {
            let ports = ports_udp.trim_end_matches(',');
            cmds.push(format!("amap -A -bqvu -m -o \"{}/0_udp_amap.txt\" {} {}", out, services[0].0, ports));
        }
        cmds
    } else {
        vec![]
    };

    for cmd in cmds {
        Command::new("sh")
            .arg("-c")
            .arg(&cmd)
            .output()
            .expect("Failed to execute command");
    }

    let mut amap_svcs = vec![];

    if Path::new(&format!("{}/0_tcp_amap.txt", out)).exists() {
        let file = fs::File::open(format!("{}/0_tcp_amap.txt", out)).expect("Failed to open TCP Amap file");
        let reader = csv::ReaderBuilder::new()
            .delimiter(b':')
            .quote(b'"')
            .has_headers(false)
            .from_reader(file);
        for result in reader.into_records() {
            let record = result.expect("Failed to read record");
            if record.len() > 5 && !record[0].starts_with('#') {
                amap_svcs.push((record[0].to_string(), record[1].parse::<i32>().unwrap_or(0), record[5].to_string()));
            }
        }
    }

    if Path::new(&format!("{}/0_udp_amap.txt", out)).exists() {
        let file = fs::File::open(format!("{}/0_udp_amap.txt", out)).expect("Failed to open UDP Amap file");
        let reader = csv::ReaderBuilder::new()
            .delimiter(b':')
            .quote(b'"')
            .has_headers(false)
            .from_reader(file);
        for result in reader.into_records() {
            let record = result.expect("Failed to read record");
            if record.len() > 5 && !record[0].starts_with('#') {
                amap_svcs.push((record[0].to_string(), -record[1].parse::<i32>().unwrap_or(0), record[5].to_string()));
            }
        }
    }

    for (i, val) in services.iter().enumerate() {
        for amap_svc in &amap_svcs {
            if val.0 == amap_svc.0 && val.1 == amap_svc.1 && (val.2.contains("unknown") || !only_unidentified) {
                services[i] = amap_svc.clone();
            }
        }
    }

    services
}

#[derive(ArgEnum, Clone)]
enum Protocol {
    Tcp,
    Udp,
}

fn main() {
    let matches = App::new("Network Scanner")
        .version("1.0")
        .author("Author Name <author@example.com>")
        .about("Scans networks using nmap and amap")
        .arg(Arg::new("address")
            .about("The IP address to scan")
            .required(true)
            .index(1))
        .arg(Arg::new("ports")
            .about("Ports to scan (e.g. 1-1024, 21,22,80, or 80)")
            .short('p')
            .long("ports")
            .takes_value(true)
            .required(true))
        .arg(Arg::new("protocol")
            .about("Protocol to use for scanning")
            .short('P')
            .long("protocol")
            .possible_values(&Protocol::variants())
            .takes_value(true)
            .required(true))
        .get_matches();

    let address = matches.value_of("address").unwrap();
    let ports = matches.value_of("ports").unwrap();
    let protocol: Protocol = matches.value_of_t("protocol").unwrap();

    let outdir = "/path/to/output";
    let srvname = "_srv";
    let nmapparams = "-Pn";

    let services = run_nmap(address, outdir, srvname, nmapparams, ports, protocol.clone());
    let identified_services = run_amap(services, true, outdir, srvname);

    for service in identified_services {
        println!("{:?}", service);
    }
}
