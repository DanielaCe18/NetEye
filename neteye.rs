use std::fs;
use std::process::Command;
use serde::Deserialize;
use serde_xml_rs::from_reader;
use std::path::Path;
use clap::{Arg, App, ArgEnum};
use regex::Regex;

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

#[derive(ArgEnum, Clone)]
enum Protocol {
    Tcp,
    Udp,
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

fn enum_http(address: &str, port: u16, service: &str, basedir: &str) {
    let scheme = if service.contains("https") || service.contains("ssl") {
        "https"
    } else {
        "http"
    };
    let nikto_ssl = if scheme == "https" { " -ssl" } else { "" };

    let commands = vec![
        format!(
            "nmap -vv --reason -sV -p {} --script=\"(http* or ssl*) and not (broadcast or dos or external or http-slowloris* or fuzzer)\" -oN \"{}/{}_http_nmap.txt\" -oX \"{}/{}_http_nmap.xml\" {}",
            port, basedir, port, basedir, port, address
        ),
        format!(
            "curl -i {}://{}:{}/ -m 10 -o \"{}/{}_http_index.html\"",
            scheme, address, port, basedir, port
        ),
        format!(
            "curl -i {}://{}:{}/robots.txt -m 10 -o \"{}/{}_http_robots.txt\"",
            scheme, address, port, basedir, port
        ),
    ];

    for cmd in &commands {
        Command::new("sh")
            .arg("-c")
            .arg(cmd)
            .output()
            .expect("Failed to execute command");
    }

    let second_stage_commands = vec![
        format!(
            "gobuster dir -w /usr/share/seclists/Discovery/Web_Content/common.txt -t 10 -u {}://{}:{}/ -e -s \"200,204,301,302,307,403,500\" | tee \"{}/{}_http_dirb.txt\"",
            scheme, address, port, basedir, port
        ),
        format!(
            "nikto -h {}://{}:{}{} -o \"{}/{}_http_nikto.txt\"",
            scheme, address, port, nikto_ssl, basedir, port
        ),
    ];

    for cmd in &second_stage_commands {
        Command::new("sh")
            .arg("-c")
            .arg(cmd)
            .output()
            .expect("Failed to execute command");
    }
}

fn enum_smtp(address: &str, port: u16, basedir: &str) {
    let cmd = format!(
        "nmap -vv --reason -sV -p {} --script=\"(smtp*) and not (brute or broadcast or dos or external or fuzzer)\" -oN \"{}/{}_smtp_nmap.txt\" -oX \"{}/{}_smtp_nmap.xml\" {}",
        port, basedir, port, basedir, port, address
    );

    Command::new("sh")
        .arg("-c")
        .arg(&cmd)
        .output()
        .expect("Failed to execute command");
}

fn enum_pop3(address: &str, port: u16, basedir: &str) {
    let cmd = format!(
        "nmap -vv --reason -sV -p {} --script=\"(pop3*) and not (brute or broadcast or dos or external or fuzzer)\" -oN \"{}/{}_pop3_nmap.txt\" -oX \"{}/{}_pop3_nmap.xml\" {}",
        port, basedir, port, basedir, port, address
    );

    Command::new("sh")
        .arg("-c")
        .arg(&cmd)
        .output()
        .expect("Failed to execute command");
}

fn enum_imap(address: &str, port: u16, basedir: &str) {
    let cmd = format!(
        "nmap -vv --reason -sV -p {} --script=\"(imap*) and not (brute or broadcast or dos or external or fuzzer)\" -oN \"{}/{}_imap_nmap.txt\" -oX \"{}/{}_imap_nmap.xml\" {}",
        port, basedir, port, basedir, port, address
    );

    Command::new("sh")
        .arg("-c")
        .arg(&cmd)
        .output()
        .expect("Failed to execute command");
}

fn enum_ftp(address: &str, port: u16, basedir: &str) {
    let cmd = format!(
        "nmap -vv --reason -sV -p {} --script=\"(ftp*) and not (brute or broadcast or dos or external or fuzzer)\" -oN \"{}/{}_ftp_nmap.txt\" -oX \"{}/{}_ftp_nmap.xml\" {}",
        port, basedir, port, basedir, port, address
    );

    Command::new("sh")
        .arg("-c")
        .arg(&cmd)
        .output()
        .expect("Failed to execute command");
}

fn enum_smb(address: &str, port: u16, basedir: &str) {
    let nmap_port = if port == 139 || port == 445 {
        "139,445"
    } else {
        &port.to_string()
    };

    let cmds = vec![
        format!(
            "nmap -vv --reason -sV -p {} --script=\"(nbstat or smb*) and not (brute or broadcast or dos or external or fuzzer)\" --script-args=unsafe=1 -oN \"{}/{}_smb_nmap.txt\" -oX \"{}/{}_smb_nmap.xml\" {}",
            nmap_port, basedir, port, basedir, port, address
        ),
        format!(
            "enum4linux -a -M -l -d {} | tee \"{}/{}_smb_enum4linux.txt\"",
            address, basedir, port
        ),
        format!(
            "python2 /usr/share/doc/python-impacket/examples/samrdump.py {} {}/SMB | tee \"{}/{}_smb_samrdump.txt\"",
            address, port, basedir, port
        ),
        format!(
            "nbtscan -rvh {} | tee \"{}/{}_smb_nbtscan.txt\"",
            address, basedir, port
        ),
    ];

    for cmd in &cmds {
        Command::new("sh")
            .arg("-c")
            .arg(cmd)
            .output()
            .expect("Failed to execute command");
    }
}

fn enum_mssql(address: &str, port: u16, basedir: &str) {
    let cmd = format!(
        "nmap -vv --reason -sV -p {} --script=\"(ms-sql*) and not (brute or broadcast or dos or external or fuzzer)\" --script-args=mssql.instance-port={},mssql.username-sa,mssql.password-sa -oN \"{}/{}_mssql_nmap.txt\" -oX \"{}/{}_mssql_nmap.xml\" {}",
        port, port, basedir, port, basedir, port, address
    );

    Command::new("sh")
        .arg("-c")
        .arg(&cmd)
        .output()
        .expect("Failed to execute command");
}

fn enum_mysql(address: &str, port: u16, basedir: &str) {
    let cmd = format!(
        "nmap -vv --reason -sV -p {} --script=\"(mysql*) and not (brute or broadcast or dos or external or fuzzer)\" -oN \"{}/{}_mysql_nmap.txt\" -oX \"{}/{}_mysql_nmap.xml\" {}",
        port, basedir, port, basedir, port, address
    );

    Command::new("sh")
        .arg("-c")
        .arg(&cmd)
        .output()
        .expect("Failed to execute command");
}

fn enum_oracle(address: &str, port: u16, basedir: &str) {
    let cmd = format!(
        "nmap -vv --reason -sV -p {} --script=\"(oracle*) and not (brute or broadcast or dos or external or fuzzer)\" -oN \"{}/{}_oracle_nmap.txt\" -oX \"{}/{}_oracle_nmap.xml\" {}",
        port, basedir, port, basedir, port, address
    );

    Command::new("sh")
        .arg("-c")
        .arg(&cmd)
        .output()
        .expect("Failed to execute command");
}

fn enum_nfs(address: &str, port: u16, basedir: &str) {
    let cmd = format!(
        "nmap -vv --reason -sV -p {} --script=\"(rpcinfo or nfs*) and not (brute or broadcast or dos or external or fuzzer)\" -oN \"{}/{}_nfs_nmap.txt\" -oX \"{}/{}_nfs_nmap.xml\" {}",
        port, basedir, port, basedir, port, address
    );

    Command::new("sh")
        .arg("-c")
        .arg(&cmd)
        .output()
        .expect("Failed to execute command");
}

fn enum_snmp(address: &str, port: u16, basedir: &str) {
    let cmds = vec![
        format!(
            "nmap -vv --reason -sV -p {} --script=\"(snmp*) and not (brute or broadcast or dos or external or fuzzer)\" -oN \"{}/{}_snmp_nmap.txt\" -oX \"{}/{}_snmp_nmap.xml\" {}",
            port, basedir, port, basedir, port, address
        ),
        format!(
            "onesixtyone -c data/community -dd -o \"{}/{}_snmp_onesixtyone.txt\" {}",
            basedir, port, address
        ),
        format!(
            "snmpwalk -c public -v 1 {} | tee \"{}/{}_snmp_snmpwalk.txt\"",
            address, basedir, port
        ),
    ];

    for cmd in &cmds {
        Command::new("sh")
            .arg("-c")
            .arg(cmd)
            .output()
            .expect("Failed to execute command");
    }
}

fn enum_dns(address: &str, port: u16, basedir: &str) {
    let nmblookup_cmd = format!(
        "nmblookup -A {} | grep '<00>' | grep -v '<GROUP>' | cut -d' ' -f1",
        address
    );

    let host = match Command::new("sh")
        .arg("-c")
        .arg(&nmblookup_cmd)
        .output()
    {
        Ok(output) => String::from_utf8_lossy(&output.stdout).trim().to_string(),
        Err(_) => return,
    };

    let cmd = format!(
        "dig -p{} @{}.thinc.local thinc.local axfr > \"{}/{}_dns_dig.txt\"",
        port, host, basedir, port
    );

    Command::new("sh")
        .arg("-c")
        .arg(&cmd)
        .output()
        .expect("Failed to execute command");
}

fn enum_rdp(address: &str, port: u16, basedir: &str) {
    let cmd = format!(
        "nmap -vv --reason -sV -p {} --script=\"(rdp*) and not (brute or broadcast or dos or external or fuzzer)\" -oN \"{}/{}_rdp_nmap.txt\" -oX \"{}/{}_rdp_nmap.xml\" {}",
        port, basedir, port, basedir, port, address
    );

    Command::new("sh")
        .arg("-c")
        .arg(&cmd)
        .output()
        .expect("Failed to execute command");
}

fn enum_vnc(address: &str, port: u16, basedir: &str) {
    let cmd = format!(
        "nmap -vv --reason -sV -p {} --script=\"(vnc* or realvnc*) and not (brute or broadcast or dos or external or fuzzer)\" --script-args=unsafe=1 -oN \"{}/{}_vnc_nmap.txt\" -oX \"{}/{}_vnc_nmap.xml\" {}",
        port, basedir, port, basedir, port, address
    );

    Command::new("sh")
        .arg("-c")
        .arg(&cmd)
        .output()
        .expect("Failed to execute command");
}

fn enum_generic_tcp(address: &str, port: u16, basedir: &str) {
    let cmd = format!(
        "nmap -vv --reason -sV -sC -p {} --script-args=unsafe=1 -oN \"{}/{}_generic_tcp_nmap.txt\" -oX \"{}/{}_generic_tcp_nmap.xml\" {}",
        port, basedir, port, basedir, port, address
    );

    Command::new("sh")
        .arg("-c")
        .arg(&cmd)
        .output()
        .expect("Failed to execute command");
}

fn enum_generic_udp(address: &str, port: u16, basedir: &str) {
    let cmd = format!(
        "nmap -vv --reason -sV -sC -sU -p {} --script-args=unsafe=1 -oN \"{}/{}_generic_udp_nmap.txt\" -oX \"{}/{}_generic_udp_nmap.xml\" {}",
        port, basedir, port, basedir, port, address
    );

    Command::new("sh")
        .arg("-c")
        .arg(&cmd)
        .output()
        .expect("Failed to execute command");
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
        match service.2.as_str() {
            s if s.contains("http") => enum_http(&service.0, service.1.abs() as u16, &service.2, outdir),
            s if s.contains("smtp") => enum_smtp(&service.0, service.1.abs() as u16, outdir),
            s if s.contains("pop3") => enum_pop3(&service.0, service.1.abs() as u16, outdir),
            s if s.contains("imap") => enum_imap(&service.0, service.1.abs() as u16, outdir),
            s if s.contains("ftp") => enum_ftp(&service.0, service.1.abs() as u16, outdir),
            s if s.contains("mssql") => enum_mssql(&service.0, service.1.abs() as u16, outdir),
            s if s.contains("mysql") => enum_mysql(&service.0, service.1.abs() as u16, outdir),
            s if s.contains("oracle") => enum_oracle(&service.0, service.1.abs() as u16, outdir),
            s if s.contains("nfs") => enum_nfs(&service.0, service.1.abs() as u16, outdir),
            s if s.contains("snmp") => enum_snmp(&service.0, service.1.abs() as u16, outdir),
            s if s.contains("dns") => enum_dns(&service.0, service.1.abs() as u16, outdir),
            s if s.contains("rdp") => enum_rdp(&service.0, service.1.abs() as u16, outdir),
            s if s.contains("vnc") => enum_vnc(&service.0, service.1.abs() as u16, outdir),
            s if s.contains("smb") => enum_smb(&service.0, service.1.abs() as u16, outdir),
            _ => {
                if service.1 > 0 {
                    enum_generic_tcp(&service.0, service.1.abs() as u16, outdir);
                } else {
                    enum_generic_udp(&service.0, service.1.abs() as u16, outdir);
                }
            }
        }
    }
}
