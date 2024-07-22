mod pingcheck;
mod shodan;

use futures::stream::{self, StreamExt};
use std::fs::OpenOptions;
use std::io::Write;
use std::net::SocketAddr;
use std::num::{NonZeroU64, NonZeroUsize};
use std::sync::{Arc, Mutex};
use std::time::Instant;
use structopt::StructOpt;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::net::UdpSocket;
use tokio::process::Command;
use tokio::time;

#[derive(Debug, StructOpt)]
#[structopt(
    name = "Neteye",
    usage = "cargo run -- [OPTIONS]",
    long_about = "
A multi-threaded TCP/UDP port scanner and service detection utility integrated with Shodan.     
                                                    
                                     @@@@  @   @@@@                                         
                                  @@    @@@@@@@@   @@                                      
                                @@  @@@          @@  @@ @@                                 
                               @  @@               @@  @  @@                               
                           @  @  @       %@@@.       @  @   @@                             
                         @@@ @@ @      @@     @@      @ @@    @@                           
                        @@   @ @@     @  @@@@@  @-    @  @      @                          
                      @@     @ @     @@ @   @@@  @     @ @       @@                        
                     @@      @ @     @@ @@@@@@@  @     @ @        @@                    
                     @@      @ @@     @  @@@@@  @@    @  @        @@                       
                       @@    @@ @      @@     @@      @ @@       @@                        
                        @@    @  @       *@@@@       @  @      @@                          
                          @@   @@ @@               @@  @     @@                            
                            @@   @  @@@         @@@  @@    @@                              
                              @@   @@   @@@@@@@   @@@  @@@                                 
                                 @@   @@@@@*@@@@@    @@@@  @                               
                                    @@@        :@@@@ @@  @@@@@                             
                                                      @@@@@@@@@@                           
                                                        @@@@@@@@@@                         
                                                          @@@@@@@@@@                       
                                                           @@@@@@  @                      
                                                              @@  @ @                      
                                                                @@@@+                      
                                                                                           
                                                                                           
                          @    @  @@@@  @@@@@  @@@@  @   @@ @@@@@                          
                          @@   @  @       @    @     @   @  @                              
                          @ @@ @  @@@@    @    @@@@   @@@   @@@@@                          
                          @   @@  @       @    @       @    @                              
                          @    @  @@@@    @    @@@@    @    @@@@@                          
                                                                                                                                                                                                                                  
",
    about = "A multi-threaded TCP/UDP port scanner and service detection utility.",
    global_settings = &[structopt::clap::AppSettings::UnifiedHelpMessage, structopt::clap::AppSettings::DisableVersion]
)]
struct Opts {
    /// IP address or hostname to scan
    #[structopt(short = "a", long = "address", default_value = "127.0.0.1", help = "IP address or hostname to scan")]
    address: String,

    /// Perform a ping check to the specified address
    #[structopt(short = "p", long = "ping-check", help = "Perform a ping check to the specified address")]
    ping_check: bool,

    /// Port number to start scanning from
    #[structopt(short = "s", long = "startPort", default_value = "1", help = "Port number to start scanning from")]
    start_port: u16,

    /// Port number to end scanning at
    #[structopt(short = "e", long = "endPort", default_value = "65535", help = "Port number to end scanning at")]
    end_port: u16,

    /// Enable TCP port scanning
    #[structopt(short = "T", long = "tcp", help = "Enable TCP port scanning")]
    scan_tcp: bool,

    /// Enable UDP port scanning
    #[structopt(short = "U", long = "udp", help = "Enable UDP port scanning")]
    scan_udp: bool,

    /// Print detailed output for the scan process
    #[structopt(short = "v", long = "verbose", help = "Print detailed output for the scan process")]
    verbose: bool,

    /// Inspect open ports for more details
    #[structopt(short = "i", long = "inspect", help = "Inspect open ports for more details")]
    inspect: bool,

    /// Use Shodan to scan the specified address
    #[structopt(short = "S", long = "shodan", help = "Use Shodan to scan the specified public address")]
    shodan: bool,

    /// Output file to save results
    #[structopt(short = "o", long = "output", help = "Output file to save results")]
    output: Option<String>,

    /// Number of threads to use for scanning
    #[structopt(short = "j", long = "threads", help = "Number of threads to use for scanning")]
    threads: Option<NonZeroUsize>,

    /// Timeout in milliseconds for each port check
    #[structopt(short = "t", long = "timeout", default_value = "3000", help = "Timeout in milliseconds for each port check")]
    timeout: NonZeroU64,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let now = Instant::now();
    let opts = Opts::from_args();

    let threads = match opts.threads {
        Some(threads) => threads,
        None => std::thread::available_parallelism()?,
    }
    .get();
    let timeout = opts.timeout.get();

    let file = if let Some(output_file) = &opts.output {
        Some(Arc::new(Mutex::new(OpenOptions::new().create(true).write(true).truncate(true).open(output_file)?)))
    } else {
        None
    };

    if opts.verbose {
        println!("Scanning target: {:?}", opts.address);
        println!("Scanning IP    : {:?}", opts.address);
        println!("Start-port     : {:?}", opts.start_port);
        println!("End-port       : {:?}", opts.end_port);
        println!("Threads        : {:?}", threads);
        println!("Protocol       : {:?}", if opts.scan_tcp { "TCP" } else { "UDP" });
        println!("---------------------------------------------");
        println!("Port        Status   Service           VERSION");
    }

    if opts.ping_check {
        let result = pingcheck::ping_check(&opts.address);
        match result {
            Ok(success) => {
                if success {
                    println!("Ping to {} succeeded!", opts.address);
                } else {
                    println!("Ping to {} failed!", opts.address);
                }
            },
            Err(e) => {
                eprintln!("Error: {}", e);
                std::process::exit(1);
            }
        }
    }

    if opts.shodan {
        tokio::task::block_in_place(|| {
            shodan::shodan_scan(&opts.address).unwrap();
        });
    }

    if opts.scan_tcp {
        scan_ports(&opts.address, opts.start_port, opts.end_port, timeout, threads, "tcp", file.clone(), opts.inspect).await?;
    }

    if opts.scan_udp {
        scan_ports(&opts.address, opts.start_port, opts.end_port, timeout, threads, "udp", file.clone(), opts.inspect).await?;
    }

    let elapsed = now.elapsed();
    println!("Time Elapsed: {:?}", elapsed);

    Ok(())
}

async fn scan_ports(
    address: &str,
    start_port: u16,
    end_port: u16,
    timeout: u64,
    threads: usize,
    protocol: &str,
    file: Option<Arc<Mutex<std::fs::File>>>,
    inspect: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut ports_to_scan: Vec<u16> = vec![];

    for num in start_port..=end_port {
        ports_to_scan.push(num);
    }

    let open_ports = stream::iter(ports_to_scan)
        .map(move |port| {
            let address = address.to_string();
            let protocol = protocol.to_string();
            let file = file.clone();
            let inspect = inspect;
            async move {
                let (open, service, version) = match protocol.as_str() {
                    "tcp" => scan_tcp_port(&address, port, timeout).await,
                    "udp" => scan_udp_port(&address, port, timeout).await,
                    _ => (false, String::new(), String::new()),
                };

                if open {
                    let result = format!("{:<5} /{}   open     {:<15} {}", port, protocol, service, version);
                    println!("{}", result);

                    if let Some(ref file) = file {
                        let mut file = file.lock().unwrap();
                        writeln!(file, "{}", result).expect("Failed to write to file");
                    }

                    if inspect {
                        println!("Inspecting port: {}", port);
                        if let Some(ref file) = file {
                            inspect_port(port, protocol.clone(), Some(file.clone())).await;
                        } else {
                            inspect_port(port, protocol.clone(), file.clone()).await;
                        }
                    }
                }

                (port, open)
            }
        })
        .buffer_unordered(threads);

    open_ports.for_each(|_| futures::future::ready(())).await;

    Ok(())
}

async fn scan_tcp_port(address: &str, port: u16, timeout: u64) -> (bool, String, String) {
    let addr = format!("{}:{}", address, port);
    match time::timeout(tokio::time::Duration::from_millis(timeout), TcpStream::connect(addr)).await {
        Ok(Ok(mut stream)) => {
            // Send a probe and read the response (simple banner grabbing)
            let _ = stream.write_all(b"HEAD / HTTP/1.0\r\n\r\n").await;
            let mut buffer = [0; 1024];
            match stream.read(&mut buffer).await {
                Ok(_) => {
                    let response = String::from_utf8_lossy(&buffer).to_string();
                    let (service, version) = identify_service_version(&response);
                    (true, service, version)
                }
                Err(_) => (true, "unknown".to_string(), "unknown".to_string()),
            }
        }
        _ => (false, String::new(), String::new()),
    }
}

async fn scan_udp_port(address: &str, port: u16, timeout: u64) -> (bool, String, String) {
    let addr: SocketAddr = format!("{}:{}", address, port).parse().unwrap();
    let socket = UdpSocket::bind("0.0.0.0:0").await.unwrap();
    let _ = socket.send_to(b"\n", &addr).await;
    let mut buffer = [0; 1024];
    match time::timeout(tokio::time::Duration::from_millis(timeout), socket.recv_from(&mut buffer)).await {
        Ok(Ok((_, _))) => {
            let response = String::from_utf8_lossy(&buffer).to_string();
            let (service, version) = identify_service_version(&response);
            (true, service, version)
        }
        _ => (false, String::new(), String::new()),
    }
}

fn identify_service_version(response: &str) -> (String, String) {
    if response.contains("SSH") {
        ("ssh".to_string(), extract_version(response))
    } else if response.contains("HTTP/1.1") || response.contains("HTTP/1.0") {
        ("http".to_string(), extract_version(response))
    } else if response.contains("HTTPS") || response.contains("SSL") {
        ("https".to_string(), extract_version(response))
    } else if response.contains("FTP") {
        ("ftp".to_string(), extract_version(response))
    } else if response.contains("SMTP") {
        ("smtp".to_string(), extract_version(response))
    } else if response.contains("IMAP") {
        ("imap".to_string(), extract_version(response))
    } else if response.contains("POP3") {
        ("pop3".to_string(), extract_version(response))
    } else if response.contains("Telnet") {
        ("telnet".to_string(), extract_version(response))
    } else if response.contains("DNS") {
        ("dns".to_string(), extract_version(response))
    } else {
        ("unknown".to_string(), response.to_string())
    }
}

fn extract_version(response: &str) -> String {
    let lines: Vec<&str> = response.lines().collect();
    if let Some(line) = lines.iter().find(|&&line| line.to_lowercase().contains("server:")) {
        line.to_string()
    } else {
        response.lines().next().unwrap_or("").to_string()
    }
}

async fn inspect_port(port: u16, protocol: String, file: Option<Arc<Mutex<std::fs::File>>>) {
    println!("Running inspect_port for {} on {} protocol", port, protocol);
    let output = if cfg!(target_os = "windows") {
        // On Windows, use netstat
        Command::new("cmd")
            .args(&["/C", &format!("netstat -ano | findstr :{}", port)])
            .output()
            .await
    } else {
        // On Unix-like systems, use lsof
        Command::new("lsof")
            .arg(format!("-i:{}:{}", protocol, port))
            .output()
            .await
    };

    let output = output.unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);

    println!("{}", stdout);
    if let Some(file) = file {
        let mut file = file.lock().unwrap();
        writeln!(file, "{}", stdout).expect("Failed to write to file");
    }
}
