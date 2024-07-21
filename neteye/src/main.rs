use futures::stream::{self, StreamExt};
use std::fs::OpenOptions;
use std::io::Write;
use std::num::{NonZeroU64, NonZeroUsize};
use std::sync::{Arc, Mutex};
use std::time::Instant;
use structopt::StructOpt;
use tokio::process::Command;

#[derive(Debug, StructOpt)]
#[structopt(
    name = "port-scan",
    about = "A multi-threaded TCP/UDP port scanner and service detection utility.",
    no_version
)]
struct Opts {
    /// Name for reference
    #[structopt(short = "n", long = "name", default_value = "default", help = "Reference name for the scan")]
    name: String,

    /// Address to scan
    #[structopt(short = "a", long = "address", default_value = "127.0.0.1", help = "IP address or hostname to scan")]
    address: String,

    /// Print verbose output
    #[structopt(short = "v", long = "verbose", help = "Print detailed output for the scan process")]
    verbose: bool,

    /// Number of threads to use
    #[structopt(short = "j", long = "threads", help = "Number of threads to use for scanning")]
    threads: Option<NonZeroUsize>,

    /// Port to begin scanning from
    #[structopt(
        short = "s",
        long = "startPort",
        default_value = "1",
        help = "Port number to start scanning from"
    )]
    start_port: u16,

    /// Port to end scanning at
    #[structopt(
        short = "e",
        long = "endPort",
        default_value = "65535",
        help = "Port number to end scanning at"
    )]
    end_port: u16,

    /// Number of milliseconds to wait before timing out on a port check
    #[structopt(
        short = "t",
        long = "timeout",
        default_value = "3000",
        help = "Timeout in milliseconds for each port check"
    )]
    timeout: NonZeroU64,

    /// Scan TCP ports
    #[structopt(short = "T", long = "tcp", help = "Enable TCP port scanning")]
    scan_tcp: bool,

    /// Scan UDP ports
    #[structopt(short = "U", long = "udp", help = "Enable UDP port scanning")]
    scan_udp: bool,

    /// Inspect open ports
    #[structopt(short = "i", long = "inspect", help = "Inspect open ports for more details")]
    inspect: bool,

    /// Output file to save results
    #[structopt(short = "o", long = "output", help = "Output file to save results")]
    output: Option<String>,
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
        println!("Name: {:?}", opts.name);
        println!("Address to scan: {:?}", opts.address);
        println!("Number of threads: {:?}", threads);
        println!("Timeout: {:?}ms", timeout);
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
            async move {
                let open = match protocol.as_str() {
                    "tcp" => scan_tcp_port(&address, port, timeout).await,
                    "udp" => scan_udp_port(&address, port, timeout).await,
                    _ => false,
                };

                let result = if open {
                    format!("Port {} is open ({})", port, protocol)
                } else if port == start_port || port == end_port {
                    format!("Port {} is closed ({})", port, protocol)
                } else {
                    String::new()
                };

                if !result.is_empty() {
                    println!("{}", result);
                }

                if open && inspect {
                    if let Some(ref file) = file {
                        tokio::spawn(inspect_port(port, protocol.clone(), file.clone()));
                    }
                }

                if let Some(ref file) = file {
                    let mut file = file.lock().unwrap();
                    if !result.is_empty() {
                        writeln!(file, "{}", result).expect("Failed to write to file");
                    }
                }

                (port, open, result)
            }
        })
        .buffer_unordered(threads);

    open_ports.for_each(|_| futures::future::ready(())).await;

    Ok(())
}

async fn scan_tcp_port(address: &str, port: u16, timeout: u64) -> bool {
    let addr = format!("{}:{}", address, port);
    let socket = tokio::net::TcpSocket::new_v4().unwrap();
    match tokio::time::timeout(tokio::time::Duration::from_millis(timeout), socket.connect(addr.parse().unwrap())).await {
        Ok(Ok(_)) => true,
        _ => false,
    }
}

async fn scan_udp_port(address: &str, port: u16, timeout: u64) -> bool {
    let addr = format!("{}:{}", address, port);
    let socket = tokio::net::UdpSocket::bind("0.0.0.0:0").await.unwrap();
    match tokio::time::timeout(tokio::time::Duration::from_millis(timeout), socket.send_to(&[0], &addr)).await {
        Ok(Ok(_)) => true,
        _ => false,
    }
}

async fn inspect_port(port: u16, protocol: String, file: Arc<Mutex<std::fs::File>>) {
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
    let mut file = file.lock().unwrap();
    writeln!(file, "{}", stdout).expect("Failed to write to file");
}
