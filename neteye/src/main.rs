use futures::stream::{self, StreamExt};
use std::num::{NonZeroU64, NonZeroUsize};
use std::time::Instant;
use structopt::StructOpt;
use tokio::net::{TcpSocket, UdpSocket};
use tokio::process::Command;
use tokio::time;

#[derive(Debug, StructOpt)]
#[structopt(
    name = "port-scan",
    about = "A multi-threaded TCP/UDP port scanner and service detection utility."
)]
struct Opts {
    /// Name for reference
    #[structopt(short = "n", long = "name", default_value = "default")]
    name: String,

    /// Address to scan
    #[structopt(short = "a", long = "address", default_value = "127.0.0.1")]
    address: String,

    /// Print verbose output
    #[structopt(short = "v", long = "verbose", help = "Print verbose output")]
    verbose: bool,

    /// Number of threads to use
    #[structopt(short = "j", long = "threads", help = "Number of threads to use")]
    threads: Option<NonZeroUsize>,

    /// Port to begin scanning from
    #[structopt(
        short = "s",
        long = "startPort",
        help = "Port to start scanning from",
        default_value = "1"
    )]
    start_port: u16,

    /// Port to end scanning at
    #[structopt(
        short = "e",
        long = "endPort",
        help = "Port to end scanning at",
        default_value = "65535"
    )]
    end_port: u16,

    /// Number of seconds to wait before timing out on a port check (ms)
    #[structopt(
        short = "t",
        long = "timeout",
        help = "Number of seconds to wait before timing out of a port check (ms).",
        default_value = "3000"
    )]
    timeout: NonZeroU64,

    /// Scan TCP ports
    #[structopt(short = "T", long = "tcp", help = "Scan TCP ports")]
    scan_tcp: bool,

    /// Scan UDP ports
    #[structopt(short = "U", long = "udp", help = "Scan UDP ports")]
    scan_udp: bool,
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

    if opts.verbose {
        println!("Name: {:?}", opts.name);
        println!("Address to scan: {:?}", opts.address);
        println!("Number of threads: {:?}", threads);
        println!("Timeout: {:?}ms", timeout);
    }

    if opts.scan_tcp {
        scan_ports(opts.address.clone(), opts.start_port, opts.end_port, timeout, threads, "tcp").await?;
    }

    if opts.scan_udp {
        scan_ports(opts.address, opts.start_port, opts.end_port, timeout, threads, "udp").await?;
    }

    let elapsed = now.elapsed();
    println!("Time Elapsed: {:?}", elapsed);
    Ok(())
}

async fn scan_ports(
    address: String,
    start_port: u16,
    end_port: u16,
    timeout: u64,
    threads: usize,
    protocol: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut ports_to_scan: Vec<u16> = vec![];

    for num in start_port..=end_port {
        ports_to_scan.push(num);
    }

    let open_ports = stream::iter(ports_to_scan)
        .map(move |port| {
            let address = address.clone();
            async move {
                let open = match protocol {
                    "tcp" => scan_tcp_port(&address, port, timeout).await,
                    "udp" => scan_udp_port(&address, port, timeout).await,
                    _ => false,
                };

                if open {
                    println!("Port {} is open ({})", port, protocol);
                } else if port == start_port || port == end_port {
                    println!("Port {} is closed ({})", port, protocol);
                }

                (port, open)
            }
        })
        .buffer_unordered(threads);

    let results: Vec<(u16, bool)> = open_ports.collect().await;
    for (port, open) in results {
        if open {
            inspect_port(port, protocol).await;
        }
    }

    Ok(())
}

async fn scan_tcp_port(address: &str, port: u16, timeout: u64) -> bool {
    let addr = format!("{}:{}", address, port);
    let socket = TcpSocket::new_v4().unwrap();
    match time::timeout(time::Duration::from_millis(timeout), socket.connect(addr.parse().unwrap())).await {
        Ok(Ok(_)) => true,
        _ => false,
    }
}

async fn scan_udp_port(address: &str, port: u16, timeout: u64) -> bool {
    let addr = format!("{}:{}", address, port);
    let socket = UdpSocket::bind("0.0.0.0:0").await.unwrap();
    match time::timeout(time::Duration::from_millis(timeout), socket.send_to(&[0], &addr)).await {
        Ok(Ok(_)) => true,
        _ => false,
    }
}

async fn inspect_port(port: u16, protocol: &str) {
    let output = Command::new("lsof")
        .arg(format!("-i:{}:{}", protocol, port))
        .kill_on_drop(true)
        .output()
        .await;

    let stdout = String::from_utf8_lossy(match &output {
        Ok(output) => &output.stdout,
        Err(_) => &[],
    });
    println!("{}", stdout);
}
