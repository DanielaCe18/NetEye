
# Neteye

Neteye is a multi-threaded TCP/UDP port scanner and service detection utility integrated with Shodan, written entirely in Rust. This powerful and flexible network reconnaissance tool is designed for network security professionals and penetration testers.

<div align="center">
  <img src="https://github.com/user-attachments/assets/5715e821-4cf2-42ae-8e4e-4ac984b7a9c5" alt="Description" width="100"/>
</div>

## Features

- ✔️ Works on both Windows and Unix systems
- ✔️ Supports port scanning over TCP and UDP protocols
- ✔️ Detailed banner-grabbing feature
- ✔️ Ping check for identifying reachable targets
- ✔️ Multi-threading support for fast scanning operations
- ✔️ Option to save scan results to a file
- ✔️ Provides detailed version information
- ✔️ Shodan integration for enhanced scanning capabilities

## Installation

Neteye requires Rust and Cargo to be installed.

1. Clone the repository:
    ```sh
    git clone https://github.com/DanielaCe18/NetEye.git
    ```

2. Navigate to the Neteye folder:
    ```sh
    cd neteye
    ```

3. Build the Cargo project:
    ```sh
    cargo build
    ```

## Configuration

Update the `shodan.rs` file with your Shodan API key:
```rust
const SHODAN_API_KEY: &str = "YOUR_SHODAN_API_KEY";
```

## Usage

To run Neteye, use the following command structure:
```sh
cargo run -- [OPTIONS]
```

### Options

- `-h, --help`                      Prints help information
- `-a, --address <address>`         IP address or hostname to scan (default: 127.0.0.1)
- `-T, --tcp`                       Enable TCP port scanning
- `-U, --udp`                       Enable UDP port scanning
- `-s, --startPort <start-port>`    Port number to start scanning from (default: 1)
- `-e, --endPort <end-port>`        Port number to end scanning at (default: 65535)
- `-i, --inspect`                   Inspect open ports for more details
- `-o, --output <output>`           Output file to save results
- `-p, --ping-check`                Perform a ping check to the specified address
- `-S, --shodan`                    Use Shodan to scan the specified public address
- `-j, --threads <threads>`         Number of threads to use for scanning
- `-t, --timeout <timeout>`         Timeout in milliseconds for each port check (default: 3000)
- `-v, --verbose`                   Print detailed output for the scan process

### Example Usage

1. Show help message:
    ```sh
    cargo run -- --help
    ```

2. Perform ping check and scan with TCP protocol ports with verbose option:
    ```sh
    cargo run -- -a 192.168.1.70 -T -p -v
    ```

3. Scan IP address 192.168.1.1 for open ports from 1-443 with TCP protocol and verbose option for details:
    ```sh
    cargo run -- -a 192.168.1.1 -T -s 1 -e 443 -v
    ```

4. Scan open ports with UDP protocol from ports 1-80:
    ```sh
    cargo run -- -a 192.168.1.1 -U -s 1 -e 80 -v
    ```

5. Inspect each port in detail for TCP protocols:
    ```sh
    cargo run -- -a 192.168.1.70 -T -i
    ```

6. Scan and save the result in a file:
    ```sh
    cargo run -- -a 192.168.1.39 -T -v -o scan_result.txt
    ```

7. Scan a public address with Shodan to find all open ports:
    ```sh
    cargo run -- -S -a 8.8.8.8
    ```

8. Define thread and timeout for the scan:
    ```sh
    cargo run -- -a 192.168.1.1 -U -s 1 -e 80 -v -j 10 -t 5000
    ```

### Output Example

```sh
cargo run -- -a 192.168.1.39 -T -s 1 -e 443 -v -o scan_result.txt 
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.25s
     Running `target\debug\neteye.exe -a 192.168.1.39 -T -s 1 -e 443 -v -o scan_result.txt`
Scanning target: "192.168.1.39"
Scanning IP    : "192.168.1.39"
Start-port     : 1
End-port       : 443
Threads        : 4
Protocol       : "TCP"
---------------------------------------------
Port        Status   Service           VERSION
22    /tcp   open     ssh             SSH-2.0-OpenSSH_8.4p1 Debian-5
80    /tcp   open     http            Server: Apache/2.4.48 (Debian)
```

<img width="602" alt="image" src="https://github.com/user-attachments/assets/d4c953c3-9dc7-468a-a885-3c098b43c59d">


## Licensing

Neteye is released under the MIT license by DanielaCe18. Source code is available on GitHub.

## Disclaimer ⚠️

Usage of Neteye for attacking a target without prior consent of its owner is illegal. It is the end user's responsibility to obey all applicable local laws.
