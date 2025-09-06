# Masque-Plus

A simple Go launcher for `usque` that handles registration, configuration, and running a SOCKS proxy.  
Designed for **Cloudflare MASQUE protocol** usage.

Cross-platform: works on **Linux, macOS, Windows, and Android**. The binaries are automatically built via **GitHub Actions**.

![masque-plus](masque-plus.jpg)

## Features

- Automatically registers `usque` if config is missing or renewal is requested.
- Supports both **IPv4** and **IPv6** endpoints, including domain resolution.
- Starts a local SOCKS proxy on a specified IP and port.
- Handles private key errors by re-registering automatically.
- Endpoint scanner to auto-select a working IP from CIDR ranges.
- Customizable MASQUE parameters like SNI, port, DNS servers, MTU, keepalive, and proxy authentication.
- Warp status check during scanning to ensure "warp=on".
- Cross-platform support for Linux, macOS, Windows, and Android.

## Installation

Download the latest release for your system architecture from the [Releases page](https://github.com/ircfspace/masque-plus/releases/latest).

Place the `usque` binary in the same folder as this launcher (`Masque-Plus.exe` for Windows, or `Masque-Plus` for Linux/macOS).

## Usage

```bash
./Masque-Plus --endpoint <host:port> [--bind <IP:Port>] [--renew] [--scan] [-4|-6] [other flags]
```

### Core Flags

| Flag                       | Description                                                                                                                                                             | Default                                                    |
| -------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------- |
| `--bind`                   | IP and port to bind the local SOCKS proxy. Format: `IP:Port`.                                                                                                           | 127.0.0.1:1080                                             |
| `--endpoint`               | Required unless `--scan` is used. The MASQUE server endpoint to connect. Supports IPv4/IPv6/domains (e.g., 162.159.198.2:443, [2606:4700:103::2]:443, example.com:443). | -                                                          |
| `--scan`                   | Auto-select an endpoint by scanning and randomly choosing a suitable IP (respecting `-4`/`-6`).                                                                         | false                                                      |
| `-4`                       | Force IPv4 endpoint selection (works with `--scan` or provided `--endpoint`).                                                                                           | -                                                          |
| `-6`                       | Force IPv6 endpoint selection (works with `--scan` or provided `--endpoint`).                                                                                           | -                                                          |
| `--connect-timeout`        | Overall timeout for the final connect/process to be up. Accepts Go durations (e.g., 10s, 1m).                                                                           | 15m                                                        |
| `--renew`                  | Force renewal of the configuration even if `config.json` already exists.                                                                                                | false                                                      |
| `--range4`                 | Comma-separated IPv4 CIDRs to scan (with `--scan`).                                                                                                                     | 162.159.192.0/24,<br>162.159.197.0/24,<br>162.159.198.0/24 |
| `--range6`                 | Comma-separated IPv6 CIDRs to scan (with `--scan`).                                                                                                                     | 2606:4700:103::/64                                         |
| `--ping`                   | Ping each candidate before connect (QUIC probe).                                                                                                                        | true                                                       |
| `--scan-timeout`           | Per-endpoint scan timeout (dial+handshake).                                                                                                                             | 5s                                                         |
| `--scan-max`               | Maximum number of endpoints to try during scan.                                                                                                                         | 30                                                         |
| `--scan-verbose-child`     | Print MASQUE child process logs during scan.                                                                                                                            | false                                                      |
| `--scan-tunnel-fail-limit` | Number of 'Failed to connect tunnel' occurrences before skipping an endpoint.                                                                                           | 2                                                          |
| `--scan-ordered`           | Scan candidates in CIDR order (disable shuffling).                                                                                                                      | false                                                      |
| `--version`                | Show the current version of the program.                                                                                                                                |                                                            |

### Usque-Specific Flags (Passed Directly to `usque socks`)

| Flag                    | Description                                                                                      | Default                                |
| ----------------------- | ------------------------------------------------------------------------------------------------ | -------------------------------------- |
| `--connect-port`        | Used port for MASQUE connection (overrides endpoint port if specified).                          | `443`                                  |
| `--dns`                 | Comma-separated DNS servers to use (e.g., `8.8.8.8,1.1.1.1`). Validates IPs and ignores invalid. | -                                      |
| `--dns-timeout`         | Timeout for DNS queries.                                                                         | `2s`                                   |
| `--initial-packet-size` | Initial packet size for MASQUE connection.                                                       | `1242`                                 |
| `--keepalive-period`    | Keepalive period for MASQUE connection.                                                          | `30s`                                  |
| `--local-dns`           | Don't use the tunnel for DNS queries.                                                            | `false`                                |
| `--mtu`                 | MTU for MASQUE connection.                                                                       | `1280`                                 |
| `--no-tunnel-ipv4`      | Disable IPv4 inside the MASQUE tunnel.                                                           | `false`                                |
| `--no-tunnel-ipv6`      | Disable IPv6 inside the MASQUE tunnel.                                                           | `false`                                |
| `--password`            | Password for proxy authentication (requires `--username`).                                       | -                                      |
| `--username`            | Username for proxy authentication (requires `--password`).                                       | -                                      |
| `--reconnect-delay`     | Delay between reconnect attempts.                                                                | `1s`                                   |
| `--sni`                 | SNI address to use for MASQUE connection (defaults to domain if endpoint is a domain).           | `consumer-masque.cloudflareclient.com` |
| `--ipv6`                | Use IPv6 for MASQUE connection (overrides to match endpoint if mismatch).                        | `false`                                |

### Examples

```bash
# Connect to a specific IP endpoint and start SOCKS proxy
./Masque-Plus --endpoint 162.159.198.2:443

# Use a domain endpoint with custom SNI and port
./Masque-Plus --endpoint example.com:8443 --sni example.com --connect-port 8443 --bind 127.0.0.1:8086

# Force renewal and use custom DNS servers
./Masque-Plus --endpoint 162.159.198.2:443 --renew --dns 8.8.8.8,1.1.1.1

# Scan for a working IPv4 endpoint with verbose logs
./Masque-Plus --scan -4 --scan-verbose-child --sni consumer-masque.cloudflareclient.com

# Enable proxy authentication and disable IPv4 in tunnel
./Masque-Plus --endpoint [2606:4700:103::2]:443 --username test --password secret --no-tunnel-ipv4

# Custom scan ranges and max attempts
./Masque-Plus --scan --range4 162.159.192.0/24,162.159.197.0/24 --scan-max 50
```

## TODO

✅ Add an internal endpoint scanner to automatically search and suggest optimal MASQUE endpoints.<br />
⬜ Planning to add the `MasqueInMasque` method to get an IP from a different location.

## Notes

- Make sure the `usque` binary has execution permissions (`chmod +x usque` on Linux/macOS).
- Configurations are saved in `config.json` in the same folder.
- If a private key error occurs, the launcher will attempt to re-register `usque` automatically.
- During scanning, endpoints are shuffled for randomness (unless `--scan-ordered`), and a Warp check is performed to ensure "warp=on".
- Invalid DNS servers are logged and ignored.
- If only one of `--username` or `--password` is provided, authentication is skipped with a warning.

## For Developers

To build the binary locally (Windows example):

```bash
go build -o masque-plus.exe
```

## Credits

- This project uses [`usque`](https://github.com/Diniboy1123/usque) as the core MASQUE implementation.
- MASQUE protocol and Cloudflare 1.1.1.1 inspired the functionality.
- Development and code assistance were supported by ChatGPT.
