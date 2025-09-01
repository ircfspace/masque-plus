# Masque-Plus

A simple Go launcher for `usque` that handles registration, configuration, and running a SOCKS proxy.  
Designed for **Cloudflare MASQUE protocol** usage.

Cross-platform: works on **Linux, macOS, Windows, and Android**. The binaries are automatically built via **GitHub Actions**.

![masque-plus](masque-plus.jpg)

## Features

- Automatically registers `usque` if config is missing or renewal is requested.
- Supports both **IPv4** and **IPv6** endpoints.
- Starts a local SOCKS proxy on a specified IP and port.
- Handles private key errors by re-registering automatically.
- Cross-platform support for Linux, macOS, Windows, and Android.

## Installation

Download the latest release for your system architecture from the [Releases page](https://github.com/ircfspace/masque-plus/releases/latest).

Place the `usque` binary in the same folder as this launcher (`Masque-Plus.exe` for Windows, or `Masque-Plus` for Linux/macOS).

## Usage

```bash
./Masque-Plus --endpoint <IP> [--bind <IP:Port>] [--renew] [--connect-timeout <duration>] [--scan] [-4|-6]
```

### Flags

| Flag                | Description                                                                                      | Default          |
| ------------------- | ------------------------------------------------------------------------------------------------ | ---------------- |
| `--bind`            | IP and port to bind the local SOCKS proxy. Format: `IP:Port`.                                    | `127.0.0.1:1080` |
| `--endpoint`        | **Required** unless `--scan` is used. The MASQUE server endpoint to connect. Supports IPv4/IPv6. | -                |
| `--scan`            | Auto-select an endpoint by scanning and randomly choosing a suitable IP (respecting `-4`/`-6`).  | `false`          |
| `-4`                | Force IPv4 endpoint selection (works with `--scan` or provided `--endpoint`).                    | -                |
| `-6`                | Force IPv6 endpoint selection (works with `--scan` or provided `--endpoint`).                    | -                |
| `--connect-timeout` | Connection timeout for reaching the endpoint. Accepts Go-style durations (e.g., `10s`, `1m`).    | `15s`            |
| `--renew`           | Force renewal of the configuration even if `config.json` already exists.                         | `false`          |

### Examples

```bash
# Connect to MASQUE server at 162.159.198.2:443 and start a SOCKS proxy on the default 127.0.0.1:1080
./Masque-Plus --endpoint 162.159.198.2:443

# Bind SOCKS proxy to a custom IP and port
./Masque-Plus --endpoint 162.159.198.2:443 --bind 127.0.0.1:8086

# Force configuration renewal
./Masque-Plus --endpoint 162.159.198.2:443 --renew

# Use scanner to auto-select an endpoint (random IP; honors -4/-6)
./Masque-Plus --scan

# Scanner with forced IPv4
./Masque-Plus --scan -4

# Scanner with forced IPv6
./Masque-Plus --scan -6

# Set a custom connection timeout
./Masque-Plus --endpoint 162.159.198.2:443 --connect-timeout 30s
```

## TODO

✅ Add an internal endpoint scanner to automatically search and suggest optimal MASQUE endpoints.<br />
⬜ Planning to add the `MasqueInMasque` method to get an IP from a different location.

## Notes

- Make sure the `usque` binary has execution permissions (`chmod +x usque` on Linux/macOS).
- Configurations are saved in `config.json` in the same folder.
- If a private key error occurs, the launcher will attempt to re-register `usque` automatically.

## For Developers

To build the binary locally (Windows example):

```bash
go build -o masque-plus.exe
```

## Credits

- This project uses [`usque`](https://github.com/Diniboy1123/usque) as the core MASQUE implementation.
- MASQUE protocol and Cloudflare 1.1.1.1 inspired the functionality.
- Development and code assistance were supported by ChatGPT.
