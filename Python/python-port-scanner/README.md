# python-scan-script

A fast, lightweight TCP/UDP port scanner for Windows built entirely in Python — no third-party dependencies required.

> **Legal Disclaimer:** This tool is intended for authorized security testing, network administration, and educational purposes only. Only scan systems you own or have explicit written permission to test. Unauthorized port scanning may be illegal in your jurisdiction. The author assumes no liability for misuse.

---

## Features

- **Fast** — 300 concurrent threads; scans all 65535 TCP ports in 1–3 minutes
- **TCP + UDP** — full TCP connect scan plus probes for 9 common UDP services
- **Banner grabbing** — retrieves service banners with TLS support for HTTPS, SMTPS, IMAPS, and more
- **Smart probes** — sends service-specific payloads (HTTP HEAD, SMTP EHLO, etc.) instead of generic data
- **IPv4 + IPv6** — automatically detects and handles both address families
- **Injection-safe** — validates all user input; strips ANSI escape sequences from banner output
- **Save output** — tee results to a file while still printing to the terminal
- **No dependencies** — standard library only (`socket`, `ssl`, `subprocess`, `concurrent.futures`)

---

## Requirements

- Python 3.8+
- Windows (uses `ping -n` syntax)
- Run as **Administrator** for best UDP results

---

## Usage

```
python python-scan-script.py [target] [options]
```

If no target is passed, the script will prompt you for one.

### Arguments

| Argument | Description |
|---|---|
| `target` | IP address or domain (e.g. `192.168.1.1` or `scanme.nmap.org`) |
| `-p`, `--ports` | TCP ports to scan — range, list, or mix. Default: `1-65535` |
| `-o`, `--output` | Save output to a file |
| `--no-udp` | Skip UDP scan |
| `--no-banners` | Skip banner grabbing |

---

## Examples

```bash
# Basic scan (all ports)
python python-scan-script.py scanme.nmap.org

# Scan a port range
python python-scan-script.py 192.168.1.1 -p 1-1024

# Scan specific ports
python python-scan-script.py 192.168.1.1 -p 22,80,443,3389

# Mix range and specific ports
python python-scan-script.py 192.168.1.1 -p 1-1024,3306,8080-8090

# Save results to a file
python python-scan-script.py 192.168.1.1 -o results.txt

# Fastest mode — TCP only, no banners
python python-scan-script.py 192.168.1.1 --no-udp --no-banners

# Full scan saved to file
python python-scan-script.py 192.168.1.1 -p 1-65535 -o scan.txt
```

---

## Example Output

```
============================================================
█                      1. HOST CHECKS                      █
============================================================
[SUCCESS] DNS: scanme.nmap.org (45.33.32.156)  [IPv4]
[SUCCESS] Host is UP (ping)

============================================================
█                   2. TCP PORT SCANNING                   █
============================================================
[INFO] Scanning 65535 TCP ports with 300 threads...

  [OPEN] 22/tcp   (SSH)
  [OPEN] 80/tcp   (HTTP)
  [OPEN] 443/tcp  (HTTPS)

[SUMMARY] 3 open TCP port(s): 22, 80, 443

============================================================
█              3. UDP SCANNING (COMMON PORTS)              █
============================================================
[INFO] Scanning 9 common UDP ports...

[SUMMARY] No open UDP ports found (or all filtered).

============================================================
█                    4. BANNER GRABBING                    █
============================================================

  Port 22/tcp (SSH)
  ─────────────────────────────────────────
  SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.13
  ─────────────────────────────────────────

  Port 80/tcp (HTTP)
  ─────────────────────────────────────────
  HTTP/1.1 200 OK
  Server: Apache/2.4.7 (Ubuntu)
  ─────────────────────────────────────────
```

---

## How It Works

| Stage | What it does |
|---|---|
| **1. Host Checks** | DNS resolution (IPv4/IPv6) + ping |
| **2. TCP Scan** | Concurrent TCP connect scan across all specified ports |
| **3. UDP Scan** | Sends probes to 9 common UDP ports; detects open/closed via response or ICMP |
| **4. Banner Grab** | Connects to each open port, sends a service-specific probe, reads the response |

### UDP ports scanned

| Port | Service |
|---|---|
| 53 | DNS |
| 67 | DHCP |
| 123 | NTP |
| 137 | NetBIOS |
| 161 | SNMP |
| 500 | IKE (VPN) |
| 514 | Syslog |
| 1900 | UPnP |
| 5353 | mDNS |

---

## License

MIT — see [LICENSE](LICENSE) for details.
