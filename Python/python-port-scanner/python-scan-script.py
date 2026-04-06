import socket
import ssl
import sys
import subprocess
import argparse
import threading
import re
from concurrent.futures import ThreadPoolExecutor, as_completed

# --- Input validation ---

# Only allow valid hostnames (RFC 1123) and bare IPv4/IPv6 addresses.
# Rejects spaces, shell metacharacters (&|;$`!), and flag-looking tokens (-x).
_TARGET_RE = re.compile(
    r'^(?:'
    r'(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?'
    r'(?:\.(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?))*)' # hostname
    r'|(?:\d{1,3}\.){3}\d{1,3}'                                      # IPv4
    r'|\[?[0-9a-fA-F:]+\]?'                                          # IPv6
    r')$'
)

# Port argument: only digits, commas, hyphens, and spaces
_PORT_ARG_RE = re.compile(r'^[\d,\-\s]+$')

# ANSI escape sequences — strip from banner output to prevent terminal hijack
_ANSI_RE = re.compile(r'\x1b\[[0-9;]*[mGKHFJA-Z]|\x1b[()][AB012]')

# --- Config ---
TCP_THREADS = 300   # Kept under Windows ephemeral port limit (~16k)
UDP_THREADS = 50
SCAN_TIMEOUT = 0.5
BANNER_TIMEOUT = 2

KNOWN_SERVICES = {
    21: "FTP",    22: "SSH",        23: "Telnet",   25: "SMTP",
    53: "DNS",    80: "HTTP",       110: "POP3",    143: "IMAP",
    443: "HTTPS", 445: "SMB",       465: "SMTPS",   993: "IMAPS",
    995: "POP3S", 3306: "MySQL",    3389: "RDP",    5432: "PostgreSQL",
    6379: "Redis",8080: "HTTP-Alt", 8443: "HTTPS-Alt", 27017: "MongoDB",
}

TLS_PORTS  = {443, 8443, 465, 993, 995}
HTTP_PORTS = {80, 8080, 8000, 8008}

# Probes sent after connecting — empty means just listen for spontaneous banner
SERVICE_PROBES = {
    25:   b'EHLO probe\r\n',
    80:   b'HEAD / HTTP/1.0\r\nHost: probe\r\n\r\n',
    8080: b'HEAD / HTTP/1.0\r\nHost: probe\r\n\r\n',
    8000: b'HEAD / HTTP/1.0\r\nHost: probe\r\n\r\n',
    110:  b'',   # POP3 sends banner on connect
    143:  b'',   # IMAP sends banner on connect
    21:   b'',   # FTP sends banner on connect
    22:   b'',   # SSH sends banner on connect
}

COMMON_UDP_PORTS = [53, 67, 123, 137, 161, 500, 514, 1900, 5353]

UDP_PROBES = {
    53:  b'\xaa\xbb\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00'  # DNS query
         b'\x07version\x04bind\x00\x00\x10\x00\x03',
    161: b'\x30\x26\x02\x01\x01\x04\x06public\xa0\x19'         # SNMP GetRequest
         b'\x02\x04\x00\x00\x00\x01\x02\x01\x00\x02\x01\x00'
         b'\x30\x0b\x30\x09\x06\x05\x2b\x06\x01\x02\x01\x05\x00',
}

_print_lock = threading.Lock()
_output_file = None


def safe_print(msg=''):
    with _print_lock:
        print(f'\r{" " * 70}\r', end='')
        print(msg, flush=True)
        if _output_file:
            _output_file.write(msg + '\n')
            _output_file.flush()


def print_header(title):
    safe_print("\n" + "=" * 60)
    safe_print(f"█ {title.upper():^56} █")
    safe_print("=" * 60)


def validate_target(target):
    if not _TARGET_RE.match(target):
        raise ValueError(
            f"Invalid target '{target}'. Only hostnames and IP addresses are allowed."
        )

def strip_ansi(text):
    return _ANSI_RE.sub('', text)


# --- Host Checks ---

def resolve_target(target):
    """Resolve target to (ip, socket_family). Supports IPv4 and IPv6."""
    try:
        results = socket.getaddrinfo(target, None)
        family, _, _, _, sockaddr = results[0]
        ip = sockaddr[0]
        version = "IPv6" if family == socket.AF_INET6 else "IPv4"
        label = f" ({ip})" if ip != target else ""
        safe_print(f"[SUCCESS] DNS: {target}{label}  [{version}]")
        return ip, family
    except socket.gaierror:
        raise ValueError(f"Cannot resolve '{target}'")


def ping_check(ip):
    try:
        result = subprocess.run(
            ['ping', '-n', '1', '-w', '1000', ip],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            safe_print("[SUCCESS] Host is UP (ping)")
        else:
            safe_print("[WARN] Ping failed — host may block ICMP but could still be reachable")
    except subprocess.TimeoutExpired:
        safe_print("[WARN] Ping timed out")
    except (FileNotFoundError, Exception) as e:
        safe_print(f"[WARN] Ping skipped: {e}")


# --- TCP Scan ---

def _scan_tcp(ip, port, family):
    with socket.socket(family, socket.SOCK_STREAM) as sock:
        sock.settimeout(SCAN_TIMEOUT)
        return port if sock.connect_ex((ip, port)) == 0 else None


def port_scan(ip, ports, family):
    print_header("2. TCP PORT SCANNING")
    safe_print(f"[INFO] Scanning {len(ports)} TCP ports with {TCP_THREADS} threads...\n")

    open_ports = []
    completed = 0
    total = len(ports)
    lock = threading.Lock()

    def scan(port):
        nonlocal completed
        result = _scan_tcp(ip, port, family)
        with lock:
            completed += 1
            if completed % 5000 == 0 or completed == total:
                with _print_lock:
                    print(f"  Progress: {completed}/{total} ({completed*100//total}%)  ", end='\r', flush=True)
        return result

    with ThreadPoolExecutor(max_workers=TCP_THREADS) as executor:
        futures = [executor.submit(scan, p) for p in ports]
        for future in as_completed(futures):
            port = future.result()
            if port is not None:
                service = KNOWN_SERVICES.get(port, "unknown")
                safe_print(f"  [OPEN] {port}/tcp  ({service})")
                open_ports.append(port)

    open_ports.sort()
    safe_print()

    if open_ports:
        safe_print(f"[SUMMARY] {len(open_ports)} open TCP port(s): {', '.join(map(str, open_ports))}")
    else:
        safe_print("[SUMMARY] No open TCP ports found.")

    return open_ports


# --- UDP Scan ---

def _scan_udp(ip, port, family):
    probe = UDP_PROBES.get(port, b'\x00')
    with socket.socket(family, socket.SOCK_DGRAM) as sock:
        sock.settimeout(1)
        try:
            sock.sendto(probe, (ip, port))
            sock.recvfrom(1024)
            return port  # Got a response — definitely open
        except ConnectionResetError:
            return None  # ICMP port unreachable = closed
        except socket.timeout:
            return None  # No response = open|filtered, skip for clarity


def udp_scan(ip, ports, family):
    print_header("3. UDP SCANNING (COMMON PORTS)")
    safe_print(f"[INFO] Scanning {len(ports)} common UDP ports...\n")

    open_ports = []

    with ThreadPoolExecutor(max_workers=UDP_THREADS) as executor:
        futures = {executor.submit(_scan_udp, ip, port, family): port for port in ports}
        for future in as_completed(futures):
            port = future.result()
            if port is not None:
                service = KNOWN_SERVICES.get(port, "unknown")
                safe_print(f"  [OPEN] {port}/udp  ({service})")
                open_ports.append(port)

    open_ports.sort()
    safe_print()

    if open_ports:
        safe_print(f"[SUMMARY] {len(open_ports)} open UDP port(s): {', '.join(map(str, open_ports))}")
    else:
        safe_print("[SUMMARY] No open UDP ports found (or all filtered).")

    return open_ports


# --- Banner Grabbing ---

def _grab_banner(ip, port, family):
    probe = SERVICE_PROBES.get(port, b'HEAD / HTTP/1.0\r\nHost: probe\r\n\r\n' if port in HTTP_PORTS else b'')
    ctx = ssl.create_default_context() if port in TLS_PORTS else None
    if ctx:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

    with socket.socket(family, socket.SOCK_STREAM) as raw:
        raw.settimeout(BANNER_TIMEOUT)
        try:
            raw.connect((ip, port))
            sock = ctx.wrap_socket(raw, server_hostname=ip) if ctx else raw
            if probe:
                sock.send(probe)
            data = sock.recv(1024)
            return data.decode('utf-8', errors='ignore').strip() if data else None
        except (socket.timeout, ConnectionRefusedError, ssl.SSLError, socket.error):
            return None


def service_scan(ip, open_ports, family):
    print_header("4. BANNER GRABBING")

    if not open_ports:
        safe_print("[SKIP] No open ports to scan.")
        return

    results = {}

    with ThreadPoolExecutor(max_workers=min(len(open_ports), 50)) as executor:
        futures = {executor.submit(_grab_banner, ip, port, family): port for port in open_ports}
        for future in as_completed(futures):
            port = futures[future]
            results[port] = future.result()

    for port in open_ports:
        service = KNOWN_SERVICES.get(port, "unknown")
        banner = results.get(port)
        safe_print(f"\n  Port {port}/tcp ({service})")
        if banner:
            safe_print(f"  {'─' * 41}")
            for line in banner.splitlines()[:10]:
                safe_print(f"  {strip_ansi(line)}")
            safe_print(f"  {'─' * 41}")
        else:
            safe_print("  [WARN] No banner received.")


# --- Helpers ---

def parse_ports(port_arg):
    if not _PORT_ARG_RE.match(port_arg):
        raise ValueError(
            f"Invalid port argument '{port_arg}'. Only digits, commas, and hyphens are allowed."
        )
    ports = set()
    for part in port_arg.split(','):
        part = part.strip()
        if '-' in part:
            start, end = part.split('-', 1)
            ports.update(range(int(start), int(end) + 1))
        else:
            ports.add(int(part))

    invalid = [p for p in ports if not (1 <= p <= 65535)]
    if invalid:
        raise ValueError(f"Invalid port(s): {invalid}. Ports must be 1–65535.")

    return sorted(ports)


# --- Main ---

def main():
    parser = argparse.ArgumentParser(description="nmap-lite: fast TCP/UDP port scanner")
    parser.add_argument('target', nargs='?', help='Target IP or domain')
    parser.add_argument('-p', '--ports', default='1-65535',
                        help='TCP ports: range (1-1024), list (22,80,443), or mix. Default: 1-65535')
    parser.add_argument('--no-udp', action='store_true', help='Skip UDP scan')
    parser.add_argument('--no-banners', action='store_true', help='Skip banner grabbing')
    parser.add_argument('-o', '--output', metavar='FILE', help='Save output to a file')
    args = parser.parse_args()

    global _output_file
    if args.output:
        try:
            _output_file = open(args.output, 'w', encoding='utf-8')
            print(f"[INFO] Saving output to '{args.output}'")
        except OSError as e:
            print(f"[ERROR] Cannot open output file: {e}")
            sys.exit(1)

    target = args.target or input("Enter target (IP or domain): ").strip()
    if not target:
        print("[ERROR] No target provided.")
        sys.exit(1)

    try:
        validate_target(target)
    except ValueError as e:
        print(f"[ERROR] {e}")
        sys.exit(1)

    try:
        ports = parse_ports(args.ports)
    except ValueError as e:
        print(f"[ERROR] {e}")
        sys.exit(1)

    # Stage 1: Host checks
    print_header("1. HOST CHECKS")
    try:
        ip, family = resolve_target(target)
    except ValueError as e:
        print(f"[FATAL] {e}")
        sys.exit(1)
    ping_check(ip)

    # Stage 2: TCP scan
    open_tcp = port_scan(ip, ports, family)

    # Stage 3: UDP scan
    if not args.no_udp:
        udp_scan(ip, COMMON_UDP_PORTS, family)

    # Stage 4: Banner grabbing
    if not args.no_banners:
        service_scan(ip, open_tcp, family)

    print_header("SCAN COMPLETE")
    safe_print("Done.\n")

    if _output_file:
        _output_file.close()
        print(f"[INFO] Output saved to '{args.output}'")


if __name__ == "__main__":
    main()
