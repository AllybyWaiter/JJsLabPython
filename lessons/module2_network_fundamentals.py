"""
Module 2: Network Fundamentals
Deep dive into TCP/UDP, port scanning, banner grabbing, and network mapping
from a security perspective. Builds practical tools alongside the theory.
"""

from utils.display import (
    section_header, sub_header, lesson_block, code_block,
    scenario_block, why_it_matters, info, success, warning, press_enter,
    show_menu, disclaimer, hint_text, ask_yes_no, C, G, Y, R, RESET, BRIGHT, DIM
)
from utils.progress import mark_lesson_complete, mark_challenge_complete
from utils.quiz import run_quiz


# ──────────────────────────────────────────────────────────────────────
#  Module metadata
# ──────────────────────────────────────────────────────────────────────
MODULE_KEY = "module2"


# ──────────────────────────────────────────────────────────────────────
#  Lesson 1 — TCP/UDP Deep Dive
# ──────────────────────────────────────────────────────────────────────
def lesson_tcp_udp(progress):
    section_header("Lesson 1: TCP/UDP Deep Dive")

    lesson_block(
        "Every network interaction you will ever analyze, attack, or defend involves "
        "either TCP or UDP at the transport layer. These two protocols ride on top "
        "of IP (Internet Protocol) and serve fundamentally different purposes. "
        "Understanding their mechanics at a deep level is not optional for security "
        "professionals — it is the foundation everything else is built on."
    )

    lesson_block(
        "TCP (Transmission Control Protocol) is a connection-oriented protocol. "
        "Before any data flows, TCP establishes a connection using a three-way "
        "handshake. The client sends a SYN (synchronize) packet to the server. "
        "The server responds with a SYN-ACK (synchronize-acknowledge). The client "
        "completes the handshake with an ACK (acknowledge). Only then can data "
        "flow. This handshake ensures both sides are ready and agree on initial "
        "sequence numbers used to track data ordering."
    )

    sub_header("The TCP Three-Way Handshake")
    code_block("""\
# TCP Three-Way Handshake — what happens when you connect

#   Client                          Server
#     |                                |
#     |  ──── SYN (seq=100) ────>      |   Step 1: Client initiates
#     |                                |
#     |  <── SYN-ACK (seq=300,         |   Step 2: Server acknowledges
#     |       ack=101) ──              |           and sends its own SYN
#     |                                |
#     |  ──── ACK (seq=101,            |   Step 3: Client acknowledges
#     |        ack=301) ────>          |           Connection established!
#     |                                |
#     |  ════ DATA FLOWS ════          |   Now both sides can send data
#     |                                |

# In Python, all of this happens inside sock.connect():
import socket
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect(("example.com", 80))   # SYN -> SYN-ACK -> ACK happens here
sock.sendall(b"Hello")               # Data flows on the established connection
sock.close()                          # FIN -> ACK -> FIN -> ACK tears it down""", language="text")

    lesson_block(
        "After the handshake, TCP provides several guarantees: all data arrives "
        "(it retransmits lost packets), data arrives in order (sequence numbers "
        "track position), data is not corrupted (checksums verify integrity), and "
        "flow control prevents the sender from overwhelming the receiver (the "
        "receive window). TCP also provides congestion control to avoid overwhelming "
        "the network itself."
    )

    lesson_block(
        "TCP connections are terminated with a four-way process. Either side can "
        "initiate by sending a FIN (finish) packet. The other side acknowledges "
        "with an ACK, then sends its own FIN, which gets acknowledged. This "
        "ensures both sides have finished transmitting. If something goes wrong, "
        "a RST (reset) packet abruptly terminates the connection."
    )

    sub_header("TCP Connection States")
    code_block("""\
# Key TCP states you will see during security work:
#
# LISTEN        — Server is waiting for incoming connections
# SYN_SENT      — Client has sent SYN, waiting for SYN-ACK
# SYN_RECEIVED  — Server received SYN, sent SYN-ACK, waiting for ACK
# ESTABLISHED   — Connection is active, data can flow
# FIN_WAIT_1    — Sent FIN, waiting for ACK
# FIN_WAIT_2    — Received ACK for our FIN, waiting for peer's FIN
# TIME_WAIT     — Waiting to ensure peer received final ACK (lasts 2*MSL)
# CLOSE_WAIT    — Received FIN from peer, waiting for application to close
# CLOSED        — Connection is fully terminated

# View TCP connection states on your system:
# Linux:   ss -tan
# macOS:   netstat -an -p tcp
# Windows: netstat -an -p tcp""", language="text")

    lesson_block(
        "UDP (User Datagram Protocol) is the opposite of TCP in many ways. It is "
        "connectionless — there is no handshake. Each packet (called a datagram) is "
        "independent and self-contained. UDP provides no guarantees: packets can "
        "arrive out of order, be duplicated, or be lost entirely. There is no flow "
        "control or congestion control. This sounds terrible, but the trade-off is "
        "speed and simplicity."
    )

    sub_header("TCP vs UDP Comparison")
    code_block("""\
# ┌─────────────────────┬──────────────────┬──────────────────┐
# │ Feature             │ TCP              │ UDP              │
# ├─────────────────────┼──────────────────┼──────────────────┤
# │ Connection          │ Connection-based │ Connectionless   │
# │ Reliability         │ Guaranteed       │ Best-effort      │
# │ Ordering            │ Ordered          │ No ordering      │
# │ Speed               │ Slower (overhead)│ Faster (minimal) │
# │ Header size         │ 20-60 bytes      │ 8 bytes          │
# │ Use cases           │ HTTP, SSH, FTP   │ DNS, DHCP, VoIP  │
# │ Scan detection      │ Easier (SYN/ACK) │ Harder (no resp) │
# │ Flooding attacks    │ SYN flood        │ UDP flood        │
# └─────────────────────┴──────────────────┴──────────────────┘""", language="text")

    sub_header("Port Numbers and Services")
    lesson_block(
        "Port numbers range from 0 to 65535 and are divided into three ranges. "
        "Well-known ports (0-1023) are assigned to standard services — HTTP is 80, "
        "HTTPS is 443, SSH is 22, DNS is 53. These typically require root/admin "
        "privileges to bind to. Registered ports (1024-49151) are used by "
        "applications that register with IANA. Dynamic/ephemeral ports (49152-65535) "
        "are used by client programs for outbound connections."
    )

    code_block("""\
# Common ports every security professional must know:
#
# Port  Protocol  Service         Security Notes
# ─────────────────────────────────────────────────────
#  20   TCP       FTP-Data        Cleartext file transfer
#  21   TCP       FTP-Control     Cleartext credentials
#  22   TCP       SSH             Encrypted remote access
#  23   TCP       Telnet          Cleartext (avoid!)
#  25   TCP       SMTP            Email delivery
#  53   TCP/UDP   DNS             Name resolution
#  80   TCP       HTTP            Unencrypted web
# 110   TCP       POP3            Cleartext email retrieval
# 135   TCP       MSRPC           Windows RPC (target for attacks)
# 139   TCP       NetBIOS         Windows file sharing
# 143   TCP       IMAP            Email retrieval
# 443   TCP       HTTPS           Encrypted web
# 445   TCP       SMB             Windows file sharing
# 993   TCP       IMAPS           Encrypted IMAP
#1433   TCP       MSSQL           Microsoft SQL Server
#3306   TCP       MySQL           MySQL database
#3389   TCP       RDP             Remote Desktop
#5432   TCP       PostgreSQL      PostgreSQL database
#5900   TCP       VNC             Remote desktop (often unencrypted)
#8080   TCP       HTTP-Alt        Alternative web server port
#8443   TCP       HTTPS-Alt       Alternative HTTPS port""", language="text")

    sub_header("What Happens During a Connection — Packet by Packet")
    code_block("""\
import socket

# Let's trace what happens at the network level when we do this:
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# 1. socket() — OS allocates resources, no network traffic yet

sock.connect(("93.184.216.34", 80))
# 2. connect() triggers:
#    - DNS lookup (if hostname given): UDP query to DNS server
#    - SYN packet sent to 93.184.216.34:80
#    - SYN-ACK received from server
#    - ACK sent to server
#    - connect() returns — connection is ESTABLISHED

sock.sendall(b"GET / HTTP/1.1\\r\\nHost: example.com\\r\\n\\r\\n")
# 3. sendall() triggers:
#    - Data packed into TCP segment(s)
#    - Each segment gets sequence number
#    - Segments sent, ACKs received for each
#    - OS handles retransmission if ACK not received

response = sock.recv(4096)
# 4. recv() triggers:
#    - Waits for data in the receive buffer
#    - OS reassembles segments in order
#    - Returns up to 4096 bytes of application data

sock.close()
# 5. close() triggers:
#    - FIN sent to server
#    - ACK received from server
#    - FIN received from server
#    - ACK sent to server
#    - Socket enters TIME_WAIT state""")

    why_it_matters(
        "Understanding TCP/UDP at this level is critical for security work. SYN scans "
        "exploit the handshake to detect open ports without completing connections. "
        "SYN flood attacks exhaust server resources by sending millions of SYN packets "
        "without completing handshakes. Firewalls and IDS systems make decisions based "
        "on TCP flags and connection states. Network forensics involves reading packet "
        "captures and understanding exactly what happened at each step. Without this "
        "knowledge, you are just running tools without understanding their output."
    )

    scenario_block("SYN Flood Attack Investigation", (
        "Your monitoring system alerts on high CPU usage on the web server. Running "
        "'netstat -an | grep SYN_RECEIVED' reveals 50,000 half-open connections — "
        "all in the SYN_RECEIVED state. This is a classic SYN flood attack. The "
        "attacker is sending SYN packets with spoofed source IPs, so the server "
        "sends SYN-ACK replies that never get answered. Each half-open connection "
        "consumes server resources until the backlog queue is full and legitimate "
        "users cannot connect. Your knowledge of the TCP handshake lets you "
        "immediately identify the attack type and apply SYN cookies as a mitigation."
    ))

    # ── Practice Challenge ──
    sub_header("Practice Challenge")
    info("Write a Python script that demonstrates the difference between TCP and UDP:")
    info("  1. Create a TCP connection to a known service and time the handshake")
    info("  2. Send a UDP packet to a DNS server (port 53) and time the response")
    info("  3. Compare and print the results\n")

    if ask_yes_no("Would you like a hint?"):
        hint_text("Use time.time() before and after connect() to measure TCP handshake time.")
        hint_text("For DNS over UDP, send a raw DNS query: b'\\xaa\\xaa\\x01\\x00...' to port 53.")

    press_enter()

    if ask_yes_no("Show the full solution?"):
        code_block("""\
import socket
import time

def measure_tcp_handshake(host, port):
    \"\"\"Measure TCP three-way handshake time.\"\"\"
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5)
    start = time.time()
    try:
        sock.connect((host, port))
        elapsed = time.time() - start
        sock.close()
        return elapsed
    except (socket.timeout, ConnectionRefusedError, OSError) as e:
        return None

def measure_udp_dns(dns_server="8.8.8.8"):
    \"\"\"Send a DNS query over UDP and measure response time.\"\"\"
    # Minimal DNS query for example.com (type A)
    query = (
        b"\\xaa\\xaa"  # Transaction ID
        b"\\x01\\x00"  # Flags: standard query
        b"\\x00\\x01"  # Questions: 1
        b"\\x00\\x00"  # Answer RRs: 0
        b"\\x00\\x00"  # Authority RRs: 0
        b"\\x00\\x00"  # Additional RRs: 0
        b"\\x07example\\x03com\\x00"  # Query: example.com
        b"\\x00\\x01"  # Type: A
        b"\\x00\\x01"  # Class: IN
    )
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(5)
    start = time.time()
    try:
        sock.sendto(query, (dns_server, 53))
        data, addr = sock.recvfrom(512)
        elapsed = time.time() - start
        sock.close()
        return elapsed
    except socket.timeout:
        return None

# Run the comparison
print("TCP vs UDP Performance Comparison")
print("=" * 40)

tcp_time = measure_tcp_handshake("example.com", 80)
if tcp_time:
    print(f"TCP handshake to example.com:80 = {tcp_time*1000:.1f} ms")
else:
    print("TCP connection failed")

udp_time = measure_udp_dns()
if udp_time:
    print(f"UDP DNS query to 8.8.8.8:53    = {udp_time*1000:.1f} ms")
else:
    print("UDP DNS query failed")

if tcp_time and udp_time:
    print(f"\\nTCP overhead vs UDP: {((tcp_time/udp_time)-1)*100:.0f}% slower")
    print("(TCP requires a 3-way handshake; UDP just sends the packet)")""")
    press_enter()

    mark_lesson_complete(progress, MODULE_KEY, "lesson1")
    success("Lesson 1 complete: TCP/UDP Deep Dive")
    press_enter()


# ──────────────────────────────────────────────────────────────────────
#  Lesson 2 — Building a Port Scanner
# ──────────────────────────────────────────────────────────────────────
def lesson_port_scanner(progress):
    section_header("Lesson 2: Building a Port Scanner")

    lesson_block(
        "A port scanner is the most fundamental tool in a security professional's "
        "toolkit. It discovers which network services are running on a target system "
        "by probing ports and analyzing the responses. When you understand how to "
        "build one from scratch, you truly understand what tools like nmap are doing "
        "under the hood — and you can customize the behavior for your exact needs."
    )

    lesson_block(
        "The simplest scanning technique is the TCP connect scan. For each port, you "
        "attempt a full TCP connection (the three-way handshake). If the connection "
        "succeeds (you receive a SYN-ACK and complete with ACK), the port is open. "
        "If you receive a RST (reset) packet, the port is closed. If there is no "
        "response at all (timeout), the port is filtered — likely blocked by a "
        "firewall."
    )

    lesson_block(
        "The main downside of TCP connect scanning is speed. Each probe waits for "
        "either a connection or a timeout. With a 2-second timeout, scanning 65,535 "
        "ports sequentially would take over 36 hours. This is why threading is "
        "essential — by scanning many ports in parallel, we can reduce this to "
        "minutes. Python's concurrent.futures module makes this straightforward."
    )

    why_it_matters(
        "Port scanning is the first phase of almost every security assessment. It "
        "tells you what services are exposed to the network. An organization might "
        "think they only expose a web server, but a port scan reveals an open database "
        "port, a forgotten development server, or an unauthorized service. Every open "
        "port is a potential attack surface. Knowing how to scan quickly and interpret "
        "results accurately is a non-negotiable skill."
    )

    sub_header("Step 1: Basic Single-Port Check")
    code_block("""\
import socket

def check_port(host, port, timeout=1.5):
    \"\"\"Check if a single TCP port is open.
    Returns: 'open', 'closed', or 'filtered'
    \"\"\"
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))  # Returns 0 on success
        sock.close()

        if result == 0:
            return "open"
        else:
            return "closed"
    except socket.timeout:
        return "filtered"
    except OSError:
        return "error"

# Test it
status = check_port("127.0.0.1", 80)
print(f"Port 80: {status}")""")

    lesson_block(
        "Notice we use connect_ex() instead of connect(). The key difference is "
        "that connect_ex() returns an error code instead of raising an exception — "
        "0 means success (port open), any other value means failure. This is more "
        "efficient than catching exceptions for every closed port, especially when "
        "scanning thousands of ports."
    )

    sub_header("Step 2: Sequential Scanner (Slow but Simple)")
    code_block("""\
import socket
import time

def sequential_scan(host, ports, timeout=1.5):
    \"\"\"Scan ports one at a time (slow but reliable).\"\"\"
    results = {"open": [], "closed": [], "filtered": []}

    print(f"Scanning {host} ({len(ports)} ports)...")
    start_time = time.time()

    for port in ports:
        status = check_port(host, port, timeout)
        results[status].append(port)
        if status == "open":
            try:
                service = socket.getservbyport(port, "tcp")
            except OSError:
                service = "unknown"
            print(f"  {port}/tcp  open  {service}")

    elapsed = time.time() - start_time
    print(f"\\nScan complete: {elapsed:.1f}s")
    print(f"  Open: {len(results['open'])}")
    print(f"  Closed: {len(results['closed'])}")
    print(f"  Filtered: {len(results['filtered'])}")
    return results

# Scan common ports
common_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143,
                443, 445, 993, 995, 1433, 3306, 3389, 5432, 8080, 8443]
sequential_scan("127.0.0.1", common_ports)""")

    sub_header("Step 3: Threaded Scanner (Fast)")
    code_block("""\
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

def check_port(host, port, timeout=1.0):
    \"\"\"Check if a single TCP port is open.\"\"\"
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        return port, "open" if result == 0 else "closed"
    except socket.timeout:
        return port, "filtered"
    except OSError:
        return port, "error"

def threaded_scan(host, ports, timeout=1.0, max_workers=100):
    \"\"\"Scan ports using a thread pool for speed.\"\"\"
    results = {"open": [], "closed": [], "filtered": []}

    # Resolve hostname once
    try:
        ip = socket.gethostbyname(host)
    except socket.gaierror:
        print(f"Could not resolve hostname: {host}")
        return results

    print(f"Scanning {host} ({ip})")
    print(f"Ports: {len(ports)} | Threads: {max_workers} | Timeout: {timeout}s")
    print("-" * 50)
    start = time.time()

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(check_port, ip, port, timeout): port
            for port in ports
        }

        for future in as_completed(futures):
            port, status = future.result()
            results.setdefault(status, []).append(port)
            if status == "open":
                try:
                    service = socket.getservbyport(port, "tcp")
                except OSError:
                    service = "unknown"
                print(f"  {port:>5}/tcp  open  {service}")

    elapsed = time.time() - start
    results["open"].sort()

    print(f"\\n{'=' * 50}")
    print(f"Scan completed in {elapsed:.2f} seconds")
    print(f"  Open:     {len(results['open'])} ports")
    print(f"  Closed:   {len(results.get('closed', []))} ports")
    print(f"  Filtered: {len(results.get('filtered', []))} ports")
    return results

# Example: scan top 1024 ports quickly
threaded_scan("127.0.0.1", range(1, 1025), timeout=0.5, max_workers=200)""")

    lesson_block(
        "The threaded scanner is dramatically faster. Scanning 1024 ports with a "
        "0.5-second timeout could take 512 seconds sequentially. With 200 threads, "
        "the same scan takes about 3 seconds — a 170x speedup. However, be careful "
        "with thread count. Too many threads can overwhelm the target or your own "
        "system. Start with 100-200 for local networks, reduce to 20-50 for remote "
        "targets to avoid detection and rate-limiting."
    )

    sub_header("Step 4: Adding a Command-Line Interface")
    code_block("""\
#!/usr/bin/env python3
\"\"\"
port_scanner.py — A fast, threaded port scanner.
For authorized testing only.
\"\"\"
import argparse
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

def parse_port_range(port_string):
    \"\"\"Parse port specification: '80', '1-1024', '22,80,443', or '1-100,443,8080'.\"\"\"
    ports = set()
    for part in port_string.split(","):
        if "-" in part:
            start, end = part.split("-", 1)
            ports.update(range(int(start), int(end) + 1))
        else:
            ports.add(int(part))
    return sorted(ports)

def main():
    parser = argparse.ArgumentParser(description="TCP Port Scanner")
    parser.add_argument("target", help="Target host or IP")
    parser.add_argument("-p", "--ports", default="1-1024",
                        help="Port range (e.g., '80', '1-1024', '22,80,443')")
    parser.add_argument("-t", "--timeout", type=float, default=1.0)
    parser.add_argument("-w", "--workers", type=int, default=100)
    args = parser.parse_args()

    ports = parse_port_range(args.ports)
    threaded_scan(args.target, ports, args.timeout, args.workers)

if __name__ == "__main__":
    main()""")

    sub_header("Interpreting Scan Results")
    code_block("""\
# What the results mean:
#
# OPEN     — A service is listening and accepting connections.
#            Action: Identify the service, check for vulnerabilities.
#
# CLOSED   — The port is reachable but no service is listening.
#            The host sent a RST packet. This is normal.
#            Note: This confirms the host is alive and reachable.
#
# FILTERED — No response at all within the timeout period.
#            Usually means a firewall is silently dropping packets.
#            Action: Try a longer timeout, try a different scan type.
#
# Common findings and their implications:
#
# Port 22 open     — SSH access available (check for weak passwords)
# Port 23 open     — Telnet! Cleartext protocol, major finding
# Port 80/443 open — Web server (begin web app testing)
# Port 445 open    — SMB (check for EternalBlue, null sessions)
# Port 3306 open   — MySQL exposed to network (should be localhost only)
# Port 3389 open   — RDP exposed (check for BlueKeep, brute force)""", language="text")

    scenario_block("Discovering Shadow IT", (
        "During a quarterly security assessment, you scan the company's IP range and "
        "discover a machine at 10.0.5.47 with ports 80, 22, and 3306 open. This "
        "machine is not in the company's asset inventory. Investigation reveals a "
        "developer set up a personal server under their desk running an unpatched "
        "web application with a MySQL database exposed to the entire network. The "
        "database contained a copy of customer records for 'testing.' Your port "
        "scan caught this shadow IT before an attacker could exploit it."
    ))

    # ── Practice Challenge ──
    sub_header("Practice Challenge")
    info("Extend the port scanner with these features:")
    info("  1. Add a 'top ports' option that scans the 20 most common ports")
    info("  2. Save results to a JSON file with timestamp and target info")
    info("  3. Add a progress indicator that shows percentage complete\n")

    if ask_yes_no("Would you like a hint?"):
        hint_text("For progress: use a threading.Lock and a shared counter.")
        hint_text("For JSON output: collect results in a list of dicts, use json.dump().")

    press_enter()

    if ask_yes_no("Show the full solution?"):
        code_block("""\
import socket
import time
import json
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

TOP_20_PORTS = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139,
                143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080]

class PortScanner:
    def __init__(self, host, ports, timeout=1.0, workers=100):
        self.host = host
        self.ports = ports
        self.timeout = timeout
        self.workers = workers
        self.results = []
        self.scanned = 0
        self.lock = threading.Lock()
        self.total = len(ports)

    def _check_port(self, port):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(self.timeout)
            result = s.connect_ex((self.host, port))
            s.close()
            status = "open" if result == 0 else "closed"
        except socket.timeout:
            status = "filtered"
        except OSError:
            status = "error"

        with self.lock:
            self.scanned += 1
            pct = self.scanned / self.total * 100
            print(f"\\r  Progress: {pct:.0f}% ({self.scanned}/{self.total})",
                  end="", flush=True)

        return {"port": port, "status": status}

    def scan(self):
        ip = socket.gethostbyname(self.host)
        start = time.time()

        with ThreadPoolExecutor(max_workers=self.workers) as pool:
            futures = [pool.submit(self._check_port, p) for p in self.ports]
            for f in as_completed(futures):
                self.results.append(f.result())

        print()  # newline after progress
        self.results.sort(key=lambda r: r["port"])
        elapsed = time.time() - start

        # Display results
        open_ports = [r for r in self.results if r["status"] == "open"]
        for r in open_ports:
            try:
                svc = socket.getservbyport(r["port"], "tcp")
            except OSError:
                svc = "unknown"
            r["service"] = svc
            print(f"  {r['port']:>5}/tcp  open  {svc}")

        print(f"\\nDone in {elapsed:.2f}s — {len(open_ports)} open ports")
        return self.results

    def save_json(self, filepath):
        report = {
            "target": self.host,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "ports_scanned": len(self.ports),
            "results": [r for r in self.results if r["status"] == "open"],
        }
        with open(filepath, "w") as f:
            json.dump(report, f, indent=2)
        print(f"  Results saved to {filepath}")

# Usage:
scanner = PortScanner("127.0.0.1", TOP_20_PORTS)
scanner.scan()
scanner.save_json("scan_results.json")""")
    press_enter()

    mark_lesson_complete(progress, MODULE_KEY, "lesson2")
    mark_challenge_complete(progress, MODULE_KEY, "port_scanner")
    success("Lesson 2 complete: Building a Port Scanner")
    press_enter()


# ──────────────────────────────────────────────────────────────────────
#  Lesson 3 — Banner Grabbing
# ──────────────────────────────────────────────────────────────────────
def lesson_banner_grabbing(progress):
    section_header("Lesson 3: Banner Grabbing")

    lesson_block(
        "After discovering open ports, the next step is to identify what software "
        "is running on them. Many network services announce themselves by sending a "
        "banner — a text string that often includes the software name, version number, "
        "and sometimes the operating system. This is called banner grabbing, and it is "
        "one of the most valuable reconnaissance techniques available."
    )

    lesson_block(
        "Banner grabbing works because many protocols are designed to send an "
        "identification string when a client connects. SSH servers send their version "
        "string immediately upon connection (e.g., 'SSH-2.0-OpenSSH_8.9p1'). FTP "
        "servers send a welcome message with the server software name. SMTP servers "
        "announce themselves with a 220 greeting line. HTTP servers include a Server "
        "header in responses. Even when administrators try to hide version info, "
        "behavioral analysis can often fingerprint the software."
    )

    lesson_block(
        "There are two types of banner grabbing. Passive banner grabbing reads "
        "whatever the server sends upon connection without sending any data. Active "
        "banner grabbing sends a request (like an HTTP GET) and analyzes the "
        "response headers and content. Both techniques are valuable and used in "
        "combination for thorough enumeration."
    )

    why_it_matters(
        "Knowing the exact software and version running on a port is critical for "
        "vulnerability assessment. A server running OpenSSH 7.4 has different "
        "vulnerabilities than one running OpenSSH 9.0. An Apache 2.4.49 web server "
        "is vulnerable to a path traversal attack (CVE-2021-41773) while 2.4.51 is "
        "not. Banner information lets you quickly prioritize which services need "
        "attention and cross-reference against vulnerability databases like CVE and "
        "NVD. It is also a finding in itself — version disclosure helps attackers."
    )

    sub_header("Passive Banner Grabbing — Just Connect and Listen")
    code_block("""\
import socket

def grab_banner(host, port, timeout=3):
    \"\"\"Connect to a port and read whatever the service sends.\"\"\"
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((host, port))

            # Some services send a banner immediately
            banner = s.recv(1024)
            return banner.decode("utf-8", errors="replace").strip()
    except (socket.timeout, ConnectionRefusedError, OSError):
        return None

# Try common ports that send banners
banner_ports = [21, 22, 25, 110, 143]
host = "127.0.0.1"

for port in banner_ports:
    banner = grab_banner(host, port)
    if banner:
        print(f"  {port:>5}/tcp: {banner[:80]}")
    else:
        print(f"  {port:>5}/tcp: (no banner)")""")

    sub_header("Active Banner Grabbing — Send a Request")
    code_block("""\
import socket

def active_grab(host, port, probe=b"\\r\\n", timeout=3):
    \"\"\"Send a probe and read the response.\"\"\"
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((host, port))

            # Wait briefly for any automatic banner
            s.settimeout(1)
            try:
                initial = s.recv(1024)
            except socket.timeout:
                initial = b""

            # Send probe to trigger a response
            s.sendall(probe)
            s.settimeout(timeout)
            try:
                response = s.recv(4096)
            except socket.timeout:
                response = b""

            return (initial + response).decode("utf-8", errors="replace").strip()
    except (ConnectionRefusedError, OSError):
        return None

# Different probes for different services
probes = {
    "HTTP":  b"HEAD / HTTP/1.1\\r\\nHost: target\\r\\n\\r\\n",
    "SMTP":  b"EHLO test\\r\\n",
    "FTP":   b"\\r\\n",
    "SSH":   b"",   # SSH sends banner without prompting
}

# Try HTTP banner grab
banner = active_grab("example.com", 80, probes["HTTP"])
if banner:
    print(f"HTTP Response:\\n{banner[:300]}")""")

    sub_header("HTTP Header Enumeration")
    code_block("""\
import requests

def enumerate_http_service(url, timeout=5):
    \"\"\"Extract service information from HTTP headers.\"\"\"
    findings = []

    try:
        resp = requests.head(url, timeout=timeout, allow_redirects=False,
                            verify=False)

        # Server software
        server = resp.headers.get("Server", "Not disclosed")
        findings.append(("Server", server))

        # Technology stack
        powered_by = resp.headers.get("X-Powered-By", "Not disclosed")
        findings.append(("X-Powered-By", powered_by))

        # ASP.NET version
        aspnet = resp.headers.get("X-AspNet-Version", "")
        if aspnet:
            findings.append(("ASP.NET Version", aspnet))

        # PHP version (sometimes in X-Powered-By)
        if "PHP" in powered_by:
            findings.append(("PHP Detected", powered_by))

        # Framework clues from cookies
        cookies = resp.headers.get("Set-Cookie", "")
        if "JSESSIONID" in cookies:
            findings.append(("Framework", "Java (JSESSIONID cookie)"))
        elif "PHPSESSID" in cookies:
            findings.append(("Framework", "PHP (PHPSESSID cookie)"))
        elif "ASP.NET_SessionId" in cookies:
            findings.append(("Framework", "ASP.NET (SessionId cookie)"))
        elif "csrftoken" in cookies and "sessionid" in cookies:
            findings.append(("Framework", "Likely Django"))

        # Response body clues
        resp_get = requests.get(url, timeout=timeout, verify=False)
        body = resp_get.text.lower()
        if "wp-content" in body or "wordpress" in body:
            findings.append(("CMS", "WordPress detected"))
        elif "drupal" in body:
            findings.append(("CMS", "Drupal detected"))
        elif "joomla" in body:
            findings.append(("CMS", "Joomla detected"))

    except requests.exceptions.RequestException as e:
        findings.append(("Error", str(e)))

    return findings

# Example usage
results = enumerate_http_service("http://example.com")
print("HTTP Service Enumeration:")
for label, value in results:
    print(f"  {label:>20}: {value}")""")

    sub_header("Building a Multi-Port Banner Grabber")
    code_block("""\
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

# Service-specific probes for better banner extraction
SERVICE_PROBES = {
    21:  (b"\\r\\n", "FTP"),
    22:  (b"", "SSH"),          # SSH sends banner automatically
    25:  (b"EHLO scanner\\r\\n", "SMTP"),
    80:  (b"HEAD / HTTP/1.0\\r\\nHost: target\\r\\n\\r\\n", "HTTP"),
    110: (b"\\r\\n", "POP3"),
    143: (b"\\r\\n", "IMAP"),
    443: (b"", "HTTPS"),        # Needs SSL wrapping
    3306:(b"\\r\\n", "MySQL"),
    5432:(b"\\r\\n", "PostgreSQL"),
    8080:(b"HEAD / HTTP/1.0\\r\\nHost: target\\r\\n\\r\\n", "HTTP-Alt"),
}

def banner_scan(host, port, timeout=3):
    \"\"\"Grab banner from a specific port with an appropriate probe.\"\"\"
    probe, service_name = SERVICE_PROBES.get(port, (b"\\r\\n", "unknown"))

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((host, port))

            # Read any immediate banner
            s.settimeout(1.5)
            try:
                banner = s.recv(1024)
            except socket.timeout:
                banner = b""

            # Send probe if we have one and got no initial banner
            if probe and len(banner) < 5:
                s.sendall(probe)
                s.settimeout(timeout)
                try:
                    banner = s.recv(4096)
                except socket.timeout:
                    pass

            banner_text = banner.decode("utf-8", errors="replace").strip()
            # Truncate long banners
            if len(banner_text) > 200:
                banner_text = banner_text[:200] + "..."

            return {
                "port": port,
                "service": service_name,
                "banner": banner_text,
                "status": "open"
            }

    except (ConnectionRefusedError, socket.timeout, OSError):
        return {"port": port, "service": service_name,
                "banner": "", "status": "closed/filtered"}

def full_banner_scan(host, ports=None, workers=20):
    \"\"\"Scan multiple ports and grab banners.\"\"\"
    if ports is None:
        ports = list(SERVICE_PROBES.keys())

    print(f"Banner grabbing {host} on {len(ports)} ports...")
    results = []

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(banner_scan, host, p): p for p in ports}
        for future in as_completed(futures):
            result = future.result()
            results.append(result)
            if result["status"] == "open" and result["banner"]:
                print(f"  {result['port']:>5}/tcp ({result['service']:>10}): "
                      f"{result['banner'][:60]}")

    return sorted(results, key=lambda r: r["port"])

# Run it
results = full_banner_scan("127.0.0.1")""")

    sub_header("Analyzing Banners for Vulnerabilities")
    code_block("""\
import re

def analyze_banner(banner_text, port):
    \"\"\"Check a banner against known vulnerable versions.\"\"\"
    findings = []

    # OpenSSH version checks
    ssh_match = re.search(r"OpenSSH[_\\s]([\\d.]+)", banner_text)
    if ssh_match:
        version = ssh_match.group(1)
        findings.append(f"OpenSSH {version} detected")
        major, minor = map(int, version.split(".")[:2])
        if major < 8:
            findings.append("[HIGH] OpenSSH < 8.0 — multiple known CVEs")
        elif major == 8 and minor < 5:
            findings.append("[MEDIUM] OpenSSH < 8.5 — consider upgrading")

    # Apache version checks
    apache_match = re.search(r"Apache/(\\d+\\.\\d+\\.\\d+)", banner_text)
    if apache_match:
        version = apache_match.group(1)
        findings.append(f"Apache {version} detected")
        parts = list(map(int, version.split(".")))
        if parts[0] == 2 and parts[1] == 4 and parts[2] == 49:
            findings.append("[CRITICAL] Apache 2.4.49 — CVE-2021-41773 "
                          "(path traversal/RCE)")

    # MySQL version check
    mysql_match = re.search(r"(\\d+\\.\\d+\\.\\d+)", banner_text)
    if port == 3306 and mysql_match:
        findings.append(f"MySQL {mysql_match.group(1)} detected")
        findings.append("[INFO] MySQL exposed to network — verify this is intended")

    # FTP anonymous access hint
    if port == 21 and "220" in banner_text:
        findings.append("[INFO] FTP service active — test for anonymous access")

    return findings

# Example
banner = "SSH-2.0-OpenSSH_7.4"
for finding in analyze_banner(banner, 22):
    print(f"  {finding}")""")

    scenario_block("Version-Based Exploitation", (
        "Your port scan reveals port 80 open on a target. Banner grabbing shows "
        "'Apache/2.4.49 (Unix)'. You immediately recognize this version as vulnerable "
        "to CVE-2021-41773, a critical path traversal vulnerability that can lead to "
        "remote code execution. A quick test confirms the vulnerability. If the "
        "banner had shown Apache 2.4.52, you would know it is patched. This is why "
        "banner grabbing is one of the first things you do after port scanning — it "
        "instantly narrows your focus to the most impactful vulnerabilities."
    ))

    # ── Practice Challenge ──
    sub_header("Practice Challenge")
    info("Build a banner grabber that:")
    info("  1. Takes a host and a list of ports")
    info("  2. Grabs banners from all open ports")
    info("  3. Parses the banner to identify software and version")
    info("  4. Cross-references against a dictionary of known vulnerable versions\n")

    if ask_yes_no("Would you like a hint?"):
        hint_text("Start with the banner_scan() function above as your base.")
        hint_text("Create a KNOWN_VULNS dict mapping version strings to CVE IDs.")

    press_enter()

    if ask_yes_no("Show the full solution?"):
        code_block("""\
import socket
import re
from concurrent.futures import ThreadPoolExecutor

# Database of known vulnerable versions (simplified)
KNOWN_VULNS = {
    "OpenSSH_7.4":  ["CVE-2017-15906", "CVE-2018-15919"],
    "OpenSSH_7.6":  ["CVE-2018-15473"],
    "Apache/2.4.49": ["CVE-2021-41773 (CRITICAL: Path Traversal/RCE)"],
    "Apache/2.4.50": ["CVE-2021-42013 (CRITICAL: Path Traversal/RCE)"],
    "nginx/1.16":   ["CVE-2019-9516 (HTTP/2 DoS)"],
    "vsftpd 2.3.4": ["CVE-2011-2523 (Backdoor!)"],
    "ProFTPD 1.3.5": ["CVE-2015-3306 (Remote Code Execution)"],
}

def vuln_check(banner):
    \"\"\"Check a banner against known vulnerabilities.\"\"\"
    vulns_found = []
    for pattern, cves in KNOWN_VULNS.items():
        if pattern in banner:
            vulns_found.extend(cves)
    return vulns_found

def full_enumeration(host, ports):
    results = []
    for port in ports:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(3)
                s.connect((host, port))
                s.settimeout(2)
                try:
                    banner = s.recv(1024).decode(errors="replace").strip()
                except socket.timeout:
                    s.sendall(b"HEAD / HTTP/1.0\\r\\n\\r\\n")
                    banner = s.recv(4096).decode(errors="replace").strip()

                vulns = vuln_check(banner)
                results.append({
                    "port": port, "banner": banner[:100],
                    "vulns": vulns
                })
        except (ConnectionRefusedError, socket.timeout, OSError):
            continue

    # Report
    print(f"\\nEnumeration Report for {host}")
    print("=" * 60)
    for r in results:
        print(f"\\n  Port {r['port']}/tcp")
        print(f"  Banner: {r['banner']}")
        if r['vulns']:
            for v in r['vulns']:
                print(f"  [!] VULN: {v}")
        else:
            print(f"  [OK] No known vulnerabilities matched")

full_enumeration("127.0.0.1", [22, 80, 21, 443, 8080])""")
    press_enter()

    mark_lesson_complete(progress, MODULE_KEY, "lesson3")
    mark_challenge_complete(progress, MODULE_KEY, "banner_grabber")
    success("Lesson 3 complete: Banner Grabbing")
    press_enter()


# ──────────────────────────────────────────────────────────────────────
#  Lesson 4 — Network Mapping
# ──────────────────────────────────────────────────────────────────────
def lesson_network_mapping(progress):
    section_header("Lesson 4: Network Mapping")

    lesson_block(
        "Network mapping is the process of discovering all active hosts on a network "
        "and understanding how they are connected. Before you can assess the security "
        "of a network, you need to know what is on it. Network mapping answers the "
        "fundamental questions: How many hosts are alive? What are their IP addresses? "
        "What operating systems are they running? What services are exposed? How are "
        "they connected to each other?"
    )

    lesson_block(
        "There are several techniques for discovering hosts. ICMP echo (ping) is the "
        "simplest — send an ICMP echo request and wait for a reply. However, many "
        "hosts block ICMP. TCP ping is more reliable — try connecting to a common "
        "port (80 or 443) and see if the host responds. ARP (Address Resolution "
        "Protocol) scanning works on local networks — it is the most reliable method "
        "for discovering hosts on your subnet because ARP operates at Layer 2 and "
        "cannot be blocked by IP-level firewalls."
    )

    lesson_block(
        "ARP is the protocol that maps IP addresses to MAC (hardware) addresses on "
        "a local network. When your computer wants to communicate with 192.168.1.50, "
        "it first checks its ARP cache. If the MAC address is not cached, it sends a "
        "broadcast ARP request asking 'Who has 192.168.1.50?' The host at that IP "
        "responds with its MAC address. By sending ARP requests for every IP in the "
        "subnet, we can discover all active hosts — even those that block ping and "
        "have no open TCP ports."
    )

    why_it_matters(
        "You cannot secure what you do not know exists. Network mapping is the "
        "essential first step of any security assessment. Organizations routinely "
        "discover unknown devices on their networks — rogue wireless access points, "
        "unauthorized servers, IoT devices, personal equipment, and even attacker "
        "implants. An accurate network map is also critical for incident response: "
        "when a compromise is detected, you need to know what other systems might "
        "be affected. Continuous network mapping detects changes that could indicate "
        "unauthorized access."
    )

    sub_header("Host Discovery with ICMP Ping")
    code_block("""\
import subprocess
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed

def ping_host(ip_str, timeout=1):
    \"\"\"Ping a single host and return True if it responds.\"\"\"
    try:
        # Use system ping command (works cross-platform)
        import platform
        param = "-n" if platform.system().lower() == "windows" else "-c"
        timeout_param = "-w" if platform.system().lower() == "windows" else "-W"

        result = subprocess.run(
            ["ping", param, "1", timeout_param, str(timeout), ip_str],
            capture_output=True,
            text=True,
            timeout=timeout + 2
        )
        return result.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return False

def ping_sweep(network_cidr, workers=50):
    \"\"\"Ping sweep an entire subnet.\"\"\"
    network = ipaddress.ip_network(network_cidr, strict=False)
    hosts = [str(ip) for ip in network.hosts()]

    print(f"Ping sweeping {network_cidr} ({len(hosts)} hosts)...")
    alive = []

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(ping_host, ip): ip for ip in hosts}
        for future in as_completed(futures):
            ip = futures[future]
            if future.result():
                alive.append(ip)
                print(f"  [+] {ip} is alive")

    alive.sort(key=lambda x: ipaddress.ip_address(x))
    print(f"\\nDiscovered {len(alive)} live hosts out of {len(hosts)}")
    return alive

# Example: sweep a /24 subnet
# alive_hosts = ping_sweep("192.168.1.0/24")""")

    sub_header("TCP-Based Host Discovery")
    code_block("""\
import socket
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed

def tcp_ping(ip_str, port=80, timeout=1):
    \"\"\"Try a TCP connection to detect if a host is alive.\"\"\"
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip_str, port))
        sock.close()
        # connect_ex returns 0 (open) or error code
        # Both open AND closed (RST) ports prove the host is alive
        # Only timeout/no-route means the host is probably down
        return result != 110 and result != 113  # Not timeout/no-route
    except (socket.timeout, OSError):
        return False

def tcp_sweep(network_cidr, ports=[80, 443, 22], workers=100):
    \"\"\"Discover hosts using TCP probes on common ports.\"\"\"
    network = ipaddress.ip_network(network_cidr, strict=False)
    hosts = [str(ip) for ip in network.hosts()]

    print(f"TCP sweep of {network_cidr} on ports {ports}")
    alive = set()

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {}
        for ip in hosts:
            for port in ports:
                future = pool.submit(tcp_ping, ip, port)
                futures[future] = (ip, port)

        for future in as_completed(futures):
            ip, port = futures[future]
            if future.result() and ip not in alive:
                alive.add(ip)
                print(f"  [+] {ip} responded on port {port}")

    sorted_hosts = sorted(alive, key=lambda x: ipaddress.ip_address(x))
    print(f"\\nDiscovered {len(sorted_hosts)} hosts via TCP")
    return sorted_hosts

# Example usage:
# hosts = tcp_sweep("192.168.1.0/24", ports=[80, 443, 22, 3389])""")

    sub_header("Understanding ARP for Local Network Discovery")
    code_block("""\
# ARP (Address Resolution Protocol) — How Local Networks Work
#
# When Host A wants to talk to Host B on the same subnet:
#
#   Host A (192.168.1.10)                Host B (192.168.1.20)
#       |                                      |
#       |  ARP Request (broadcast):             |
#       |  "Who has 192.168.1.20?              |
#       |   Tell 192.168.1.10"                 |
#       | ──────── FF:FF:FF:FF:FF:FF ────────> |
#       |                                      |
#       |  ARP Reply (unicast):                |
#       |  "192.168.1.20 is at                 |
#       |   AA:BB:CC:DD:EE:FF"                 |
#       | <─────── direct to Host A ────────── |
#       |                                      |
#       |  Now Host A can send IP packets      |
#       |  to Host B using the MAC address     |
#
# ARP scanning advantages:
# - Works even if ICMP is blocked
# - Works even if all TCP/UDP ports are closed
# - Cannot be blocked by host-level firewalls
# - Only works on the local subnet (Layer 2)
#
# View your ARP cache:
#   Linux/macOS: arp -a
#   Windows:     arp -a""", language="text")

    sub_header("Reading the System ARP Cache")
    code_block("""\
import subprocess
import re

def read_arp_cache():
    \"\"\"Read the system ARP cache to find known hosts.\"\"\"
    try:
        result = subprocess.run(
            ["arp", "-a"],
            capture_output=True,
            text=True,
            timeout=5
        )

        hosts = []
        # Parse ARP output — format varies by OS
        for line in result.stdout.splitlines():
            # Match IP and MAC address patterns
            ip_match = re.search(
                r'\\b(\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3})\\b', line
            )
            mac_match = re.search(
                r'([0-9a-fA-F]{1,2}[:-]){5}[0-9a-fA-F]{1,2}', line
            )

            if ip_match and mac_match:
                ip = ip_match.group(1)
                mac = mac_match.group(0)
                hosts.append({"ip": ip, "mac": mac})

        return hosts

    except (subprocess.TimeoutExpired, FileNotFoundError):
        return []

# Display known hosts from ARP cache
print("Hosts in ARP cache:")
for host in read_arp_cache():
    print(f"  {host['ip']:>15}  {host['mac']}")""")

    sub_header("Building a Complete Network Mapper")
    code_block("""\
import socket
import subprocess
import ipaddress
import json
import time
import re
from concurrent.futures import ThreadPoolExecutor, as_completed

class NetworkMapper:
    \"\"\"Discovers and catalogs hosts on a network.\"\"\"

    def __init__(self, network_cidr, timeout=1.0, workers=100):
        self.network = ipaddress.ip_network(network_cidr, strict=False)
        self.timeout = timeout
        self.workers = workers
        self.hosts = {}  # ip -> host info dict

    def discover_hosts(self, methods=("tcp", "ping")):
        \"\"\"Run host discovery using specified methods.\"\"\"
        all_ips = [str(ip) for ip in self.network.hosts()]
        print(f"[*] Discovering hosts in {self.network} "
              f"({len(all_ips)} addresses)")

        if "tcp" in methods:
            self._tcp_discovery(all_ips)
        if "ping" in methods:
            self._ping_discovery(all_ips)

        print(f"[+] Total hosts discovered: {len(self.hosts)}")
        return self.hosts

    def _tcp_discovery(self, ips):
        \"\"\"Discover hosts via TCP probes.\"\"\"
        probe_ports = [80, 443, 22, 445, 3389]
        print(f"  TCP probing ports {probe_ports}...")

        with ThreadPoolExecutor(max_workers=self.workers) as pool:
            futures = {}
            for ip in ips:
                for port in probe_ports:
                    f = pool.submit(self._tcp_probe, ip, port)
                    futures[f] = (ip, port)

            for future in as_completed(futures):
                ip, port = futures[future]
                is_alive, is_open = future.result()
                if is_alive:
                    if ip not in self.hosts:
                        self.hosts[ip] = {
                            "ip": ip,
                            "open_ports": [],
                            "discovery": "tcp",
                            "hostname": ""
                        }
                    if is_open and port not in self.hosts[ip]["open_ports"]:
                        self.hosts[ip]["open_ports"].append(port)

    def _tcp_probe(self, ip, port):
        \"\"\"Probe a single IP:port. Returns (is_alive, is_open).\"\"\"
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(self.timeout)
            result = s.connect_ex((ip, port))
            s.close()
            if result == 0:
                return True, True    # Host alive, port open
            else:
                return True, False   # Host alive, port closed
        except socket.timeout:
            return False, False
        except OSError:
            return False, False

    def _ping_discovery(self, ips):
        \"\"\"Discover hosts via ICMP ping.\"\"\"
        import platform
        param = "-n" if platform.system().lower() == "windows" else "-c"
        print("  ICMP ping sweep...")

        already_found = set(self.hosts.keys())
        remaining = [ip for ip in ips if ip not in already_found]

        with ThreadPoolExecutor(max_workers=self.workers) as pool:
            futures = {pool.submit(self._ping, ip, param): ip
                      for ip in remaining}
            for future in as_completed(futures):
                ip = futures[future]
                if future.result() and ip not in self.hosts:
                    self.hosts[ip] = {
                        "ip": ip,
                        "open_ports": [],
                        "discovery": "icmp",
                        "hostname": ""
                    }

    def _ping(self, ip, count_flag):
        try:
            r = subprocess.run(
                ["ping", count_flag, "1", "-W", "1", ip],
                capture_output=True, timeout=3
            )
            return r.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return False

    def resolve_hostnames(self):
        \"\"\"Reverse-DNS lookup for discovered hosts.\"\"\"
        print("[*] Resolving hostnames...")
        for ip in self.hosts:
            try:
                hostname = socket.gethostbyaddr(ip)[0]
                self.hosts[ip]["hostname"] = hostname
            except (socket.herror, socket.gaierror):
                self.hosts[ip]["hostname"] = "(no PTR record)"

    def generate_report(self):
        \"\"\"Print a formatted network map report.\"\"\"
        sorted_hosts = sorted(
            self.hosts.values(),
            key=lambda h: ipaddress.ip_address(h["ip"])
        )

        print(f"\\n{'=' * 65}")
        print(f"  NETWORK MAP — {self.network}")
        print(f"  Discovered: {len(sorted_hosts)} hosts")
        print(f"  Generated:  {time.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{'=' * 65}\\n")

        for host in sorted_hosts:
            ports_str = ", ".join(str(p) for p in sorted(host["open_ports"]))
            hostname = host.get("hostname", "")
            print(f"  {host['ip']:>15}  {hostname:>30}  "
                  f"ports: [{ports_str or 'none detected'}]")

        print(f"\\n{'=' * 65}")

    def save_json(self, filepath):
        \"\"\"Export the network map as JSON.\"\"\"
        report = {
            "network": str(self.network),
            "scan_time": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "host_count": len(self.hosts),
            "hosts": list(self.hosts.values()),
        }
        with open(filepath, "w") as f:
            json.dump(report, f, indent=2)
        print(f"  Network map saved to {filepath}")

# Usage:
# mapper = NetworkMapper("192.168.1.0/24")
# mapper.discover_hosts(methods=("tcp", "ping"))
# mapper.resolve_hostnames()
# mapper.generate_report()
# mapper.save_json("network_map.json")""")

    sub_header("Understanding Network Topology")
    code_block("""\
# After discovering hosts, map the network topology:
#
# Internet
#    |
# [Firewall / Router]  (192.168.1.1)
#    |
#    ├── [Web Server]   (192.168.1.10)  ports: 80, 443
#    ├── [Mail Server]  (192.168.1.11)  ports: 25, 143, 993
#    ├── [DB Server]    (192.168.1.20)  ports: 3306
#    ├── [Dev Server]   (192.168.1.30)  ports: 22, 80, 3000, 8080
#    ├── [Workstation]  (192.168.1.100) ports: (none)
#    ├── [Workstation]  (192.168.1.101) ports: 3389
#    └── [???Unknown]   (192.168.1.200) ports: 22, 4444  <-- suspicious!
#
# Key observations from this map:
# 1. DB server (3306) should only be accessible from the web server
# 2. Dev server has multiple web services — potential attack surface
# 3. Unknown host at .200 with port 4444 (Metasploit?) — investigate!
# 4. Workstation at .101 has RDP exposed — should it be?""", language="text")

    scenario_block("Finding the Attacker's Foothold", (
        "During an incident response, you need to quickly map the compromised "
        "network segment. Your network mapper discovers 47 hosts on the VLAN, "
        "matching the expected count from the asset inventory — except there are "
        "48 entries in your scan. The extra host (10.0.3.88) is not in any inventory. "
        "Banner grabbing reveals it is running an SSH server and a web-based command "
        "and control panel on port 8443. This is the attacker's pivot point — a "
        "Raspberry Pi plugged into a network jack in a conference room. Your network "
        "mapping skills led directly to discovering the physical implant."
    ))

    # ── Practice Challenge ──
    sub_header("Practice Challenge")
    info("Build a network discovery script that combines multiple methods:")
    info("  1. ARP cache reading for instant local host discovery")
    info("  2. TCP probing on common ports for reliable discovery")
    info("  3. Reverse DNS lookup for every discovered host")
    info("  4. A summary report with all findings\n")

    if ask_yes_no("Would you like a hint?"):
        hint_text("Start with read_arp_cache() to get known hosts instantly.")
        hint_text("Then use tcp_sweep() to find hosts not in the ARP cache.")
        hint_text("Use socket.gethostbyaddr() for reverse DNS, wrapped in try/except.")

    press_enter()

    if ask_yes_no("Show the full solution?"):
        code_block("""\
import socket
import subprocess
import re
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed

def combined_discovery(network_cidr):
    network = ipaddress.ip_network(network_cidr, strict=False)
    all_ips = {str(ip) for ip in network.hosts()}
    discovered = {}

    # Phase 1: Read ARP cache (instant)
    print("[Phase 1] Reading ARP cache...")
    try:
        arp_output = subprocess.run(
            ["arp", "-a"], capture_output=True, text=True, timeout=5
        ).stdout
        for line in arp_output.splitlines():
            ip_match = re.search(r'(\\d+\\.\\d+\\.\\d+\\.\\d+)', line)
            mac_match = re.search(
                r'([0-9a-fA-F:.-]{11,17})', line
            )
            if ip_match and mac_match:
                ip = ip_match.group(1)
                if ip in all_ips:
                    discovered[ip] = {
                        "mac": mac_match.group(0),
                        "method": "arp",
                        "ports": [],
                        "hostname": ""
                    }
    except Exception:
        pass
    print(f"  Found {len(discovered)} hosts in ARP cache")

    # Phase 2: TCP probe remaining hosts
    print("[Phase 2] TCP probing...")
    remaining = all_ips - set(discovered.keys())
    probe_ports = [22, 80, 443, 445, 8080]

    def tcp_check(ip, port):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.8)
            r = s.connect_ex((ip, port))
            s.close()
            return ip, port, r == 0
        except:
            return ip, port, False

    with ThreadPoolExecutor(max_workers=150) as pool:
        futures = []
        for ip in remaining:
            for port in probe_ports:
                futures.append(pool.submit(tcp_check, ip, port))

        for f in as_completed(futures):
            ip, port, is_open = f.result()
            if is_open:
                if ip not in discovered:
                    discovered[ip] = {
                        "mac": "unknown",
                        "method": "tcp",
                        "ports": [],
                        "hostname": ""
                    }
                if port not in discovered[ip]["ports"]:
                    discovered[ip]["ports"].append(port)

    print(f"  Total hosts: {len(discovered)}")

    # Phase 3: Reverse DNS
    print("[Phase 3] Resolving hostnames...")
    for ip in discovered:
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            discovered[ip]["hostname"] = hostname
        except (socket.herror, socket.gaierror):
            discovered[ip]["hostname"] = ""

    # Report
    print(f"\\n{'=' * 70}")
    print(f"  NETWORK DISCOVERY REPORT — {network_cidr}")
    print(f"  Hosts found: {len(discovered)}")
    print(f"{'=' * 70}\\n")

    for ip in sorted(discovered, key=lambda x: ipaddress.ip_address(x)):
        h = discovered[ip]
        ports = ",".join(map(str, sorted(h["ports"]))) or "-"
        name = h["hostname"] or "(no DNS)"
        method = h["method"]
        print(f"  {ip:>15}  {name:>25}  via:{method:<4}  "
              f"ports:[{ports}]")

    return discovered

# combined_discovery("192.168.1.0/24")""")
    press_enter()

    mark_lesson_complete(progress, MODULE_KEY, "lesson4")
    mark_challenge_complete(progress, MODULE_KEY, "network_mapper")
    success("Lesson 4 complete: Network Mapping")
    success("You have completed all lessons in Module 2!")
    press_enter()


# ──────────────────────────────────────────────────────────────────────
#  Quiz
# ──────────────────────────────────────────────────────────────────────
QUIZ_QUESTIONS = [
    {
        "q": "What are the three packets exchanged during a TCP three-way handshake?",
        "options": [
            "A) SYN, ACK, FIN",
            "B) SYN, SYN-ACK, ACK",
            "C) SYN, RST, ACK",
            "D) ACK, SYN-ACK, FIN",
        ],
        "answer": "b",
        "explanation": "The TCP three-way handshake is: (1) Client sends SYN, (2) Server responds with SYN-ACK, (3) Client sends ACK. Only then is the connection established.",
    },
    {
        "q": "Why is UDP scanning harder than TCP scanning?",
        "options": [
            "A) UDP uses encryption by default",
            "B) UDP ports cannot be scanned",
            "C) UDP is connectionless — no SYN-ACK to confirm an open port",
            "D) UDP only works on localhost",
        ],
        "answer": "c",
        "explanation": "TCP scanning relies on the SYN-ACK response to identify open ports. UDP has no handshake — an open UDP port might simply not respond, making it indistinguishable from a filtered port.",
    },
    {
        "q": "What does it mean when a port scan shows a port as 'filtered'?",
        "options": [
            "A) The service is running but requires authentication",
            "B) The port is open but bandwidth-limited",
            "C) No response was received — likely blocked by a firewall",
            "D) The port responded with a RST packet",
        ],
        "answer": "c",
        "explanation": "A 'filtered' result means the scanner received no response (timeout). This usually indicates a firewall is silently dropping the packets. A RST response would mean 'closed', not 'filtered'.",
    },
    {
        "q": "Why is ARP scanning the most reliable method for local network discovery?",
        "options": [
            "A) ARP works over the internet, not just local networks",
            "B) ARP operates at Layer 2 and cannot be blocked by IP-level firewalls",
            "C) ARP is faster than light",
            "D) ARP uses encryption to avoid detection",
        ],
        "answer": "b",
        "explanation": "ARP operates at the data link layer (Layer 2). Since all hosts must respond to ARP to communicate on the network, even hosts with IP firewalls blocking all ports will still respond to ARP requests on the local subnet.",
    },
    {
        "q": "A banner grab on port 22 returns 'SSH-2.0-OpenSSH_7.4'. Why is this a security concern?",
        "options": [
            "A) SSH should never run on port 22",
            "B) The version disclosure helps attackers find known vulnerabilities for that specific version",
            "C) OpenSSH is inherently insecure",
            "D) Version 7.4 uses UDP instead of TCP",
        ],
        "answer": "b",
        "explanation": "Knowing the exact version allows attackers to search CVE databases for vulnerabilities specific to OpenSSH 7.4. While SSH needs to exchange version info for protocol negotiation, exposing old/unpatched versions increases risk.",
    },
    {
        "q": "Why should you use connect_ex() instead of connect() in a port scanner?",
        "options": [
            "A) connect_ex() is faster because it skips the handshake",
            "B) connect_ex() returns an error code instead of raising an exception, which is more efficient for scanning many ports",
            "C) connect_ex() supports UDP, while connect() only supports TCP",
            "D) connect_ex() automatically grabs service banners",
        ],
        "answer": "b",
        "explanation": "connect_ex() returns 0 on success and an error code on failure, avoiding the overhead of exception handling for every closed port. When scanning thousands of ports, this is significantly more efficient than catching ConnectionRefusedError on each one.",
    },
]


# ──────────────────────────────────────────────────────────────────────
#  Module entry point
# ──────────────────────────────────────────────────────────────────────
def run(progress):
    """Main entry point called from the menu system."""
    module_key = MODULE_KEY
    while True:
        choice = show_menu("Module 2: Network Fundamentals", [
            ("lesson1", "Lesson 1: TCP/UDP Deep Dive"),
            ("lesson2", "Lesson 2: Building a Port Scanner"),
            ("lesson3", "Lesson 3: Banner Grabbing"),
            ("lesson4", "Lesson 4: Network Mapping"),
            ("quiz", "Take the Quiz"),
        ])

        if choice == "back":
            return
        if choice == "quit":
            raise SystemExit

        if choice == "lesson1":
            lesson_tcp_udp(progress)
        elif choice == "lesson2":
            lesson_port_scanner(progress)
        elif choice == "lesson3":
            lesson_banner_grabbing(progress)
        elif choice == "lesson4":
            lesson_network_mapping(progress)
        elif choice == "quiz":
            run_quiz(QUIZ_QUESTIONS, "network_fundamentals", module_key, progress)
