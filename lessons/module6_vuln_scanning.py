"""
Module 6: Vulnerability Scanning
=================================
Covers the fundamentals of vulnerability assessment — understanding CVEs and
CVSS scores, port scanning techniques, detecting outdated software, and
auditing system configurations for common security misconfigurations.

All scanning must only be performed against systems you own or have explicit
written authorization to test.
"""

from utils.display import (
    section_header, sub_header, lesson_block, code_block,
    scenario_block, why_it_matters, info, success, warning, press_enter,
    show_menu, disclaimer, hint_text, ask_yes_no, C, G, Y, R, RESET, BRIGHT, DIM,
    pace, learning_goal, nice_work, tip
)
from utils.progress import mark_lesson_complete, mark_challenge_complete
from utils.quiz import run_quiz


# ---------------------------------------------------------------------------
# Lesson 1 — Understanding Vulnerabilities
# ---------------------------------------------------------------------------
def _lesson_understanding_vulns(progress):
    module_key = "module6"
    lesson_id = "understanding_vulns"

    section_header("Lesson 1: Understanding Vulnerabilities")
    learning_goal([
        "Know what a security vulnerability is and how it differs from a bug",
        "Understand the CVE system and how vulnerabilities are cataloged",
        "Read and interpret CVSS severity scores",
    ])
    disclaimer()

    # ---------- What is a vulnerability ----------
    sub_header("What is a Security Vulnerability?")
    lesson_block(
        "A security vulnerability is a weakness in a system, application, or "
        "process that could be exploited by a threat actor to gain unauthorized "
        "access, disrupt operations, or steal data."
    )
    pace()

    lesson_block(
        "Vulnerabilities can exist in software code, system configurations, "
        "network architectures, or even human procedures."
    )
    lesson_block(
        "Not every bug is a vulnerability. A vulnerability specifically means "
        "that the bug has a security impact — it can be leveraged to violate "
        "the confidentiality, integrity, or availability of a system."
    )
    tip("A good mental test: 'Could someone use this bug to access data or systems they should not?' If yes, it is a vulnerability.")
    pace()

    # ---------- The CVE System ----------
    sub_header("The CVE System")
    lesson_block(
        "CVE stands for Common Vulnerabilities and Exposures. It is a globally "
        "recognized system for identifying and cataloging publicly known "
        "security vulnerabilities."
    )
    lesson_block(
        "Each vulnerability is assigned a unique identifier in the format "
        "CVE-YYYY-NNNNN (e.g., CVE-2021-44228, the infamous Log4Shell "
        "vulnerability)."
    )
    pace()

    lesson_block(
        "The CVE system is maintained by the MITRE Corporation and funded by "
        "the U.S. Department of Homeland Security. CVE Numbering Authorities "
        "(CNAs) — including major vendors like Microsoft, Google, and Red Hat "
        "— are authorized to assign CVE IDs."
    )
    pace()

    info(f"{BRIGHT}CVE Lifecycle:{RESET}")
    info(f"  1. A vulnerability is discovered (by a researcher, vendor, or attacker).")
    info(f"  2. A CVE ID is reserved (often before full details are published).")
    info(f"  3. The vendor develops and tests a patch.")
    print()
    pace()

    info(f"  4. The CVE is published with a description, affected versions, and references.")
    info(f"  5. Security scanners are updated to detect the vulnerability.")
    info(f"  6. Organizations apply patches and verify remediation.")
    print()
    nice_work("You now understand the CVE identification system!")
    pace()

    # ---------- CVSS Scoring ----------
    sub_header("CVSS Scoring")
    lesson_block(
        "The Common Vulnerability Scoring System (CVSS) provides a standardized "
        "way to rate the severity of vulnerabilities on a scale of 0.0 to 10.0."
    )
    lesson_block(
        "CVSS scores help organizations prioritize which vulnerabilities to "
        "fix first."
    )
    pace()

    info(f"{BRIGHT}CVSS Severity Ratings:{RESET}")
    info(f"  {DIM}0.0{RESET}       — None")
    info(f"  {G}0.1 - 3.9{RESET} — Low")
    info(f"  {Y}4.0 - 6.9{RESET} — Medium")
    info(f"  {R}7.0 - 8.9{RESET} — High")
    info(f"  {R}{BRIGHT}9.0 - 10.0{RESET} — Critical")
    print()
    pace()

    lesson_block(
        "CVSS considers several metrics to calculate the score."
    )

    info(f"{BRIGHT}Attack Vector (AV){RESET}       — Network, Adjacent, Local, or Physical")
    info(f"{BRIGHT}Attack Complexity (AC){RESET}    — Low or High")
    info(f"{BRIGHT}Privileges Required (PR){RESET}  — None, Low, or High")
    info(f"{BRIGHT}User Interaction (UI){RESET}     — None or Required")
    print()
    pace()

    info(f"{BRIGHT}Scope (S){RESET}                — Unchanged or Changed")
    info(f"{BRIGHT}Confidentiality (C){RESET}      — None, Low, or High")
    info(f"{BRIGHT}Integrity (I){RESET}            — None, Low, or High")
    info(f"{BRIGHT}Availability (A){RESET}         — None, Low, or High")
    print()
    pace()

    lesson_block(
        "A vulnerability that is remotely exploitable (Network), requires no "
        "authentication (Privileges Required: None), needs no user interaction, "
        "and has high impact on confidentiality, integrity, and availability "
        "will score close to 10.0."
    )
    lesson_block(
        "Log4Shell (CVE-2021-44228) received a CVSS score of 10.0 because it "
        "met all these worst-case criteria."
    )
    tip("When you see a CVSS score of 9.0 or above, treat it as an emergency.")
    pace()

    # ---------- NVD Database ----------
    sub_header("The National Vulnerability Database (NVD)")
    lesson_block(
        "The NVD (nvd.nist.gov) is the U.S. government's repository of "
        "vulnerability data. It enriches CVE entries with CVSS scores, "
        "affected product information, and remediation references."
    )
    lesson_block(
        "The NVD provides a REST API that allows programmatic querying."
    )
    pace()

    code_block(
        """import requests

def search_nvd(keyword, results_per_page=5):
    \"\"\"Search the NVD for vulnerabilities matching a keyword.\"\"\"
    base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {
        "keywordSearch": keyword,
        "resultsPerPage": results_per_page,
    }
    try:
        resp = requests.get(base_url, params=params, timeout=30)
        resp.raise_for_status()
        data = resp.json()
        total = data.get("totalResults", 0)
        print(f"  Found {total} total CVEs matching '{keyword}'")
        print(f"  Showing first {results_per_page}:\\n")

        for vuln in data.get("vulnerabilities", []):
            cve = vuln["cve"]
            cve_id = cve["id"]
            description = cve["descriptions"][0]["value"][:120]

            # Extract CVSS score if available
            metrics = cve.get("metrics", {})
            score = "N/A"
            if "cvssMetricV31" in metrics:
                score = metrics["cvssMetricV31"][0]["cvssData"]["baseScore"]
            elif "cvssMetricV2" in metrics:
                score = metrics["cvssMetricV2"][0]["cvssData"]["baseScore"]

            print(f"  {cve_id}  (CVSS: {score})")
            print(f"    {description}...")
            print()
    except requests.RequestException as e:
        print(f"  NVD query failed: {e}")

# Example — search for Apache vulnerabilities
# search_nvd("apache http server")""", "python"
    )
    nice_work("You can now search the NVD programmatically!")
    pace()

    # ---------- Vulnerability disclosure ----------
    sub_header("Responsible Vulnerability Disclosure")
    lesson_block(
        "When a security researcher discovers a vulnerability, the standard "
        "practice is Coordinated Vulnerability Disclosure (CVD)."
    )
    pace()

    info(f"  1. The researcher privately reports the vulnerability to the vendor.")
    info(f"  2. The vendor acknowledges receipt and begins developing a fix.")
    info(f"  3. A mutually agreed disclosure timeline is set (typically 90 days).")
    print()
    pace()

    info(f"  4. The vendor releases a patch and publishes a security advisory.")
    info(f"  5. The CVE is made public with full details.")
    info(f"  6. The researcher may publish a detailed write-up or proof of concept.")
    print()
    pace()

    lesson_block(
        "This process balances the need for transparency (so defenders can "
        "protect themselves) against the risk of giving attackers a roadmap "
        "before patches are widely deployed."
    )
    lesson_block(
        "Some organizations run bug bounty programs to incentivize "
        "responsible reporting."
    )
    pace()

    # ---------- Why it matters ----------
    why_it_matters(
        "Understanding the CVE ecosystem is fundamental to vulnerability "
        "management. Your organization should have processes to monitor new CVE "
        "announcements for the software you use, assess CVSS scores to "
        "prioritize patching, and track remediation progress."
    )
    lesson_block(
        "A single unpatched critical vulnerability can lead to a full "
        "network compromise."
    )
    pace()

    # ---------- Real-world scenario ----------
    scenario_block(
        "Log4Shell (CVE-2021-44228)",
        "In December 2021, a critical vulnerability in the Apache Log4j "
        "logging library was disclosed. It allowed remote code execution "
        "simply by causing the application to log a specially crafted string. "
        "With a CVSS score of 10.0 and Log4j embedded in hundreds of thousands "
        "of applications worldwide, it became one of the most impactful "
        "vulnerabilities in history. Organizations that maintained accurate "
        "software inventories were able to identify and patch affected systems "
        "within days; those without inventories struggled for weeks."
    )
    tip("Keep a complete inventory of every piece of software running in your environment. It pays off during emergencies.")
    pace()

    # ---------- Practice challenge ----------
    sub_header("Practice Challenge")
    lesson_block(
        "Build a Python script that queries the NVD API for a given software "
        "name, retrieves the top 10 most recent CVEs, and displays them in a "
        "table sorted by CVSS score (highest first)."
    )
    lesson_block(
        "Color-code the scores: green for Low, yellow for Medium, red for "
        "High/Critical."
    )
    hint_text("Use the NVD API v2.0 endpoint shown above.")
    hint_text("Sort the results list with a lambda on the CVSS score before printing.")
    pace()

    code_block(
        """import requests

# Color codes for terminal output
RED = "\\033[91m"
YELLOW = "\\033[93m"
GREEN = "\\033[92m"
RESET = "\\033[0m"

def color_score(score):
    \"\"\"Return a color-coded CVSS score string.\"\"\"
    if score is None:
        return "N/A"
    if score >= 7.0:
        return f"{RED}{score}{RESET}"
    elif score >= 4.0:
        return f"{YELLOW}{score}{RESET}"
    else:
        return f"{GREEN}{score}{RESET}" """, "python"
    )
    pace()

    code_block(
        """def top_cves(keyword, count=10):
    \"\"\"Fetch and display top CVEs by CVSS score for a keyword.\"\"\"
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {"keywordSearch": keyword, "resultsPerPage": count}
    resp = requests.get(url, params=params, timeout=30)
    resp.raise_for_status()

    entries = []
    for vuln in resp.json().get("vulnerabilities", []):
        cve = vuln["cve"]
        cve_id = cve["id"]
        desc = cve["descriptions"][0]["value"][:80]
        metrics = cve.get("metrics", {})
        score = None
        if "cvssMetricV31" in metrics:
            score = metrics["cvssMetricV31"][0]["cvssData"]["baseScore"]
        elif "cvssMetricV2" in metrics:
            score = metrics["cvssMetricV2"][0]["cvssData"]["baseScore"]
        entries.append((cve_id, score, desc))

    # Sort by score descending (None values last)
    entries.sort(key=lambda x: x[1] if x[1] else 0, reverse=True)

    print(f"{'CVE ID':<20} {'CVSS':>6}  Description")
    print("-" * 70)
    for cve_id, score, desc in entries:
        print(f"{cve_id:<20} {color_score(score):>6}  {desc}")

# top_cves("apache http server")""", "python"
    )

    if ask_yes_no("Mark this challenge as attempted?"):
        mark_challenge_complete(progress, module_key, "vuln_understanding_challenge")
        success("Challenge marked complete!")

    press_enter()
    mark_lesson_complete(progress, module_key, lesson_id)
    success("Lesson 1 complete: Understanding Vulnerabilities")
    press_enter()


# ---------------------------------------------------------------------------
# Lesson 2 — Port Scanning Deep Dive
# ---------------------------------------------------------------------------
def _lesson_port_scanning(progress):
    module_key = "module6"
    lesson_id = "port_scanning"

    section_header("Lesson 2: Port Scanning Deep Dive")
    learning_goal([
        "Understand what port scanning is and why it matters",
        "Know the difference between TCP Connect and SYN scans",
        "Grab service banners and detect operating systems",
        "Build a multi-threaded port scanner in Python",
    ])
    disclaimer()

    # ---------- Port scanning fundamentals ----------
    sub_header("Port Scanning Fundamentals")
    lesson_block(
        "Port scanning is the process of probing a host to discover which "
        "network ports are open, closed, or filtered. Each open port "
        "represents a running network service — and every service is a "
        "potential attack vector."
    )
    pace()

    lesson_block(
        "TCP ports range from 0 to 65535. The first 1024 (0-1023) are "
        "'well-known' ports assigned to common services like HTTP (80), "
        "HTTPS (443), SSH (22), FTP (21), and SMTP (25)."
    )
    lesson_block(
        "Ports 1024-49151 are 'registered' ports, and 49152-65535 are "
        "'dynamic' or 'ephemeral' ports."
    )
    tip("When in doubt, start by scanning the well-known ports (0-1023). That covers the most common services.")
    pace()

    # ---------- Scan types ----------
    sub_header("TCP Connect Scan vs. SYN Scan")

    info(f"{BRIGHT}TCP Connect Scan (Full Open Scan){RESET}")
    lesson_block(
        "A TCP Connect scan completes the full three-way TCP handshake "
        "(SYN -> SYN-ACK -> ACK) with each port. If the handshake succeeds, "
        "the port is open."
    )
    lesson_block(
        "This is the simplest scan type and does not require special "
        "privileges because it uses the operating system's standard "
        "connect() system call."
    )
    pace()

    code_block(
        """import socket

# TCP Connect Scan — the simplest approach
# Three-way handshake:  Client ---SYN--->   Server
#                       Client <--SYN/ACK-- Server
#                       Client ---ACK--->   Server
#                       (Connection established = port OPEN)

def tcp_connect_scan(host, port, timeout=2):
    \"\"\"Attempt a full TCP connection to determine if a port is open.\"\"\"
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        result = sock.connect_ex((host, port))
        if result == 0:
            return "open"
        else:
            return "closed"
    except socket.timeout:
        return "filtered"
    except OSError:
        return "error"
    finally:
        sock.close()""", "python"
    )
    pace()

    info(f"{BRIGHT}SYN Scan (Half-Open Scan){RESET}")
    lesson_block(
        "A SYN scan sends a SYN packet but does NOT complete the handshake. "
        "If the target responds with SYN-ACK, the port is open and the "
        "scanner immediately sends a RST to tear down the connection."
    )
    pace()

    lesson_block(
        "This is faster and stealthier than a full connect scan because the "
        "connection is never fully established, so it may not be logged by "
        "the target. SYN scans require raw socket privileges (root/admin)."
    )
    pace()

    code_block(
        """# SYN Scan — half-open technique
# Three-way handshake is NOT completed:
#   Client ---SYN--->   Server
#   Client <--SYN/ACK-- Server   (port OPEN)
#   Client ---RST--->   Server   (tear down immediately)
#
# If server responds with RST: port CLOSED
# If no response: port FILTERED
#
# SYN scans require root privileges and raw sockets.
# In practice, tools like nmap handle this:
#   nmap -sS target_ip    (SYN scan — requires root)
#   nmap -sT target_ip    (TCP connect scan — no root needed)""", "bash"
    )
    nice_work("You now understand the two most common scan types!")
    pace()

    # ---------- Other scan types ----------
    sub_header("Additional Scan Types")
    info(f"{BRIGHT}UDP Scan (-sU){RESET}       — Probes UDP ports. Slower because UDP is connectionless; "
         f"an open port may not respond at all.")
    info(f"{BRIGHT}FIN Scan (-sF){RESET}       — Sends a FIN packet. Open ports silently drop it; "
         f"closed ports respond with RST.")
    info(f"{BRIGHT}XMAS Scan (-sX){RESET}      — Sets FIN, PSH, and URG flags. Similar logic to FIN scan.")
    print()
    pace()

    info(f"{BRIGHT}NULL Scan (-sN){RESET}      — Sends a packet with no flags set.")
    info(f"{BRIGHT}ACK Scan (-sA){RESET}       — Determines firewall rules; identifies filtered vs. "
         f"unfiltered ports.")
    info(f"{BRIGHT}Version Scan (-sV){RESET}   — Probes open ports to determine the service and version.")
    print()
    tip("For most beginner use cases, a TCP Connect scan (-sT) is all you need. The others are for advanced scenarios.")
    pace()

    # ---------- Service detection ----------
    sub_header("Service Detection and Banner Grabbing")
    lesson_block(
        "Once you know a port is open, the next step is to determine what "
        "service is running and its version."
    )
    lesson_block(
        "Many services send a 'banner' — a text string identifying "
        "themselves — when a connection is established. Grabbing this banner "
        "reveals the software name and version, which can be cross-referenced "
        "against CVE databases."
    )
    pace()

    code_block(
        """import socket

def grab_banner(host, port, timeout=3):
    \"\"\"Connect to a port and attempt to read the service banner.\"\"\"
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))

        # Some services send a banner immediately
        # Others require us to send something first
        banner = ""
        try:
            banner = sock.recv(1024).decode("utf-8", errors="replace").strip()
        except socket.timeout:
            # Try sending a probe for HTTP-like services
            sock.sendall(b"HEAD / HTTP/1.0\\r\\n\\r\\n")
            try:
                banner = sock.recv(4096).decode("utf-8", errors="replace").strip()
            except socket.timeout:
                pass
        sock.close()
        return banner if banner else "(no banner)"
    except (ConnectionRefusedError, socket.timeout, OSError) as e:
        return f"(error: {e})" """, "python"
    )
    pace()

    code_block(
        """def scan_with_banners(host, ports):
    \"\"\"Scan ports and grab banners for open ones.\"\"\"
    print(f"  Scanning {host}...\\n")
    print(f"  {'PORT':<8} {'STATE':<10} BANNER")
    print(f"  {'-'*60}")
    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        result = sock.connect_ex((host, port))
        sock.close()
        if result == 0:
            banner = grab_banner(host, port)
            # Truncate long banners for display
            display_banner = banner[:60] if len(banner) > 60 else banner
            print(f"  {port:<8} {'OPEN':<10} {display_banner}")

# Only scan hosts you own — use localhost for practice
# scan_with_banners("127.0.0.1", [21, 22, 25, 80, 443, 3306, 5432, 8080])""", "python"
    )
    nice_work("Banner grabbing is a key skill -- you are doing great!")
    pace()

    # ---------- OS Fingerprinting ----------
    sub_header("OS Fingerprinting Concepts")
    lesson_block(
        "OS fingerprinting is the process of determining the operating system "
        "running on a remote host by analyzing how it responds to network "
        "probes."
    )
    lesson_block(
        "Different operating systems implement TCP/IP slightly differently — "
        "variations in initial TTL values, TCP window sizes, and responses to "
        "unusual packets can identify the OS."
    )
    pace()

    info(f"{BRIGHT}Active Fingerprinting{RESET} — Send specially crafted packets and analyze "
         f"responses. Tools: nmap -O, xprobe2.")
    info(f"{BRIGHT}Passive Fingerprinting{RESET} — Observe normal network traffic without "
         f"sending probes. Tools: p0f, NetworkMiner.")
    print()
    pace()

    lesson_block(
        "Common OS indicators from network behavior:"
    )
    info(f"  Linux:   TTL=64,  Window Size=5840 or 14600")
    info(f"  Windows: TTL=128, Window Size=65535 or 8192")
    info(f"  macOS:   TTL=64,  Window Size=65535")
    info(f"  Cisco:   TTL=255")
    print()
    pace()

    # ---------- Using python-nmap ----------
    sub_header("Using python-nmap for Programmatic Scanning")
    lesson_block(
        "The python-nmap library provides a Python wrapper around the nmap "
        "command-line tool. It allows you to run scans programmatically and "
        "parse the results as Python data structures."
    )
    tip("nmap must be installed on the system for python-nmap to work.")
    pace()

    code_block(
        """import nmap  # pip install python-nmap

def comprehensive_scan(target, port_range="1-1024"):
    \"\"\"Run a comprehensive nmap scan with service detection.\"\"\"
    scanner = nmap.PortScanner()

    print(f"  Scanning {target} ports {port_range}...")
    print(f"  This may take a few minutes...\\n")

    # -sV: Version detection
    # -sC: Default scripts
    # -O:  OS detection (requires root)
    scanner.scan(target, port_range, arguments="-sV")

    for host in scanner.all_hosts():
        print(f"  Host: {host} ({scanner[host].hostname()})")
        print(f"  State: {scanner[host].state()}")

        for protocol in scanner[host].all_protocols():
            print(f"\\n  Protocol: {protocol}")
            ports = sorted(scanner[host][protocol].keys())
            print(f"  {'PORT':<8} {'STATE':<10} {'SERVICE':<15} VERSION")
            print(f"  {'-'*60}")
            for port in ports:
                port_info = scanner[host][protocol][port]
                state = port_info["state"]
                service = port_info["name"]
                version = port_info.get("version", "")
                product = port_info.get("product", "")
                ver_str = f"{product} {version}".strip()
                print(f"  {port:<8} {state:<10} {service:<15} {ver_str}")

# Only scan hosts you own or have authorization to scan
# comprehensive_scan("127.0.0.1", "1-1024")""", "python"
    )
    pace()

    # ---------- Building a multi-threaded scanner ----------
    sub_header("Building a Multi-Threaded Port Scanner")
    lesson_block(
        "Scanning thousands of ports sequentially is slow. Using Python's "
        "concurrent.futures module, we can scan many ports in parallel."
    )
    pace()

    code_block(
        """import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
import time

def scan_port(host, port, timeout=1.5):
    \"\"\"Scan a single port. Returns (port, state, banner).\"\"\"
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        if result == 0:
            # Try to grab banner
            banner = ""
            try:
                banner = sock.recv(512).decode("utf-8", errors="replace").strip()
            except (socket.timeout, OSError):
                pass
            sock.close()
            return (port, "open", banner)
        sock.close()
        return (port, "closed", "")
    except Exception:
        return (port, "error", "")""", "python"
    )
    pace()

    code_block(
        """def threaded_scan(host, start_port=1, end_port=1024, max_workers=100):
    \"\"\"Scan a range of ports using a thread pool.\"\"\"
    print(f"  Scanning {host} ports {start_port}-{end_port} "
          f"({max_workers} threads)...\\n")
    start = time.time()
    open_ports = []

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(scan_port, host, port): port
            for port in range(start_port, end_port + 1)
        }
        for future in as_completed(futures):
            port, state, banner = future.result()
            if state == "open":
                open_ports.append((port, banner))

    elapsed = time.time() - start
    open_ports.sort()

    print(f"  {'PORT':<8} {'STATE':<10} BANNER")
    print(f"  {'-'*50}")
    for port, banner in open_ports:
        display = banner[:40] if banner else ""
        print(f"  {port:<8} {'open':<10} {display}")
    print(f"\\n  Scanned {end_port - start_port + 1} ports "
          f"in {elapsed:.1f}s — {len(open_ports)} open")

# Only scan your own hosts!
# threaded_scan("127.0.0.1", 1, 1024)""", "python"
    )
    nice_work("You have built a multi-threaded scanner -- that is a real accomplishment!")
    pace()

    # ---------- Why it matters ----------
    why_it_matters(
        "Port scanning is how you discover your actual attack surface versus "
        "what you think is exposed. Organizations regularly find unauthorized "
        "services — rogue web servers, exposed databases, forgotten test "
        "services — running on their networks."
    )
    lesson_block(
        "Regular port scanning of your own infrastructure, compared against "
        "a known-good baseline, is a critical defensive practice."
    )
    pace()

    # ---------- Real-world scenario ----------
    scenario_block(
        "The Exposed MongoDB",
        "A company deployed a MongoDB instance for a development project and "
        "accidentally bound it to 0.0.0.0 (all interfaces) instead of "
        "127.0.0.1 (localhost only). MongoDB's default configuration had no "
        "authentication enabled. A routine port scan of their external IP "
        "range would have detected port 27017 open to the internet. Instead, "
        "attackers found it first, downloaded the entire database, and left a "
        "ransom note demanding Bitcoin."
    )
    pace()

    # ---------- Practice challenge ----------
    sub_header("Practice Challenge")
    lesson_block(
        "Build a port scanner that: (1) accepts a target host and port range, "
        "(2) uses multi-threading for speed, (3) grabs banners from open ports, "
        "and (4) identifies common services by port number."
    )
    lesson_block(
        "Output results in a structured format. Test only against localhost."
    )
    hint_text("Create a dictionary mapping well-known ports to service names.")
    hint_text("Use ThreadPoolExecutor with max_workers=100 for speed.")
    pace()

    code_block(
        """import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

WELL_KNOWN = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS",
    445: "SMB", 993: "IMAPS", 995: "POP3S", 3306: "MySQL",
    3389: "RDP", 5432: "PostgreSQL", 5900: "VNC", 6379: "Redis",
    8080: "HTTP-Alt", 8443: "HTTPS-Alt", 27017: "MongoDB",
}""", "python"
    )
    pace()

    code_block(
        """def identify_service(port, banner):
    \"\"\"Identify a service by port number and banner content.\"\"\"
    # Check banner first for more accurate identification
    banner_lower = banner.lower()
    if "ssh" in banner_lower:
        return "SSH"
    if "http" in banner_lower:
        return "HTTP"
    if "ftp" in banner_lower:
        return "FTP"
    if "smtp" in banner_lower:
        return "SMTP"
    if "mysql" in banner_lower:
        return "MySQL"
    if "postgresql" in banner_lower:
        return "PostgreSQL"
    # Fall back to well-known port mapping
    return WELL_KNOWN.get(port, "Unknown")

# Build on the threaded_scan function from the lesson above,
# adding service identification and structured output.

# threaded_scan("127.0.0.1", 1, 1024)""", "python"
    )

    if ask_yes_no("Mark this challenge as attempted?"):
        mark_challenge_complete(progress, module_key, "port_scanning_challenge")
        success("Challenge marked complete!")

    press_enter()
    mark_lesson_complete(progress, module_key, lesson_id)
    success("Lesson 2 complete: Port Scanning Deep Dive")
    press_enter()


# ---------------------------------------------------------------------------
# Lesson 3 — Checking for Outdated Software
# ---------------------------------------------------------------------------
def _lesson_outdated_software(progress):
    module_key = "module6"
    lesson_id = "outdated_software"

    section_header("Lesson 3: Checking for Outdated Software")
    learning_goal([
        "Understand why outdated software is one of the biggest security risks",
        "Compare software version strings in Python",
        "Extract versions from service banners automatically",
    ])
    disclaimer()

    # ---------- Why outdated software is dangerous ----------
    sub_header("Why Outdated Software is Dangerous")
    lesson_block(
        "Running outdated software is one of the most common and preventable "
        "security risks. When a vendor patches a vulnerability, the patch "
        "itself serves as a roadmap for attackers."
    )
    lesson_block(
        "They can reverse-engineer the fix to understand the vulnerability "
        "and build exploits. Systems that have not applied the patch are "
        "then trivially exploitable."
    )
    pace()

    lesson_block(
        "The Equifax breach of 2017, which exposed 147 million people's "
        "personal data, was caused by a known Apache Struts vulnerability "
        "(CVE-2017-5638) that had a patch available two months before the "
        "breach. The organization simply failed to apply it."
    )
    tip("Patch management is not glamorous, but it prevents more breaches than almost anything else.")
    pace()

    # ---------- Version comparison logic ----------
    sub_header("Version Comparison Logic")
    lesson_block(
        "Software versions typically follow semantic versioning: "
        "MAJOR.MINOR.PATCH (e.g., 2.4.51)."
    )
    lesson_block(
        "To determine if software is outdated, you need to compare the "
        "detected version against the latest known version. Python provides "
        "the 'packaging' library for robust version comparison."
    )
    pace()

    code_block(
        """from packaging import version  # pip install packaging

def is_outdated(current_ver, latest_ver):
    \"\"\"Check if the current version is older than the latest.\"\"\"
    try:
        current = version.parse(current_ver)
        latest = version.parse(latest_ver)
        if current < latest:
            print(f"  OUTDATED: {current_ver} < {latest_ver}")
            return True
        elif current == latest:
            print(f"  UP TO DATE: {current_ver}")
            return False
        else:
            print(f"  AHEAD: {current_ver} > {latest_ver} (custom build?)")
            return False
    except version.InvalidVersion as e:
        print(f"  Could not parse version: {e}")
        return None

# Examples
is_outdated("2.4.49", "2.4.54")   # True — outdated
is_outdated("8.0.31", "8.0.31")   # False — up to date
is_outdated("3.1.0", "2.9.5")     # False — ahead""", "python"
    )
    pace()

    code_block(
        """# Manual version comparison without 'packaging' library
def compare_versions(v1, v2):
    \"\"\"Compare two dotted version strings.\"\"\"
    parts1 = [int(x) for x in v1.split(".")]
    parts2 = [int(x) for x in v2.split(".")]
    # Pad shorter list with zeros
    max_len = max(len(parts1), len(parts2))
    parts1.extend([0] * (max_len - len(parts1)))
    parts2.extend([0] * (max_len - len(parts2)))
    for a, b in zip(parts1, parts2):
        if a < b:
            return -1  # v1 is older
        elif a > b:
            return 1   # v1 is newer
    return 0  # equal""", "python"
    )
    nice_work("You can now compare version strings like a pro!")
    pace()

    # ---------- Banner analysis ----------
    sub_header("Banner Analysis for Version Detection")
    lesson_block(
        "Many services embed their version number in the banner they send "
        "upon connection. By parsing these banners with regular expressions, "
        "we can extract version strings."
    )
    pace()

    code_block(
        """import re
import socket

# Patterns to extract version strings from common service banners
BANNER_PATTERNS = {
    "Apache": re.compile(r"Apache/([\\d.]+)"),
    "nginx": re.compile(r"nginx/([\\d.]+)"),
    "OpenSSH": re.compile(r"OpenSSH[_\\s]([\\d.p]+)"),
    "MySQL": re.compile(r"([\\d.]+)-(?:MySQL|MariaDB)"),
    "PostgreSQL": re.compile(r"PostgreSQL\\s([\\d.]+)"),
    "FTP": re.compile(r"(?:vsftpd|ProFTPD|Pure-FTPd)\\s([\\d.]+)"),
    "Microsoft-IIS": re.compile(r"Microsoft-IIS/([\\d.]+)"),
    "PHP": re.compile(r"PHP/([\\d.]+)"),
}

def extract_version(banner):
    \"\"\"Extract software name and version from a service banner.\"\"\"
    results = []
    for software, pattern in BANNER_PATTERNS.items():
        match = pattern.search(banner)
        if match:
            results.append((software, match.group(1)))
    return results""", "python"
    )
    pace()

    code_block(
        """# Example banners you might encounter
test_banners = [
    "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5",
    "HTTP/1.1 200 OK\\r\\nServer: Apache/2.4.49 (Unix)",
    "HTTP/1.1 200 OK\\r\\nServer: nginx/1.18.0",
    "220 (vsFTPd 3.0.3)",
    "5.7.38-MySQL",
]

for banner in test_banners:
    results = extract_version(banner)
    for software, ver in results:
        print(f"  Detected: {software} version {ver}")""", "python"
    )
    pace()

    # ---------- Building a version checker ----------
    sub_header("Building a Version Checker")
    lesson_block(
        "Let us combine banner grabbing, version extraction, and version "
        "comparison into a unified version checker."
    )
    lesson_block(
        "This checker uses a database of known latest versions to flag "
        "outdated software."
    )
    pace()

    code_block(
        """import socket
import re
from packaging import version

# Known latest versions (you would maintain this database)
LATEST_VERSIONS = {
    "Apache": "2.4.58",
    "nginx": "1.25.3",
    "OpenSSH": "9.5",
    "MySQL": "8.0.35",
    "PostgreSQL": "16.1",
    "PHP": "8.3.0",
    "Microsoft-IIS": "10.0",
}

BANNER_PATTERNS = {
    "Apache": re.compile(r"Apache/([\\d.]+)"),
    "nginx": re.compile(r"nginx/([\\d.]+)"),
    "OpenSSH": re.compile(r"OpenSSH[_\\s]([\\d.]+)"),
    "MySQL": re.compile(r"([\\d.]+)-MySQL"),
    "PostgreSQL": re.compile(r"PostgreSQL\\s([\\d.]+)"),
    "PHP": re.compile(r"PHP/([\\d.]+)"),
}""", "python"
    )
    pace()

    code_block(
        """def check_service_version(host, port, timeout=3):
    \"\"\"Connect, grab banner, extract version, and check if outdated.\"\"\"
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))

        # Try to receive banner
        banner = ""
        try:
            banner = sock.recv(1024).decode("utf-8", errors="replace")
        except socket.timeout:
            sock.sendall(b"HEAD / HTTP/1.0\\r\\nHost: target\\r\\n\\r\\n")
            try:
                banner = sock.recv(4096).decode("utf-8", errors="replace")
            except socket.timeout:
                pass
        sock.close()

        if not banner:
            return {"port": port, "status": "no_banner"}

        # Check all patterns
        for software, pattern in BANNER_PATTERNS.items():
            match = pattern.search(banner)
            if match:
                detected_ver = match.group(1)
                latest_ver = LATEST_VERSIONS.get(software)
                is_old = False
                if latest_ver:
                    try:
                        is_old = version.parse(detected_ver) < version.parse(latest_ver)
                    except version.InvalidVersion:
                        pass
                return {
                    "port": port,
                    "software": software,
                    "version": detected_ver,
                    "latest": latest_ver,
                    "outdated": is_old,
                    "banner_snippet": banner[:80],
                }

        return {"port": port, "status": "unknown_service", "banner": banner[:80]}

    except (ConnectionRefusedError, socket.timeout, OSError):
        return {"port": port, "status": "unreachable"}""", "python"
    )
    pace()

    code_block(
        """def audit_host(host, ports):
    \"\"\"Scan multiple ports and report outdated software.\"\"\"
    print(f"  Version Audit: {host}")
    print(f"  {'='*60}\\n")
    outdated_count = 0
    for port in ports:
        result = check_service_version(host, port)
        if "software" in result:
            status = "OUTDATED" if result["outdated"] else "OK"
            marker = "[!]" if result["outdated"] else "[+]"
            print(f"  {marker} Port {port}: {result['software']} "
                  f"{result['version']} (latest: {result['latest']}) "
                  f"— {status}")
            if result["outdated"]:
                outdated_count += 1
        elif result.get("status") == "no_banner":
            print(f"  [-] Port {port}: open but no banner received")
        elif result.get("status") == "unreachable":
            pass  # Skip closed/filtered ports silently

    print(f"\\n  Summary: {outdated_count} outdated service(s) found.")

# audit_host("127.0.0.1", [22, 80, 443, 3306, 5432, 8080])""", "python"
    )
    nice_work("You have a complete version-checking pipeline now!")
    pace()

    # ---------- Why it matters ----------
    why_it_matters(
        "Automated version checking across your infrastructure provides "
        "continuous visibility into your patch status. Many compliance "
        "frameworks (PCI-DSS, SOC 2, HIPAA) require regular vulnerability "
        "assessments, and outdated software detection is a core component."
    )
    lesson_block(
        "Building or deploying version-checking tools helps ensure that "
        "known vulnerabilities are identified and remediated before attackers "
        "can exploit them."
    )
    pace()

    # ---------- Real-world scenario ----------
    scenario_block(
        "The WannaCry Ransomware Attack",
        "In May 2017, the WannaCry ransomware infected over 230,000 computers "
        "in 150 countries. It exploited EternalBlue (CVE-2017-0144), a "
        "vulnerability in the Windows SMB protocol that Microsoft had patched "
        "two months earlier (MS17-010). Organizations that had applied the "
        "patch were unaffected. Those running outdated, unpatched Windows "
        "systems — including much of the UK's National Health Service — were "
        "devastated. Automated version and patch checking would have flagged "
        "these systems as vulnerable."
    )
    pace()

    # ---------- Practice challenge ----------
    sub_header("Practice Challenge")
    lesson_block(
        "Extend the version checker above to: (1) read a list of target "
        "hosts from a file, (2) scan common ports on each host, and "
        "(3) compare detected versions against a JSON database of latest "
        "versions."
    )
    lesson_block(
        "Generate a report in CSV format listing each finding."
    )
    hint_text("Use Python's csv module to write the output file.")
    hint_text("Store the latest versions database in a JSON file for easy updates.")
    pace()

    code_block(
        """import csv
import json
import socket

def load_version_db(path="version_db.json"):
    \"\"\"Load the latest versions database from JSON.\"\"\"
    with open(path) as f:
        return json.load(f)

def load_targets(path="targets.txt"):
    \"\"\"Load target hosts from a file (one per line: host:ports).\"\"\"
    targets = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if ":" in line:
                host, port_str = line.split(":", 1)
                ports = [int(p) for p in port_str.split(",")]
            else:
                host = line
                ports = [22, 80, 443, 3306, 8080]
            targets.append((host, ports))
    return targets""", "python"
    )
    pace()

    code_block(
        """def write_report(findings, output="version_report.csv"):
    \"\"\"Write scan findings to CSV.\"\"\"
    with open(output, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["Host", "Port", "Software", "Version",
                         "Latest", "Outdated", "Banner"])
        for finding in findings:
            writer.writerow([
                finding.get("host", ""),
                finding.get("port", ""),
                finding.get("software", "unknown"),
                finding.get("version", ""),
                finding.get("latest", ""),
                finding.get("outdated", ""),
                finding.get("banner_snippet", ""),
            ])
    print(f"  Report saved to {output}")

# Combine load_targets, audit_host, and write_report
# into a full pipeline. Only scan authorized hosts!""", "python"
    )

    if ask_yes_no("Mark this challenge as attempted?"):
        mark_challenge_complete(progress, module_key, "outdated_software_challenge")
        success("Challenge marked complete!")

    press_enter()
    mark_lesson_complete(progress, module_key, lesson_id)
    success("Lesson 3 complete: Checking for Outdated Software")
    press_enter()


# ---------------------------------------------------------------------------
# Lesson 4 — Configuration Auditing
# ---------------------------------------------------------------------------
def _lesson_config_auditing(progress):
    module_key = "module6"
    lesson_id = "config_auditing"

    section_header("Lesson 4: Configuration Auditing")
    learning_goal([
        "Understand what configuration auditing is and why misconfigs cause breaches",
        "Check for default credentials, TLS issues, and missing security headers",
        "Build a comprehensive audit tool in Python",
    ])
    disclaimer()

    # ---------- What is configuration auditing ----------
    sub_header("What is Configuration Auditing?")
    lesson_block(
        "Configuration auditing is the systematic review of system, network, "
        "and application settings to identify deviations from security best "
        "practices."
    )
    lesson_block(
        "Misconfigurations are the leading cause of cloud breaches and a "
        "major contributor to on-premises compromises. A system can run "
        "fully patched software and still be vulnerable if it is misconfigured."
    )
    pace()

    lesson_block(
        "Common misconfiguration categories include: default credentials, "
        "overly permissive access controls, unnecessary services running, "
        "and debug modes enabled in production."
    )
    lesson_block(
        "Others include unencrypted communications, missing security headers, "
        "and excessive information disclosure."
    )
    tip("Even one misconfiguration on an otherwise secure system can be the entry point for an attacker.")
    pace()

    # ---------- Default credentials ----------
    sub_header("Checking for Default Credentials")
    lesson_block(
        "Many devices, applications, and services ship with default usernames "
        "and passwords. If administrators do not change these during setup, "
        "attackers can gain access trivially."
    )
    lesson_block(
        "Default credential databases are publicly available, and automated "
        "tools test for them routinely."
    )
    pace()

    code_block(
        """import socket
import base64
import requests

# Common default credentials (for educational awareness)
DEFAULT_CREDS = {
    "SSH": [
        ("admin", "admin"), ("root", "root"), ("root", "toor"),
        ("admin", "password"), ("admin", "1234"),
    ],
    "MySQL": [
        ("root", ""), ("root", "root"), ("root", "mysql"),
        ("admin", "admin"),
    ],
    "PostgreSQL": [
        ("postgres", "postgres"), ("admin", "admin"),
    ],
    "HTTP-Basic": [
        ("admin", "admin"), ("admin", "password"), ("admin", "1234"),
        ("root", "root"), ("user", "user"),
    ],
    "FTP": [
        ("anonymous", ""), ("admin", "admin"), ("ftp", "ftp"),
    ],
}""", "python"
    )
    pace()

    code_block(
        """def check_http_default_creds(url, cred_list=None):
    \"\"\"Test for default HTTP Basic Authentication credentials.\"\"\"
    cred_list = cred_list or DEFAULT_CREDS["HTTP-Basic"]
    print(f"  Testing default credentials on {url}...")
    for username, password in cred_list:
        try:
            resp = requests.get(url, auth=(username, password), timeout=5)
            if resp.status_code == 200:
                print(f"  [!] SUCCESS: {username}:{password}")
                return (username, password)
            elif resp.status_code == 401:
                print(f"  [-] Failed: {username}:{password}")
            else:
                print(f"  [?] HTTP {resp.status_code}: {username}:{password}")
        except requests.RequestException as e:
            print(f"  Error: {e}")
            return None
    print("  [+] No default credentials found (good).")
    return None

# Only test against your own systems!
# check_http_default_creds("http://localhost:8080/admin")""", "python"
    )
    nice_work("You can now test for default credentials -- a common audit finding!")
    pace()

    # ---------- SSL/TLS Misconfigurations ----------
    sub_header("SSL/TLS Configuration Auditing")
    lesson_block(
        "SSL/TLS encryption protects data in transit, but misconfigured TLS "
        "can provide a false sense of security."
    )
    lesson_block(
        "Common TLS misconfigurations include: using outdated protocol "
        "versions (SSLv3, TLS 1.0, TLS 1.1), weak cipher suites, expired "
        "or self-signed certificates, and missing certificate chain elements."
    )
    pace()

    code_block(
        """import ssl
import socket
from datetime import datetime

def audit_tls(hostname, port=443):
    \"\"\"Audit TLS configuration of a remote host.\"\"\"
    findings = []
    print(f"  TLS Audit: {hostname}:{port}")
    print(f"  {'='*50}\\n")

    # 1. Test connection and get certificate
    context = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                protocol = ssock.version()
                cipher = ssock.cipher()

                print(f"  Protocol:  {protocol}")
                print(f"  Cipher:    {cipher[0]}")
                print(f"  Key Size:  {cipher[2]} bits")

                # Check protocol version
                if protocol in ("SSLv3", "TLSv1", "TLSv1.1"):
                    print(f"  [!] FINDING: Outdated protocol {protocol}")
                    findings.append(f"Outdated protocol: {protocol}")
                else:
                    print(f"  [+] Protocol version is acceptable")

                # Check cipher strength
                if cipher[2] < 128:
                    print(f"  [!] FINDING: Weak cipher key size ({cipher[2]} bits)")
                    findings.append(f"Weak cipher: {cipher[0]}")""", "python"
    )
    pace()

    code_block(
        """                # Check certificate expiry
                not_after = datetime.strptime(
                    cert["notAfter"], "%b %d %H:%M:%S %Y %Z"
                )
                days_left = (not_after - datetime.now()).days
                if days_left < 0:
                    print(f"  [!] FINDING: Certificate EXPIRED {abs(days_left)} days ago")
                    findings.append("Expired certificate")
                elif days_left < 30:
                    print(f"  [!] WARNING: Certificate expires in {days_left} days")
                    findings.append(f"Certificate expiring soon ({days_left} days)")
                else:
                    print(f"  [+] Certificate valid for {days_left} more days")

                # Check subject
                subject = dict(x[0] for x in cert["subject"])
                print(f"  Subject:   {subject.get('commonName', 'N/A')}")
                issuer = dict(x[0] for x in cert["issuer"])
                print(f"  Issuer:    {issuer.get('organizationName', 'N/A')}")

    except ssl.SSLCertVerificationError as e:
        print(f"  [!] FINDING: Certificate verification failed: {e}")
        findings.append(f"Certificate verification failure: {e}")
    except (ConnectionRefusedError, socket.timeout) as e:
        print(f"  Could not connect: {e}")
        return findings""", "python"
    )
    pace()

    code_block(
        """    # 2. Test for deprecated protocol support
    print(f"\\n  Testing deprecated protocol support...")
    deprecated = [
        ("SSLv3", ssl.PROTOCOL_TLS),
        ("TLSv1.0", ssl.PROTOCOL_TLS),
        ("TLSv1.1", ssl.PROTOCOL_TLS),
    ]
    for proto_name, _ in deprecated:
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            if proto_name == "TLSv1.0":
                ctx.maximum_version = ssl.TLSVersion.TLSv1
                ctx.minimum_version = ssl.TLSVersion.TLSv1
            elif proto_name == "TLSv1.1":
                ctx.maximum_version = ssl.TLSVersion.TLSv1_1
                ctx.minimum_version = ssl.TLSVersion.TLSv1_1
            else:
                continue  # SSLv3 not supported in modern Python

            with socket.create_connection((hostname, port), timeout=5) as s:
                with ctx.wrap_socket(s, server_hostname=hostname) as ss:
                    print(f"  [!] {proto_name} is SUPPORTED (should be disabled)")
                    findings.append(f"Deprecated protocol supported: {proto_name}")
        except (ssl.SSLError, OSError):
            print(f"  [+] {proto_name} is NOT supported (good)")

    print(f"\\n  Total findings: {len(findings)}")
    return findings

# Only test against your own domains!
# audit_tls("yourdomain.com")""", "python"
    )
    nice_work("TLS auditing is a valuable skill -- great job getting through that!")
    pace()

    # ---------- HTTP Security Headers ----------
    sub_header("Checking HTTP Security Headers")
    lesson_block(
        "Modern web applications should set several HTTP security headers to "
        "protect against common attacks. Missing headers are a frequent "
        "audit finding."
    )
    pace()

    code_block(
        """import requests

SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "description": "Enforces HTTPS connections (HSTS)",
        "severity": "HIGH",
        "recommendation": "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains",
    },
    "Content-Security-Policy": {
        "description": "Controls which resources the browser can load (CSP)",
        "severity": "HIGH",
        "recommendation": "Define a restrictive CSP policy for your application",
    },
    "X-Content-Type-Options": {
        "description": "Prevents MIME-type sniffing",
        "severity": "MEDIUM",
        "recommendation": "Add: X-Content-Type-Options: nosniff",
    },
    "X-Frame-Options": {
        "description": "Prevents clickjacking via iframes",
        "severity": "MEDIUM",
        "recommendation": "Add: X-Frame-Options: DENY or SAMEORIGIN",
    },
    "X-XSS-Protection": {
        "description": "Enables browser XSS filtering (legacy)",
        "severity": "LOW",
        "recommendation": "Add: X-XSS-Protection: 1; mode=block",
    },
    "Referrer-Policy": {
        "description": "Controls referrer information sent with requests",
        "severity": "LOW",
        "recommendation": "Add: Referrer-Policy: strict-origin-when-cross-origin",
    },
    "Permissions-Policy": {
        "description": "Controls browser feature access (camera, mic, etc.)",
        "severity": "LOW",
        "recommendation": "Define a Permissions-Policy for your application",
    },
}

# Headers that should NOT be present (information disclosure)
DANGEROUS_HEADERS = ["Server", "X-Powered-By", "X-AspNet-Version"]""", "python"
    )
    pace()

    code_block(
        """def audit_headers(url):
    \"\"\"Check a URL for security headers and information disclosure.\"\"\"
    print(f"  Security Header Audit: {url}")
    print(f"  {'='*60}\\n")

    try:
        resp = requests.get(url, timeout=10, allow_redirects=True)
    except requests.RequestException as e:
        print(f"  Could not connect: {e}")
        return

    missing = []
    present = []

    # Check for required security headers
    print(f"  {'-'*60}")
    print(f"  {'HEADER':<35} {'STATUS':<10} SEVERITY")
    print(f"  {'-'*60}")
    for header, details in SECURITY_HEADERS.items():
        if header.lower() in (h.lower() for h in resp.headers):
            value = resp.headers.get(header, "")
            print(f"  {header:<35} {'PRESENT':<10} --")
            present.append(header)
        else:
            severity = details["severity"]
            print(f"  {header:<35} {'MISSING':<10} {severity}")
            missing.append((header, details))""", "python"
    )
    pace()

    code_block(
        """    # Check for information disclosure
    print(f"\\n  Information Disclosure Headers:")
    print(f"  {'-'*60}")
    for header in DANGEROUS_HEADERS:
        value = resp.headers.get(header)
        if value:
            print(f"  [!] {header}: {value}  (consider removing)")
        else:
            print(f"  [+] {header}: not disclosed (good)")

    # Summary
    print(f"\\n  Summary: {len(present)} present, {len(missing)} missing")
    if missing:
        print(f"\\n  Recommendations:")
        for header, details in missing:
            print(f"    - {details['recommendation']}")

# Only test your own sites!
# audit_headers("https://yourdomain.com")""", "python"
    )
    pace()

    # ---------- Open services audit ----------
    sub_header("Auditing for Unnecessary Open Services")
    lesson_block(
        "Every running service increases the attack surface. An audit should "
        "identify services that are running but not needed, services exposed "
        "to the internet that should be internal-only, and services running "
        "with excessive privileges."
    )
    pace()

    code_block(
        """import socket
from concurrent.futures import ThreadPoolExecutor

# Services that should typically NOT be exposed to the internet
RISKY_SERVICES = {
    21: ("FTP", "Use SFTP instead. FTP transmits credentials in plaintext."),
    23: ("Telnet", "Use SSH instead. Telnet is unencrypted."),
    135: ("MSRPC", "Should not be internet-facing. Filter with firewall."),
    139: ("NetBIOS", "Should not be internet-facing. Major attack vector."),
    445: ("SMB", "Should not be internet-facing. WannaCry exploited this."),
    1433: ("MSSQL", "Database should not be internet-facing."),
    1521: ("Oracle", "Database should not be internet-facing."),
    3306: ("MySQL", "Database should not be internet-facing."),
    3389: ("RDP", "Use VPN + RDP. Direct RDP exposure is high risk."),
    5432: ("PostgreSQL", "Database should not be internet-facing."),
    5900: ("VNC", "Remote desktop should not be internet-facing."),
    6379: ("Redis", "Typically has no authentication. Never expose."),
    9200: ("Elasticsearch", "Often has no authentication. Never expose."),
    11211: ("Memcached", "Can be abused for DDoS amplification."),
    27017: ("MongoDB", "Often deployed without authentication."),
}""", "python"
    )
    pace()

    code_block(
        """def audit_open_services(host, port_range=None):
    \"\"\"Scan for risky services exposed on a host.\"\"\"
    ports_to_check = port_range or list(RISKY_SERVICES.keys())
    print(f"  Open Services Audit: {host}")
    print(f"  Checking {len(ports_to_check)} potentially risky ports...\\n")

    findings = []
    for port in ports_to_check:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex((host, port))
            sock.close()
            if result == 0:
                service, risk = RISKY_SERVICES.get(port, ("Unknown", "Review manually."))
                print(f"  [!] Port {port} OPEN — {service}")
                print(f"      Risk: {risk}")
                findings.append({"port": port, "service": service, "risk": risk})
        except (socket.timeout, OSError):
            pass

    if not findings:
        print(f"  [+] No risky services found exposed.")
    else:
        print(f"\\n  Total risky services found: {len(findings)}")
    return findings

# Only audit your own hosts!
# audit_open_services("127.0.0.1")""", "python"
    )
    nice_work("You now have a full set of configuration audit checks!")
    pace()

    # ---------- Building a comprehensive audit script ----------
    sub_header("Building a Comprehensive Audit Script")
    lesson_block(
        "A proper configuration audit combines multiple checks into a single "
        "report. Here is the skeleton of a comprehensive audit tool."
    )
    pace()

    code_block(
        """import json
from datetime import datetime

class SecurityAuditor:
    \"\"\"Comprehensive security configuration auditor.\"\"\"

    def __init__(self, target):
        self.target = target
        self.findings = []
        self.timestamp = datetime.now().isoformat()

    def add_finding(self, category, severity, title, description, recommendation):
        self.findings.append({
            "category": category,
            "severity": severity,
            "title": title,
            "description": description,
            "recommendation": recommendation,
        })

    def run_all_checks(self):
        \"\"\"Run all audit checks against the target.\"\"\"
        print(f"Starting security audit of {self.target}...")
        print(f"Timestamp: {self.timestamp}\\n")

        self._check_open_services()
        self._check_tls_config()
        self._check_http_headers()
        self._check_default_creds()

        self._print_report()

    def _check_open_services(self):
        print("  [1/4] Checking for risky open services...")
        # Use audit_open_services() from above

    def _check_tls_config(self):
        print("  [2/4] Auditing TLS configuration...")
        # Use audit_tls() from above

    def _check_http_headers(self):
        print("  [3/4] Checking HTTP security headers...")
        # Use audit_headers() from above

    def _check_default_creds(self):
        print("  [4/4] Testing for default credentials...")
        # Use check_http_default_creds() from above""", "python"
    )
    pace()

    code_block(
        """    def _print_report(self):
        print(f"\\n{'='*60}")
        print(f"  SECURITY AUDIT REPORT — {self.target}")
        print(f"  {self.timestamp}")
        print(f"{'='*60}\\n")

        by_severity = {"CRITICAL": [], "HIGH": [], "MEDIUM": [], "LOW": []}
        for f in self.findings:
            by_severity.get(f["severity"], []).append(f)

        for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            items = by_severity[severity]
            if items:
                print(f"  [{severity}] — {len(items)} finding(s)")
                for item in items:
                    print(f"    - {item['title']}: {item['description']}")
                    print(f"      Fix: {item['recommendation']}")
                print()

        print(f"  Total findings: {len(self.findings)}")

    def export_json(self, path="audit_report.json"):
        report = {
            "target": self.target,
            "timestamp": self.timestamp,
            "total_findings": len(self.findings),
            "findings": self.findings,
        }
        with open(path, "w") as f:
            json.dump(report, f, indent=2)
        print(f"  Report exported to {path}")

# Usage — only on authorized targets!
# auditor = SecurityAuditor("127.0.0.1")
# auditor.run_all_checks()
# auditor.export_json()""", "python"
    )
    pace()

    # ---------- Why it matters ----------
    why_it_matters(
        "Misconfiguration is consistently ranked in the OWASP Top 10 and is "
        "the number one cause of cloud security incidents. Automated "
        "configuration auditing catches issues that manual reviews miss."
    )
    lesson_block(
        "A single misconfigured S3 bucket or database exposed without "
        "authentication can result in a major data breach."
    )
    pace()

    # ---------- Real-world scenario ----------
    scenario_block(
        "The Capital One S3 Breach",
        "In 2019, a misconfigured web application firewall (WAF) at Capital "
        "One allowed an attacker to exploit a server-side request forgery "
        "(SSRF) vulnerability and access AWS IAM credentials via the EC2 "
        "metadata service. The overly permissive IAM role allowed the "
        "attacker to list and download S3 buckets containing over 100 million "
        "customer records. Proper configuration auditing — checking IAM "
        "policies, WAF rules, and metadata service access — would have "
        "identified multiple misconfigurations before the breach occurred."
    )
    pace()

    # ---------- Practice challenge ----------
    sub_header("Practice Challenge")
    lesson_block(
        "Build a complete configuration audit tool that: (1) checks for open "
        "risky services on a target, (2) audits TLS/SSL configuration, and "
        "(3) checks for missing HTTP security headers."
    )
    lesson_block(
        "Also: (4) test for common default credentials on discovered web "
        "services, and (5) generate a JSON report with all findings "
        "categorized by severity."
    )
    hint_text("Use the SecurityAuditor class skeleton above as a starting point.")
    hint_text("Import and call the individual check functions from earlier in this lesson.")
    hint_text("Add a command-line interface with argparse for the target and output file.")
    pace()

    code_block(
        """import argparse
import json
from datetime import datetime

def main():
    parser = argparse.ArgumentParser(description="Security Configuration Auditor")
    parser.add_argument("target", help="Target hostname or IP (must be authorized)")
    parser.add_argument("--ports", default="common",
                        help="Port range: 'common', 'all', or '80,443,8080'")
    parser.add_argument("--output", "-o", default="audit_report.json",
                        help="Output JSON report path")
    parser.add_argument("--skip-creds", action="store_true",
                        help="Skip default credential testing")
    args = parser.parse_args()

    # Initialize the auditor
    auditor = SecurityAuditor(args.target)

    # Parse port configuration
    if args.ports == "common":
        ports = [21, 22, 23, 80, 135, 139, 443, 445, 1433,
                 3306, 3389, 5432, 5900, 6379, 8080, 27017]
    elif args.ports == "all":
        ports = list(range(1, 65536))
    else:
        ports = [int(p) for p in args.ports.split(",")]

    # Run the audit
    auditor.run_all_checks()
    auditor.export_json(args.output)

    print(f"\\nAudit complete. Report saved to {args.output}")

if __name__ == "__main__":
    main()""", "python"
    )

    if ask_yes_no("Mark this challenge as attempted?"):
        mark_challenge_complete(progress, module_key, "config_auditing_challenge")
        success("Challenge marked complete!")

    press_enter()
    mark_lesson_complete(progress, module_key, lesson_id)
    success("Lesson 4 complete: Configuration Auditing")
    press_enter()


# ---------------------------------------------------------------------------
# Quiz
# ---------------------------------------------------------------------------
def _run_module_quiz(progress):
    questions = [
        {
            "q": "What does CVE stand for?",
            "options": [
                "A) Common Vulnerabilities and Exposures",
                "B) Computer Virus Encyclopedia",
                "C) Cybersecurity Validation Engine",
                "D) Certified Vulnerability Examiner",
            ],
            "answer": "a",
            "explanation": (
                "CVE stands for Common Vulnerabilities and Exposures — a "
                "globally recognized identifier system for publicly known "
                "security vulnerabilities."
            ),
        },
        {
            "q": "A CVSS score of 9.5 indicates what severity level?",
            "options": [
                "A) Low",
                "B) Medium",
                "C) High",
                "D) Critical",
            ],
            "answer": "d",
            "explanation": (
                "CVSS scores of 9.0-10.0 are rated Critical. These "
                "vulnerabilities should be addressed with the highest urgency."
            ),
        },
        {
            "q": "What is the key difference between a TCP Connect scan and a SYN scan?",
            "options": [
                "A) SYN scans are slower but more accurate",
                "B) TCP Connect completes the full handshake; SYN does not",
                "C) TCP Connect requires root privileges; SYN does not",
                "D) SYN scans only work on UDP ports",
            ],
            "answer": "b",
            "explanation": (
                "A TCP Connect scan completes the full three-way handshake "
                "(SYN, SYN-ACK, ACK), while a SYN scan sends a RST after "
                "receiving SYN-ACK, never completing the connection."
            ),
        },
        {
            "q": "Why is banner grabbing useful during vulnerability scanning?",
            "options": [
                "A) It provides the administrator's email address",
                "B) It reveals the software name and version running on a port",
                "C) It encrypts the connection for safe scanning",
                "D) It automatically patches vulnerable services",
            ],
            "answer": "b",
            "explanation": (
                "Banner grabbing reveals the service software and version, "
                "which can be cross-referenced against CVE databases to "
                "identify known vulnerabilities."
            ),
        },
        {
            "q": "Which HTTP security header prevents clickjacking attacks?",
            "options": [
                "A) Content-Security-Policy",
                "B) X-Content-Type-Options",
                "C) X-Frame-Options",
                "D) Strict-Transport-Security",
            ],
            "answer": "c",
            "explanation": (
                "X-Frame-Options (DENY or SAMEORIGIN) prevents a page from "
                "being loaded inside an iframe, which is the basis of "
                "clickjacking attacks."
            ),
        },
        {
            "q": "Why should database ports (3306, 5432, 27017) NOT be exposed to the internet?",
            "options": [
                "A) They are too slow for remote connections",
                "B) They use outdated encryption algorithms",
                "C) They are often configured without authentication and are high-value targets",
                "D) They conflict with HTTP traffic",
            ],
            "answer": "c",
            "explanation": (
                "Database services are often deployed with default or no "
                "authentication. Exposing them to the internet allows "
                "attackers to connect directly, steal data, or deploy ransomware."
            ),
        },
        {
            "q": "What does the Strict-Transport-Security (HSTS) header do?",
            "options": [
                "A) Encrypts all files on the server",
                "B) Forces browsers to use HTTPS for all future connections to the domain",
                "C) Prevents SQL injection attacks",
                "D) Enables two-factor authentication",
            ],
            "answer": "b",
            "explanation": (
                "HSTS tells browsers to always use HTTPS when connecting to "
                "the domain, preventing protocol downgrade attacks and "
                "insecure HTTP connections."
            ),
        },
        {
            "q": "Which of the following is the BEST first step when a critical CVE is announced "
                 "for software you use?",
            "options": [
                "A) Immediately shut down all affected servers",
                "B) Wait for your next scheduled patch window",
                "C) Determine which systems are affected, assess exposure, and prioritize patching",
                "D) Ignore it until an exploit is publicly available",
            ],
            "answer": "c",
            "explanation": (
                "The best response is to identify affected systems, assess "
                "whether they are exposed, apply compensating controls if "
                "needed, and prioritize patching based on risk. Blind "
                "shutdown or waiting are both suboptimal responses."
            ),
        },
    ]
    run_quiz(questions, "vuln_scanning_quiz", "module6", progress)


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------
def run(progress):
    """Main entry point called from the menu system."""
    module_key = "module6"
    while True:
        choice = show_menu("Module 6: Vulnerability Scanning", [
            ("understanding_vulns", "Lesson 1: Understanding Vulnerabilities"),
            ("port_scanning", "Lesson 2: Port Scanning Deep Dive"),
            ("outdated_software", "Lesson 3: Checking for Outdated Software"),
            ("config_auditing", "Lesson 4: Configuration Auditing"),
            ("quiz", "Take the Quiz"),
        ])
        if choice == "back":
            return
        if choice == "quit":
            raise SystemExit

        if choice == "understanding_vulns":
            _lesson_understanding_vulns(progress)
        elif choice == "port_scanning":
            _lesson_port_scanning(progress)
        elif choice == "outdated_software":
            _lesson_outdated_software(progress)
        elif choice == "config_auditing":
            _lesson_config_auditing(progress)
        elif choice == "quiz":
            _run_module_quiz(progress)
