"""
Exercise runner for JJ's LAB.
Provides interactive coding challenges that users can attempt in-app.
"""

import textwrap
from utils.display import (
    section_header, sub_header, lesson_block, code_block, info, success,
    error, warning, hint_text, press_enter, show_menu, ask_yes_no,
    C, G, Y, R, RESET, BRIGHT, DIM
)
from utils.progress import mark_challenge_complete
from utils.sandbox import _free_code as test_code_interactive


CHALLENGES = {
    "module1": [
        {
            "id": "m1_port_checker",
            "title": "Build a Port Checker",
            "difficulty": "Beginner",
            "description": (
                "Write a Python function that takes a hostname and a list of ports, "
                "checks which ports are open using socket connections, and returns "
                "a list of open ports. Use a timeout of 1 second."
            ),
            "hints": [
                "Use socket.socket(socket.AF_INET, socket.SOCK_STREAM)",
                "Set a timeout with sock.settimeout(1)",
                "Use sock.connect_ex() — it returns 0 if the port is open",
            ],
            "solution": textwrap.dedent("""\
                import socket

                def check_ports(host, ports):
                    open_ports = []
                    for port in ports:
                        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        sock.settimeout(1)
                        result = sock.connect_ex((host, port))
                        if result == 0:
                            open_ports.append(port)
                        sock.close()
                    return open_ports

                # Test it
                open_ports = check_ports("127.0.0.1", [80, 443, 5050, 8080])
                print(f"Open ports: {open_ports}")
            """),
            "test_instructions": (
                "Start the vulnerable app (python vulnerable_app/app.py) and then "
                "test your function against 127.0.0.1 — port 5050 should show as open."
            ),
        },
        {
            "id": "m1_log_parser",
            "title": "Parse Apache Access Logs",
            "difficulty": "Beginner",
            "description": (
                "Write a function that parses Apache-style access log lines and "
                "extracts the IP address, HTTP method, URL path, and status code. "
                "Return a list of dictionaries."
            ),
            "hints": [
                "Apache log format: '192.168.1.1 - - [date] \"GET /path HTTP/1.1\" 200 1234'",
                "Use re.match() with named groups: (?P<ip>...)",
                "The pattern for IP is: \\d+\\.\\d+\\.\\d+\\.\\d+",
            ],
            "solution": textwrap.dedent("""\
                import re

                def parse_access_log(lines):
                    pattern = (
                        r'(?P<ip>\\d+\\.\\d+\\.\\d+\\.\\d+) - - '
                        r'\\[(?P<date>[^\\]]+)\\] '
                        r'"(?P<method>\\w+) (?P<path>\\S+) \\S+" '
                        r'(?P<status>\\d+) (?P<size>\\d+)'
                    )
                    results = []
                    for line in lines:
                        m = re.match(pattern, line)
                        if m:
                            results.append(m.groupdict())
                    return results

                # Test data
                sample_logs = [
                    '192.168.1.100 - - [13/Feb/2026:10:00:00] "GET /index.html HTTP/1.1" 200 5432',
                    '10.0.0.5 - - [13/Feb/2026:10:00:01] "POST /login HTTP/1.1" 401 243',
                    '192.168.1.100 - - [13/Feb/2026:10:00:02] "GET /admin HTTP/1.1" 403 128',
                ]
                for entry in parse_access_log(sample_logs):
                    print(entry)
            """),
            "test_instructions": "Run with the sample data above and verify the parsed output.",
        },
    ],
    "module2": [
        {
            "id": "m2_threaded_scanner",
            "title": "Build a Threaded Port Scanner",
            "difficulty": "Intermediate",
            "description": (
                "Upgrade the basic port scanner to use threading for speed. "
                "Scan ports 1-1024 on localhost using a thread pool. Print open "
                "ports as they're found, and report the total scan time."
            ),
            "hints": [
                "Use concurrent.futures.ThreadPoolExecutor",
                "Use max_workers=50 for reasonable speed",
                "Track time with time.time() before and after",
            ],
            "solution": textwrap.dedent("""\
                import socket
                import time
                from concurrent.futures import ThreadPoolExecutor, as_completed

                def scan_port(host, port):
                    try:
                        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        sock.settimeout(0.5)
                        result = sock.connect_ex((host, port))
                        sock.close()
                        return port if result == 0 else None
                    except:
                        return None

                def threaded_scan(host, port_range, workers=50):
                    open_ports = []
                    start = time.time()

                    with ThreadPoolExecutor(max_workers=workers) as executor:
                        futures = {
                            executor.submit(scan_port, host, port): port
                            for port in port_range
                        }
                        for future in as_completed(futures):
                            result = future.result()
                            if result:
                                open_ports.append(result)
                                print(f"  Port {result} is OPEN")

                    elapsed = time.time() - start
                    print(f"\\nScanned {len(port_range)} ports in {elapsed:.2f}s")
                    print(f"Open ports: {sorted(open_ports)}")
                    return sorted(open_ports)

                threaded_scan("127.0.0.1", range(1, 1025))
            """),
            "test_instructions": (
                "Run the scanner against 127.0.0.1 with the vulnerable app running. "
                "You should see port 5050 as open. The threaded version should be "
                "significantly faster than scanning sequentially."
            ),
        },
    ],
    "module3": [
        {
            "id": "m3_sqli_detector",
            "title": "Build a SQL Injection Detector",
            "difficulty": "Intermediate",
            "description": (
                "Write a function that analyzes a string input and detects common "
                "SQL injection patterns. Return True if the input looks like it "
                "contains SQLi payloads. Check for: UNION SELECT, OR 1=1, comment "
                "sequences (-- and /*), single quotes in suspicious contexts, "
                "and common SQLi keywords."
            ),
            "hints": [
                "Use re.search() with re.IGNORECASE",
                "Check for patterns like: ' OR ', 'UNION SELECT', '--', '/*'",
                "Watch for encoded variants: %27 (URL-encoded quote)",
            ],
            "solution": textwrap.dedent("""\
                import re

                SQL_PATTERNS = [
                    r"('\\s*(OR|AND)\\s+.*=.*)",           # ' OR 1=1
                    r"(UNION\\s+SELECT)",                   # UNION SELECT
                    r"(--\\s*$|/\\*)",                      # SQL comments
                    r"(;\\s*(DROP|DELETE|UPDATE|INSERT))",   # Piggyback queries
                    r"(\\b(EXEC|EXECUTE|xp_)\\b)",          # Stored procedures
                    r"(%27|%23|%3B)",                       # URL-encoded chars
                    r"(\\bSLEEP\\s*\\(|\\bBENCHMARK\\s*\\()",  # Time-based
                ]

                def detect_sqli(user_input):
                    for pattern in SQL_PATTERNS:
                        if re.search(pattern, user_input, re.IGNORECASE):
                            return True
                    return False

                # Test cases
                test_inputs = [
                    "john",                          # Clean
                    "' OR '1'='1",                   # Classic SQLi
                    "admin'--",                      # Comment injection
                    "1 UNION SELECT * FROM users",   # Union-based
                    "'; DROP TABLE users;--",        # Piggyback
                    "search term",                   # Clean
                    "1' AND SLEEP(5)--",             # Time-based
                ]
                for inp in test_inputs:
                    result = detect_sqli(inp)
                    status = "BLOCKED" if result else "ALLOWED"
                    print(f"  [{status}] {inp}")
            """),
            "test_instructions": "Run the test cases and verify that malicious inputs are detected.",
        },
    ],
    "module4": [
        {
            "id": "m4_strength_checker",
            "title": "Build a Password Strength Checker",
            "difficulty": "Beginner",
            "description": (
                "Create a password strength checker that scores passwords on: "
                "length (min 8, bonus for 12+, 16+), character diversity "
                "(uppercase, lowercase, digits, special chars), and common "
                "password list checking. Return a score 0-100 and a rating."
            ),
            "hints": [
                "Use string module for character sets",
                "Check against a list of common passwords like: password, 123456, qwerty",
                "Calculate entropy: log2(charset_size ^ length)",
            ],
            "solution": textwrap.dedent("""\
                import re
                import math

                COMMON_PASSWORDS = {
                    "password", "123456", "12345678", "qwerty", "abc123",
                    "monkey", "master", "dragon", "111111", "baseball",
                    "iloveyou", "trustno1", "sunshine", "letmein", "welcome",
                    "password1", "admin", "login", "starwars", "123456789",
                }

                def check_strength(password):
                    score = 0
                    feedback = []

                    # Length scoring
                    length = len(password)
                    if length >= 8: score += 15
                    if length >= 12: score += 15
                    if length >= 16: score += 10
                    if length < 8:
                        feedback.append("Too short — use at least 8 characters")

                    # Character diversity
                    has_lower = bool(re.search(r'[a-z]', password))
                    has_upper = bool(re.search(r'[A-Z]', password))
                    has_digit = bool(re.search(r'\\d', password))
                    has_special = bool(re.search(r'[!@#$%^&*(),.?\":{}|<>]', password))

                    charset_size = 0
                    if has_lower: score += 10; charset_size += 26
                    if has_upper: score += 10; charset_size += 26
                    if has_digit: score += 10; charset_size += 10
                    if has_special: score += 15; charset_size += 32

                    if not has_upper: feedback.append("Add uppercase letters")
                    if not has_special: feedback.append("Add special characters")

                    # Entropy bonus
                    if charset_size and length:
                        entropy = length * math.log2(charset_size)
                        if entropy > 60: score += 15

                    # Common password check
                    if password.lower() in COMMON_PASSWORDS:
                        score = max(0, score - 50)
                        feedback.append("This is a commonly used password!")

                    # Repeated characters penalty
                    if re.search(r'(.)\\1{2,}', password):
                        score -= 10
                        feedback.append("Avoid repeated characters")

                    score = max(0, min(100, score))

                    if score >= 80: rating = "Strong"
                    elif score >= 60: rating = "Moderate"
                    elif score >= 40: rating = "Weak"
                    else: rating = "Very Weak"

                    return {"score": score, "rating": rating, "feedback": feedback}

                # Test it
                test_passwords = ["password", "Hello123", "C0mpl3x!Pass#2026", "ab", "aaaaaaa"]
                for pw in test_passwords:
                    result = check_strength(pw)
                    print(f"  {pw:25s} → {result['score']:3d}/100 ({result['rating']})")
                    for f in result['feedback']:
                        print(f"    ⚠ {f}")
            """),
            "test_instructions": "Run the strength checker with various passwords and verify scoring.",
            "test_cases": [
                {
                    "input": "",
                    "expected_output": "Very Weak",
                    "description": "Weak password 'password' scores Very Weak",
                },
                {
                    "input": "",
                    "expected_output": "Strong",
                    "description": "Complex password scores Strong",
                },
            ],
            "starter_code": (
                "# Build a password strength checker\n"
                "# It should print the rating: Very Weak, Weak, Moderate, or Strong\n"
                "# Test with: 'password' (should be Very Weak) and 'C0mpl3x!Pass#2026' (should be Strong)\n"
                "\n"
                "def check_strength(password):\n"
                "    # Your code here\n"
                "    pass\n"
                "\n"
                "# Test cases\n"
                "result1 = check_strength('password')\n"
                "print(result1['rating'])\n"
                "result2 = check_strength('C0mpl3x!Pass#2026')\n"
                "print(result2['rating'])\n"
            ),
        },
    ],
    "module5": [
        {
            "id": "m5_dns_recon",
            "title": "Build a DNS Reconnaissance Tool",
            "difficulty": "Intermediate",
            "description": (
                "Write a function that takes a domain name and performs: "
                "forward DNS lookup (A records), reverse DNS lookup, and "
                "checks for common subdomains (www, mail, ftp, dev, staging, api). "
                "Print a formatted report."
            ),
            "hints": [
                "Use socket.getaddrinfo() for forward lookups",
                "Use socket.gethostbyaddr() for reverse lookups",
                "Wrap each lookup in try/except for graceful failures",
            ],
            "solution": textwrap.dedent("""\
                import socket

                COMMON_SUBDOMAINS = ["www", "mail", "ftp", "dev", "staging",
                                     "api", "admin", "test", "blog", "shop"]

                def dns_recon(domain):
                    print(f"\\n  DNS Reconnaissance: {domain}")
                    print(f"  {'=' * 40}")

                    # Forward lookup
                    try:
                        results = socket.getaddrinfo(domain, None)
                        ips = set(r[4][0] for r in results)
                        print(f"\\n  A Records:")
                        for ip in ips:
                            print(f"    {domain} → {ip}")
                            # Reverse lookup
                            try:
                                hostname = socket.gethostbyaddr(ip)[0]
                                print(f"    {ip} → {hostname} (reverse)")
                            except socket.herror:
                                print(f"    {ip} → No reverse DNS")
                    except socket.gaierror:
                        print(f"  Could not resolve {domain}")
                        return

                    # Subdomain enumeration
                    print(f"\\n  Subdomain Check:")
                    for sub in COMMON_SUBDOMAINS:
                        fqdn = f"{sub}.{domain}"
                        try:
                            ip = socket.gethostbyname(fqdn)
                            print(f"    [FOUND] {fqdn} → {ip}")
                        except socket.gaierror:
                            print(f"    [-----] {fqdn}")

                # Test with a domain you own
                dns_recon("example.com")
            """),
            "test_instructions": (
                "Test with 'localhost' or a domain you own. For safe practice, "
                "'example.com' is an IANA-reserved domain you can test against."
            ),
        },
    ],
    "module6": [
        {
            "id": "m6_header_auditor",
            "title": "Build an HTTP Header Security Auditor",
            "difficulty": "Intermediate",
            "description": (
                "Create a function that fetches HTTP headers from a URL and "
                "checks for the presence and correctness of security headers: "
                "Strict-Transport-Security, Content-Security-Policy, "
                "X-Content-Type-Options, X-Frame-Options, and Referrer-Policy. "
                "Score the site and provide recommendations."
            ),
            "hints": [
                "Use requests.get() to fetch headers",
                "Check both presence and values (e.g., X-Content-Type-Options should be 'nosniff')",
                "Score: +20 per correct header, -10 for missing critical ones",
            ],
            "solution": textwrap.dedent("""\
                import requests

                EXPECTED_HEADERS = {
                    "Strict-Transport-Security": {
                        "required": True,
                        "check": lambda v: "max-age" in v.lower(),
                        "fix": "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains",
                    },
                    "Content-Security-Policy": {
                        "required": True,
                        "check": lambda v: len(v) > 0,
                        "fix": "Add a Content-Security-Policy header to prevent XSS",
                    },
                    "X-Content-Type-Options": {
                        "required": True,
                        "check": lambda v: v.lower() == "nosniff",
                        "fix": "Add: X-Content-Type-Options: nosniff",
                    },
                    "X-Frame-Options": {
                        "required": True,
                        "check": lambda v: v.upper() in ("DENY", "SAMEORIGIN"),
                        "fix": "Add: X-Frame-Options: DENY",
                    },
                    "Referrer-Policy": {
                        "required": False,
                        "check": lambda v: len(v) > 0,
                        "fix": "Add: Referrer-Policy: strict-origin-when-cross-origin",
                    },
                }

                def audit_headers(url):
                    print(f"\\n  Header Audit: {url}")
                    print(f"  {'=' * 50}")
                    try:
                        resp = requests.get(url, timeout=5)
                    except Exception as e:
                        print(f"  Error: {e}")
                        return

                    score = 0
                    total = len(EXPECTED_HEADERS)

                    for name, config in EXPECTED_HEADERS.items():
                        value = resp.headers.get(name)
                        if value and config["check"](value):
                            print(f"  [PASS] {name}: {value[:60]}")
                            score += 1
                        elif value:
                            print(f"  [WARN] {name}: {value[:60]} (misconfigured)")
                            print(f"         → {config['fix']}")
                        else:
                            print(f"  [FAIL] {name}: MISSING")
                            print(f"         → {config['fix']}")

                    pct = score / total * 100
                    print(f"\\n  Score: {score}/{total} ({pct:.0f}%)")

                # Test against the local vulnerable app
                audit_headers("http://127.0.0.1:5050")
            """),
            "test_instructions": (
                "Start the vulnerable app and run this against http://127.0.0.1:5050. "
                "It should show several missing security headers."
            ),
        },
    ],
    "module7": [
        {
            "id": "m7_brute_force_detector",
            "title": "Build a Brute Force Detector",
            "difficulty": "Intermediate",
            "description": (
                "Write a script that parses authentication log lines and detects "
                "brute force attempts. Flag any IP address that has more than 5 "
                "failed login attempts within a 60-second window. Output the "
                "offending IPs with timestamps and attempt counts."
            ),
            "hints": [
                "Use a defaultdict(list) to track failed attempts per IP",
                "Parse timestamps with datetime.strptime()",
                "Sliding window: check if any 5 attempts fall within 60 seconds",
            ],
            "solution": textwrap.dedent("""\
                import re
                from datetime import datetime, timedelta
                from collections import defaultdict

                SAMPLE_LOGS = \"\"\"
                2026-02-13 10:00:01 auth FAILED login for user admin from 192.168.1.50
                2026-02-13 10:00:03 auth FAILED login for user admin from 192.168.1.50
                2026-02-13 10:00:05 auth FAILED login for user root from 192.168.1.50
                2026-02-13 10:00:08 auth SUCCESS login for user john from 10.0.0.5
                2026-02-13 10:00:10 auth FAILED login for user admin from 192.168.1.50
                2026-02-13 10:00:15 auth FAILED login for user test from 192.168.1.50
                2026-02-13 10:00:20 auth FAILED login for user admin from 192.168.1.50
                2026-02-13 10:00:25 auth FAILED login for user admin from 192.168.1.100
                2026-02-13 10:05:00 auth FAILED login for user admin from 192.168.1.100
                \"\"\".strip()

                def detect_brute_force(log_text, threshold=5, window_seconds=60):
                    pattern = (
                        r'(\\d{4}-\\d{2}-\\d{2} \\d{2}:\\d{2}:\\d{2}) '
                        r'auth FAILED login for user (\\w+) from (\\d+\\.\\d+\\.\\d+\\.\\d+)'
                    )
                    failed_attempts = defaultdict(list)
                    alerts = []

                    for line in log_text.split('\\n'):
                        m = re.search(pattern, line)
                        if m:
                            ts = datetime.strptime(m.group(1), '%Y-%m-%d %H:%M:%S')
                            ip = m.group(3)
                            failed_attempts[ip].append(ts)

                    for ip, timestamps in failed_attempts.items():
                        timestamps.sort()
                        # Sliding window check
                        for i in range(len(timestamps)):
                            window_end = timestamps[i] + timedelta(seconds=window_seconds)
                            count = sum(1 for t in timestamps if timestamps[i] <= t <= window_end)
                            if count >= threshold:
                                alerts.append({
                                    'ip': ip,
                                    'count': len(timestamps),
                                    'first_seen': timestamps[0],
                                    'last_seen': timestamps[-1],
                                })
                                break

                    return alerts

                alerts = detect_brute_force(SAMPLE_LOGS)
                for alert in alerts:
                    print(f"  ALERT: {alert['ip']} — {alert['count']} failed attempts")
                    print(f"         First: {alert['first_seen']}")
                    print(f"         Last:  {alert['last_seen']}")
            """),
            "test_instructions": "Run with the embedded sample logs. IP 192.168.1.50 should trigger an alert.",
            "test_cases": [
                {
                    "input": "",
                    "expected_output": "192.168.1.50",
                    "description": "Detects brute force IP 192.168.1.50",
                },
                {
                    "input": "",
                    "expected_output": "ALERT",
                    "description": "Outputs ALERT for offending IPs",
                },
            ],
            "starter_code": (
                "# Build a brute force detector\n"
                "# Parse auth logs and flag IPs with 5+ failed logins in 60 seconds\n"
                "# Print: ALERT: <ip> -- <count> failed attempts\n"
                "\n"
                "SAMPLE_LOGS = \"\"\"\n"
                "2026-02-13 10:00:01 auth FAILED login for user admin from 192.168.1.50\n"
                "2026-02-13 10:00:03 auth FAILED login for user admin from 192.168.1.50\n"
                "2026-02-13 10:00:05 auth FAILED login for user root from 192.168.1.50\n"
                "2026-02-13 10:00:10 auth FAILED login for user admin from 192.168.1.50\n"
                "2026-02-13 10:00:15 auth FAILED login for user test from 192.168.1.50\n"
                "2026-02-13 10:00:20 auth FAILED login for user admin from 192.168.1.50\n"
                "\"\"\".strip()\n"
            ),
        },
    ],
    "module8": [
        {
            "id": "m8_secure_config",
            "title": "Build a Secure Configuration Loader",
            "difficulty": "Intermediate",
            "description": (
                "Create a configuration loader that: reads settings from environment "
                "variables first, falls back to a .env file, never logs or prints "
                "secret values, and validates that required settings are present. "
                "Include a function that masks secret values for safe logging."
            ),
            "hints": [
                "Use os.environ.get() for environment variables",
                "Parse .env files line by line: KEY=VALUE format",
                "Mask secrets: show first 2 and last 2 chars, mask the rest with *",
            ],
            "solution": textwrap.dedent("""\
                import os
                import re

                class SecureConfig:
                    def __init__(self, required_keys=None):
                        self._config = {}
                        self._secret_keys = set()
                        self._required = required_keys or []

                    def load_env_file(self, filepath=".env"):
                        if not os.path.exists(filepath):
                            return
                        with open(filepath) as f:
                            for line in f:
                                line = line.strip()
                                if line and not line.startswith('#') and '=' in line:
                                    key, _, value = line.partition('=')
                                    key = key.strip()
                                    value = value.strip().strip('"').strip("'")
                                    if key not in os.environ:  # Env vars take priority
                                        self._config[key] = value

                    def load_env_vars(self, prefix="APP_"):
                        for key, value in os.environ.items():
                            if key.startswith(prefix):
                                self._config[key] = value

                    def mark_secret(self, *keys):
                        self._secret_keys.update(keys)

                    def get(self, key, default=None):
                        return self._config.get(key, os.environ.get(key, default))

                    def mask_value(self, value):
                        if len(value) <= 4:
                            return "****"
                        return value[:2] + "*" * (len(value) - 4) + value[-2:]

                    def validate(self):
                        missing = [k for k in self._required if not self.get(k)]
                        if missing:
                            raise ValueError(f"Missing required config: {', '.join(missing)}")
                        return True

                    def safe_dump(self):
                        print("  Configuration (secrets masked):")
                        for key, value in sorted(self._config.items()):
                            if key in self._secret_keys:
                                print(f"    {key} = {self.mask_value(value)}")
                            else:
                                print(f"    {key} = {value}")

                # Usage
                config = SecureConfig(required_keys=["APP_DB_HOST"])
                config._config = {
                    "APP_DB_HOST": "localhost",
                    "APP_DB_PORT": "5432",
                    "APP_DB_PASSWORD": "super_secret_password_123",
                    "APP_API_KEY": "sk-abc123xyz789",
                }
                config.mark_secret("APP_DB_PASSWORD", "APP_API_KEY")
                config.safe_dump()
            """),
            "test_instructions": "Run and verify that secret values are properly masked in the output.",
            "test_cases": [
                {
                    "input": "",
                    "expected_output": "localhost",
                    "description": "Config loads APP_DB_HOST correctly",
                },
                {
                    "input": "",
                    "expected_output": "****",
                    "description": "Secret values are masked in output",
                },
            ],
            "starter_code": (
                "# Build a secure configuration loader\n"
                "# It should mask secret values when printing\n"
                "# Mask: show first 2 and last 2 chars, replace middle with *\n"
                "\n"
                "class SecureConfig:\n"
                "    def __init__(self):\n"
                "        self._config = {}\n"
                "        self._secret_keys = set()\n"
                "\n"
                "    # Add your methods here\n"
                "\n"
                "config = SecureConfig()\n"
                "config._config = {'APP_DB_HOST': 'localhost', 'APP_DB_PASSWORD': 'super_secret_password_123'}\n"
                "config._secret_keys = {'APP_DB_PASSWORD'}\n"
                "config.safe_dump()\n"
            ),
        },
    ],
}


def run_challenge(challenge: dict, module_key: str, progress: dict):
    """Present and run a single challenge."""
    section_header(f"Challenge: {challenge['title']}")
    print(f"  {Y}Difficulty:{RESET} {challenge['difficulty']}")
    print()
    lesson_block(challenge["description"])

    if challenge.get("test_instructions"):
        info(f"Testing: {challenge['test_instructions']}")
        print()

    # Offer live code execution if test_cases are available
    if challenge.get("test_cases"):
        if ask_yes_no("Try writing and running the code live?"):
            from utils.code_runner import code_exercise
            passed = code_exercise(
                instruction=challenge["description"],
                test_cases=challenge["test_cases"],
                starter_code=challenge.get("starter_code", ""),
                hints=challenge["hints"],
                solution=challenge["solution"],
            )
            if passed and ask_yes_no("Mark this challenge as completed?"):
                mark_challenge_complete(progress, module_key, challenge["id"])
                success("Challenge marked as complete!")
            press_enter()
            return

    # Offer hints
    for i, hint in enumerate(challenge["hints"], 1):
        if ask_yes_no(f"Show hint {i}/{len(challenge['hints'])}?"):
            hint_text(hint)
        print()

    # Show solution
    print()
    if ask_yes_no("Ready to see the solution?"):
        code_block(challenge["solution"])

    if ask_yes_no("Mark this challenge as completed?"):
        mark_challenge_complete(progress, module_key, challenge["id"])
        success("Challenge marked as complete!")

    press_enter()


def exercises_menu(progress: dict):
    """Main exercises/challenges menu."""
    while True:
        options = []
        for mod_key, challenges in CHALLENGES.items():
            mod_num = mod_key.replace("module", "")
            for ch in challenges:
                done = ch["id"] in progress["modules"][mod_key]["challenges_done"]
                status = f"{G}[Done]{RESET}" if done else f"{Y}[Todo]{RESET}"
                options.append(
                    (f"{mod_key}:{ch['id']}", f"{status} M{mod_num}: {ch['title']} ({ch['difficulty']})")
                )

        options.append(("sandbox", f"{C}Test Your Code — open the code sandbox{RESET}"))

        choice = show_menu("Practice Challenges", options)
        if choice == "back":
            return
        if choice == "quit":
            raise SystemExit
        if choice == "sandbox":
            test_code_interactive()
            continue

        mod_key, challenge_id = choice.split(":", 1)
        challenge = next(c for c in CHALLENGES[mod_key] if c["id"] == challenge_id)
        run_challenge(challenge, mod_key, progress)
