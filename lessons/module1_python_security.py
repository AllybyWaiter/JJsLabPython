"""
Module 1: Python for Security
Teaches foundational Python skills used in security work — sockets, HTTP requests,
subprocess management, file I/O, regex log parsing, and building security tools.
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
MODULE_KEY = "module1"


# ──────────────────────────────────────────────────────────────────────
#  Lesson 1 — Socket Programming Basics
# ──────────────────────────────────────────────────────────────────────
def lesson_socket_basics(progress):
    section_header("Lesson 1: Socket Programming Basics")

    lesson_block(
        "Sockets are the fundamental building blocks of all network communication. "
        "Every time your browser loads a page, every time an API call is made, and "
        "every time a security tool connects to a target, sockets are doing the work "
        "underneath. A socket is an endpoint for sending or receiving data across a "
        "computer network. In Python, the built-in 'socket' module gives us full "
        "control over this low-level networking."
    )

    lesson_block(
        "There are two main types of sockets you will use in security work. "
        "TCP sockets (SOCK_STREAM) provide reliable, ordered delivery of data — "
        "they guarantee every byte arrives and in the right order. This is what web "
        "servers, SSH, and most services use. UDP sockets (SOCK_DGRAM) are faster "
        "but unreliable — packets can arrive out of order, get duplicated, or be "
        "lost entirely. DNS queries and some scanning techniques use UDP."
    )

    lesson_block(
        "The socket lifecycle follows a predictable pattern. First you create a "
        "socket object specifying the address family (AF_INET for IPv4) and the "
        "socket type (SOCK_STREAM for TCP or SOCK_DGRAM for UDP). Then you connect "
        "to a remote host and port. Once connected, you can send data with send() "
        "or sendall(), and receive data with recv(). Finally, you close the socket "
        "to free resources. Forgetting to close sockets is a common bug that leads "
        "to resource exhaustion — always use context managers or try/finally blocks."
    )

    why_it_matters(
        "Security professionals need socket programming for writing custom scanners, "
        "building proof-of-concept exploit code, crafting specialized payloads, and "
        "understanding how network services communicate at the lowest level. When a "
        "commercial tool does not support a specific protocol or edge case, you need "
        "to be able to write your own socket-level code. Understanding sockets also "
        "helps you recognize and debug network-level attacks."
    )

    sub_header("Creating a TCP Client")
    code_block("""\
import socket

# Create a TCP socket (IPv4)
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Set a timeout so we don't hang forever
sock.settimeout(5)

try:
    # Connect to a remote host
    sock.connect(("example.com", 80))

    # Send an HTTP request (raw bytes)
    request = b"GET / HTTP/1.1\\r\\nHost: example.com\\r\\n\\r\\n"
    sock.sendall(request)

    # Receive the response (up to 4096 bytes)
    response = sock.recv(4096)
    print(response.decode("utf-8", errors="replace"))
finally:
    sock.close()""")

    lesson_block(
        "Notice several important details in the code above. We use sendall() "
        "instead of send() — sendall() guarantees all bytes are transmitted, while "
        "send() might only send part of the data. We also set a timeout of 5 seconds "
        "so our program does not hang indefinitely if the remote host is unreachable. "
        "The recv() call takes a buffer size argument — 4096 bytes is a common choice. "
        "If the response is larger, you would need to call recv() in a loop."
    )

    sub_header("Using a Context Manager (Best Practice)")
    code_block("""\
import socket

# The 'with' statement ensures the socket is always closed
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
    sock.settimeout(5)
    sock.connect(("example.com", 80))
    sock.sendall(b"GET / HTTP/1.1\\r\\nHost: example.com\\r\\n\\r\\n")
    data = sock.recv(4096)
    print(data.decode())""")

    sub_header("UDP Socket Example")
    code_block("""\
import socket

# Create a UDP socket
udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
udp_sock.settimeout(3)

# UDP has no connection — just send data directly
udp_sock.sendto(b"Hello UDP", ("127.0.0.1", 9999))

try:
    data, addr = udp_sock.recvfrom(1024)
    print(f"Received from {addr}: {data.decode()}")
except socket.timeout:
    print("No response received (timeout)")
finally:
    udp_sock.close()""")

    lesson_block(
        "Notice that with UDP there is no connect() call — you use sendto() which "
        "includes the destination address each time. Similarly, recvfrom() returns "
        "both the data and the address it came from. This is because UDP is "
        "connectionless — each packet is independent."
    )

    sub_header("Resolving Hostnames")
    code_block("""\
import socket

# Resolve a hostname to an IP address
ip = socket.gethostbyname("example.com")
print(f"example.com resolves to {ip}")

# Get full address info (useful for IPv6 support)
results = socket.getaddrinfo("example.com", 443)
for family, socktype, proto, canonname, sockaddr in results:
    print(f"  {sockaddr}")""")

    scenario_block("Detecting a Rogue Service", (
        "During a routine network audit, you discover that port 4444 is open on a "
        "workstation. This port is commonly associated with Metasploit reverse shells. "
        "Using socket programming, you write a quick script that connects to the port, "
        "reads any banner or data the service sends, and logs it. The banner reveals "
        "a Meterpreter payload. Because you understood sockets, you could confirm "
        "the compromise in minutes rather than waiting for a full scan tool to run."
    ))

    # ── Practice Challenge ──
    sub_header("Practice Challenge")
    info("Write a script that connects to a given host and port, sends a simple")
    info("message, receives the response, and prints it. Use a timeout and a")
    info("context manager.\n")

    if ask_yes_no("Would you like a hint?"):
        hint_text("Use 'with socket.socket(AF_INET, SOCK_STREAM) as s:' and remember settimeout().")
        hint_text("Use sendall() for reliability, recv(4096) for the response.")

    press_enter()

    if ask_yes_no("Show the full solution?"):
        code_block("""\
import socket

def connect_and_send(host, port, message):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(5)
        try:
            s.connect((host, port))
            s.sendall(message.encode())
            response = s.recv(4096)
            print(f"Response: {response.decode(errors='replace')}")
        except socket.timeout:
            print("Connection timed out")
        except ConnectionRefusedError:
            print(f"Connection refused on {host}:{port}")

# Example usage:
connect_and_send("127.0.0.1", 80, "GET / HTTP/1.1\\r\\nHost: localhost\\r\\n\\r\\n")""")
    press_enter()

    mark_lesson_complete(progress, MODULE_KEY, "lesson1")
    success("Lesson 1 complete: Socket Programming Basics")
    press_enter()


# ──────────────────────────────────────────────────────────────────────
#  Lesson 2 — HTTP with Requests
# ──────────────────────────────────────────────────────────────────────
def lesson_http_requests(progress):
    section_header("Lesson 2: HTTP with Requests")

    lesson_block(
        "While raw sockets give you complete control, the 'requests' library is the "
        "standard tool for HTTP communication in Python. It handles connection pooling, "
        "encoding, cookies, redirects, and TLS/SSL automatically. In security work, "
        "you will use requests constantly — for interacting with web applications, "
        "testing APIs, downloading files, submitting forms, and automating web-based "
        "attacks in authorized engagements."
    )

    lesson_block(
        "The requests library supports all HTTP methods: GET for retrieving data, "
        "POST for submitting data, PUT for updating resources, DELETE for removing "
        "them, and others like PATCH, HEAD, and OPTIONS. Each method returns a "
        "Response object containing the status code, headers, body text, and more. "
        "Understanding HTTP status codes is critical — 200 means success, 301/302 "
        "are redirects, 403 is forbidden, 404 is not found, and 500 is a server error."
    )

    why_it_matters(
        "Web applications are the most common attack surface for organizations. "
        "Security testers need to automate HTTP requests to test for vulnerabilities "
        "like SQL injection, cross-site scripting, broken authentication, and "
        "insecure API endpoints. The requests library lets you script these tests "
        "efficiently and repeatably. It is also essential for interacting with "
        "security APIs like VirusTotal, Shodan, and your SIEM's REST API."
    )

    sub_header("Basic GET Request")
    code_block("""\
import requests

# Simple GET request
response = requests.get("https://httpbin.org/get")

# Check the status code
print(f"Status Code: {response.status_code}")
print(f"Content-Type: {response.headers['Content-Type']}")
print(f"Body (first 200 chars): {response.text[:200]}")

# For JSON responses, use .json()
data = response.json()
print(f"Origin IP: {data['origin']}")""")

    sub_header("POST Request with Data")
    code_block("""\
import requests

# POST form data
response = requests.post("https://httpbin.org/post", data={
    "username": "testuser",
    "password": "testpass"
})
print(response.json()["form"])

# POST JSON data
response = requests.post("https://httpbin.org/post", json={
    "action": "scan",
    "target": "192.168.1.0/24"
})
print(response.json()["json"])""")

    sub_header("Custom Headers and Authentication")
    code_block("""\
import requests

# Custom headers (common in API testing)
headers = {
    "User-Agent": "SecurityScanner/1.0",
    "Authorization": "Bearer YOUR_API_KEY",
    "X-Custom-Header": "test-value"
}
response = requests.get("https://httpbin.org/headers", headers=headers)
print(response.json())

# Basic HTTP Authentication
response = requests.get(
    "https://httpbin.org/basic-auth/user/pass",
    auth=("user", "pass")
)
print(f"Auth result: {response.status_code}")""")

    sub_header("Sessions — Maintaining State")
    code_block("""\
import requests

# A Session persists cookies and settings across requests
session = requests.Session()

# Set default headers for all requests in this session
session.headers.update({"User-Agent": "SecurityAuditor/2.0"})

# Login (cookies will be saved automatically)
session.post("https://httpbin.org/post", data={"login": "admin"})

# Subsequent requests carry the session cookies
response = session.get("https://httpbin.org/cookies")
print(response.json())

# Always close sessions when done
session.close()""")

    sub_header("Handling Errors and Timeouts")
    code_block("""\
import requests

try:
    response = requests.get("https://httpbin.org/delay/10", timeout=3)
    response.raise_for_status()  # Raises HTTPError for 4xx/5xx
    print(response.text)
except requests.exceptions.Timeout:
    print("Request timed out!")
except requests.exceptions.HTTPError as e:
    print(f"HTTP error: {e}")
except requests.exceptions.ConnectionError:
    print("Could not connect to the server")
except requests.exceptions.RequestException as e:
    print(f"Request failed: {e}")""")

    sub_header("Disabling SSL Verification (Testing Only)")
    code_block("""\
import requests
import urllib3

# Suppress InsecureRequestWarning (ONLY for authorized testing)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# verify=False skips certificate validation
response = requests.get("https://self-signed.example.com", verify=False)
print(response.status_code)""")

    warning("Never disable SSL verification in production code. This is only")
    warning("for testing against systems with self-signed certificates during")
    warning("authorized security assessments.\n")

    scenario_block("API Key Discovery", (
        "A penetration tester is reviewing a web application and notices that the "
        "JavaScript source code contains an API endpoint URL. Using the requests "
        "library, they write a script to systematically test the API with different "
        "authentication headers. They discover that the API accepts an old, "
        "deprecated API key that was supposed to have been revoked, granting access "
        "to sensitive customer data. The requests library made it trivial to test "
        "hundreds of header combinations in seconds."
    ))

    # ── Practice Challenge ──
    sub_header("Practice Challenge")
    info("Write a script that takes a URL, makes a GET request, and prints:")
    info("  - Status code and reason")
    info("  - All response headers")
    info("  - The first 500 characters of the body")
    info("  - Whether the server header reveals software version info\n")

    if ask_yes_no("Would you like a hint?"):
        hint_text("Use response.headers to iterate all headers.")
        hint_text("Check if 'Server' in response.headers and look for version numbers.")

    press_enter()

    if ask_yes_no("Show the full solution?"):
        code_block("""\
import requests
import re

def inspect_url(url):
    try:
        resp = requests.get(url, timeout=10, allow_redirects=True)

        print(f"Status: {resp.status_code} {resp.reason}")
        print(f"Final URL: {resp.url}")
        print()

        print("Response Headers:")
        for key, value in resp.headers.items():
            print(f"  {key}: {value}")
        print()

        print(f"Body (first 500 chars):\\n{resp.text[:500]}")
        print()

        # Check for server version disclosure
        server = resp.headers.get("Server", "")
        if server:
            if re.search(r"[\\d]+\\.[\\d]+", server):
                print(f"[!] Server header discloses version: {server}")
            else:
                print(f"[i] Server header: {server} (no version found)")
        else:
            print("[i] No Server header present")

    except requests.exceptions.RequestException as e:
        print(f"Error: {e}")

inspect_url("https://example.com")""")
    press_enter()

    mark_lesson_complete(progress, MODULE_KEY, "lesson2")
    success("Lesson 2 complete: HTTP with Requests")
    press_enter()


# ──────────────────────────────────────────────────────────────────────
#  Lesson 3 — Subprocess & OS Interaction
# ──────────────────────────────────────────────────────────────────────
def lesson_subprocess_os(progress):
    section_header("Lesson 3: Subprocess & OS Interaction")

    lesson_block(
        "Security tools frequently need to run system commands — launching nmap, "
        "calling openssl, reading system configurations, or automating tasks that "
        "are easier done via the command line. Python's 'subprocess' module is the "
        "correct way to do this. It replaces older functions like os.system() and "
        "os.popen() with a more powerful and secure interface."
    )

    lesson_block(
        "The most important function is subprocess.run(), which executes a command "
        "and waits for it to complete. It returns a CompletedProcess object with "
        "the return code, stdout, and stderr. You should almost always pass the "
        "command as a list of strings rather than a single string — this avoids "
        "shell injection vulnerabilities. When you pass shell=True, the command "
        "is interpreted by the system shell, which means an attacker could inject "
        "additional commands using characters like ; | && or backticks."
    )

    lesson_block(
        "The 'os' module provides complementary functionality. os.walk() recursively "
        "traverses directory trees — perfect for searching filesystems. "
        "os.environ gives you access to environment variables, which often contain "
        "secrets, paths, and configuration that security tools need. os.path provides "
        "safe path manipulation to avoid directory traversal issues."
    )

    why_it_matters(
        "Improper use of subprocess is one of the most common sources of command "
        "injection vulnerabilities in Python applications. As a security professional, "
        "you need to know both how to use subprocess safely in your own tools and "
        "how to find unsafe usage in code you are reviewing. Many real-world "
        "vulnerabilities come from developers passing user input directly to "
        "shell=True commands."
    )

    sub_header("subprocess.run() — The Safe Way")
    code_block("""\
import subprocess

# SAFE: command as a list (no shell interpretation)
result = subprocess.run(
    ["ping", "-c", "3", "127.0.0.1"],
    capture_output=True,
    text=True,
    timeout=10
)

print(f"Return code: {result.returncode}")
print(f"stdout:\\n{result.stdout}")
if result.stderr:
    print(f"stderr:\\n{result.stderr}")""")

    sub_header("DANGEROUS: shell=True with User Input")
    code_block("""\
import subprocess

# DANGEROUS — Never do this with user input!
user_input = "127.0.0.1; cat /etc/passwd"  # Malicious input!

# This executes BOTH commands because of shell=True
result = subprocess.run(
    f"ping -c 1 {user_input}",
    shell=True,           # BAD: enables shell interpretation
    capture_output=True,
    text=True
)
# The attacker's 'cat /etc/passwd' command runs too!

# SAFE alternative using a list:
import shlex
result = subprocess.run(
    ["ping", "-c", "1", user_input],  # user_input is a single argument
    capture_output=True,
    text=True,
    timeout=5
)
# This fails safely — "127.0.0.1; cat /etc/passwd" is treated as
# one hostname argument, which ping cannot resolve.""")

    warning("shell=True is the #1 source of command injection in Python scripts.")
    warning("Only use it when absolutely necessary and NEVER with untrusted input.\n")

    sub_header("os.walk() — Searching the Filesystem")
    code_block("""\
import os

# Recursively find all .conf and .ini files
def find_config_files(start_path):
    config_files = []
    for dirpath, dirnames, filenames in os.walk(start_path):
        # Skip hidden directories
        dirnames[:] = [d for d in dirnames if not d.startswith('.')]
        for filename in filenames:
            if filename.endswith(('.conf', '.ini', '.cfg', '.yaml', '.yml')):
                full_path = os.path.join(dirpath, filename)
                config_files.append(full_path)
    return config_files

configs = find_config_files("/etc")
for path in configs[:10]:
    print(f"  Found: {path}")""")

    sub_header("Environment Variables")
    code_block("""\
import os

# Read environment variables (often contain secrets)
path = os.environ.get("PATH", "")
home = os.environ.get("HOME", "")
api_key = os.environ.get("API_KEY", "NOT SET")

print(f"PATH: {path[:80]}...")
print(f"HOME: {home}")
print(f"API_KEY: {api_key}")

# Security check: find potentially sensitive env vars
sensitive_keywords = ["KEY", "SECRET", "PASSWORD", "TOKEN", "CREDENTIAL"]
for var_name, var_value in os.environ.items():
    if any(kw in var_name.upper() for kw in sensitive_keywords):
        print(f"  [!] Sensitive env var found: {var_name}=****")""")

    sub_header("Running Multiple Commands Safely")
    code_block("""\
import subprocess

def run_command(cmd_list, description=""):
    \"\"\"Run a command safely and return the output.\"\"\"
    try:
        result = subprocess.run(
            cmd_list,
            capture_output=True,
            text=True,
            timeout=30
        )
        if result.returncode == 0:
            return True, result.stdout.strip()
        else:
            return False, result.stderr.strip()
    except subprocess.TimeoutExpired:
        return False, "Command timed out"
    except FileNotFoundError:
        return False, f"Command not found: {cmd_list[0]}"

# Usage
ok, output = run_command(["uname", "-a"], "System info")
if ok:
    print(f"System: {output}")

ok, output = run_command(["whoami"], "Current user")
if ok:
    print(f"Running as: {output}")""")

    scenario_block("Command Injection in a Web App", (
        "A developer builds an internal network diagnostic tool that lets users "
        "enter an IP address to ping. The backend uses subprocess.run(f'ping {ip}', "
        "shell=True). An attacker enters '8.8.8.8; whoami' and gets command execution "
        "on the server. The fix: use subprocess.run(['ping', '-c', '3', ip]) which "
        "treats the IP as a single argument, preventing injection. Always validate "
        "input AND use list-form commands."
    ))

    # ── Practice Challenge ──
    sub_header("Practice Challenge")
    info("Write a function that safely runs a system command, captures output,")
    info("handles timeouts, and returns structured results. Then use it to get")
    info("the system hostname, current user, and Python version.\n")

    if ask_yes_no("Would you like a hint?"):
        hint_text("Wrap subprocess.run() in a try/except for TimeoutExpired and FileNotFoundError.")
        hint_text("Return a dict with 'success', 'output', and 'error' keys.")

    press_enter()

    if ask_yes_no("Show the full solution?"):
        code_block("""\
import subprocess

def safe_run(cmd_list, timeout=10):
    \"\"\"Safely execute a command and return structured results.\"\"\"
    result = {"success": False, "output": "", "error": "", "returncode": -1}
    try:
        proc = subprocess.run(
            cmd_list,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        result["returncode"] = proc.returncode
        result["output"] = proc.stdout.strip()
        result["error"] = proc.stderr.strip()
        result["success"] = proc.returncode == 0
    except subprocess.TimeoutExpired:
        result["error"] = f"Timed out after {timeout}s"
    except FileNotFoundError:
        result["error"] = f"Command not found: {cmd_list[0]}"
    return result

# Gather system info
for label, cmd in [
    ("Hostname", ["hostname"]),
    ("User", ["whoami"]),
    ("Python", ["python3", "--version"]),
]:
    r = safe_run(cmd)
    if r["success"]:
        print(f"  {label}: {r['output']}")
    else:
        print(f"  {label}: ERROR - {r['error']}")""")
    press_enter()

    mark_lesson_complete(progress, MODULE_KEY, "lesson3")
    success("Lesson 3 complete: Subprocess & OS Interaction")
    press_enter()


# ──────────────────────────────────────────────────────────────────────
#  Lesson 4 — File I/O for Security
# ──────────────────────────────────────────────────────────────────────
def lesson_file_io(progress):
    section_header("Lesson 4: File I/O for Security")

    lesson_block(
        "File I/O is fundamental to security work. You will read log files to hunt "
        "for threats, parse configuration files to find misconfigurations, write "
        "reports, handle binary payloads, and create secure temporary files. Getting "
        "file handling right is important both for your tools to work correctly and "
        "to avoid introducing security vulnerabilities of your own."
    )

    lesson_block(
        "Python's built-in open() function with context managers is the standard "
        "approach. Always use 'with' statements to ensure files are properly closed, "
        "even if an exception occurs. For text files, specify the encoding explicitly "
        "— utf-8 is the most common. For binary files (executables, images, packets), "
        "use 'rb' or 'wb' mode. Never use string mode for binary data."
    )

    lesson_block(
        "When writing security tools, you also need to think about file permissions, "
        "race conditions (TOCTOU — time of check, time of use), path traversal "
        "attacks, and secure handling of temporary files. The tempfile module provides "
        "secure defaults for creating temporary files that cannot be accessed by "
        "other users on the system."
    )

    why_it_matters(
        "Configuration files often contain hardcoded credentials, overly permissive "
        "settings, and default passwords. Log files contain evidence of attacks, "
        "unauthorized access, and data exfiltration. Your security tools need to "
        "read and write files safely — a vulnerability in your own tooling could "
        "be exploited by a sophisticated attacker. Insecure temp files have been "
        "the source of privilege escalation bugs in major software."
    )

    sub_header("Reading Text Files Safely")
    code_block("""\
# Always use context managers and explicit encoding
with open("/var/log/auth.log", "r", encoding="utf-8", errors="replace") as f:
    for line_number, line in enumerate(f, 1):
        if "Failed password" in line:
            print(f"Line {line_number}: {line.strip()}")

# Read entire file into memory (only for small files)
with open("config.txt", "r", encoding="utf-8") as f:
    content = f.read()
    print(f"File is {len(content)} characters long")

# Read lines into a list
with open("targets.txt", "r") as f:
    targets = [line.strip() for line in f if line.strip()]
    print(f"Loaded {len(targets)} targets")""")

    sub_header("Writing Files with Proper Permissions")
    code_block("""\
import os
import stat

# Write a report file
report_path = "scan_report.txt"
with open(report_path, "w", encoding="utf-8") as f:
    f.write("Security Scan Report\\n")
    f.write("=" * 40 + "\\n")
    f.write("Target: 192.168.1.0/24\\n")
    f.write("Open ports found: 22, 80, 443\\n")

# Set restrictive permissions (owner read/write only)
os.chmod(report_path, stat.S_IRUSR | stat.S_IWUSR)  # 0o600
print(f"Report written with restricted permissions")""")

    sub_header("Parsing Configuration Files")
    code_block("""\
import configparser
import json
import yaml  # pip install pyyaml

# Parse INI-style config files
config = configparser.ConfigParser()
config.read("settings.ini")
db_host = config.get("database", "host", fallback="localhost")
db_pass = config.get("database", "password", fallback="")
if db_pass:
    print("[!] Password found in config file!")

# Parse JSON config
with open("config.json", "r") as f:
    config = json.load(f)
    # Look for sensitive keys
    sensitive = ["password", "secret", "key", "token"]
    for key in config:
        if any(s in key.lower() for s in sensitive):
            print(f"[!] Sensitive key found: {key}")

# Parse YAML config
with open("docker-compose.yml", "r") as f:
    config = yaml.safe_load(f)  # ALWAYS use safe_load, never load()!
    print(f"Services: {list(config.get('services', {}).keys())}")""")

    warning("Always use yaml.safe_load() instead of yaml.load(). The unsafe")
    warning("yaml.load() can execute arbitrary Python code from the YAML file.\n")

    sub_header("Handling Binary Files")
    code_block("""\
import hashlib

# Read a binary file and compute its hash
def hash_file(filepath):
    sha256 = hashlib.sha256()
    with open(filepath, "rb") as f:
        while True:
            chunk = f.read(8192)
            if not chunk:
                break
            sha256.update(chunk)
    return sha256.hexdigest()

file_hash = hash_file("/usr/bin/python3")
print(f"SHA-256: {file_hash}")

# Read binary file header (e.g., check for ELF magic bytes)
with open("/usr/bin/python3", "rb") as f:
    magic = f.read(4)
    if magic == b"\\x7fELF":
        print("This is an ELF binary")
    elif magic[:2] == b"MZ":
        print("This is a Windows PE binary")""")

    sub_header("Secure Temporary Files")
    code_block("""\
import tempfile
import os

# Create a secure temp file (only accessible by the current user)
with tempfile.NamedTemporaryFile(mode='w', suffix='.txt',
                                  prefix='scan_', delete=False) as tmp:
    tmp.write("Temporary scan results\\n")
    tmp.write("Host: 192.168.1.1 - OPEN\\n")
    tmp_path = tmp.name

print(f"Temp file created: {tmp_path}")

# Process the temp file
with open(tmp_path, "r") as f:
    print(f.read())

# Clean up when done
os.unlink(tmp_path)
print("Temp file deleted")

# For directories, use tempfile.TemporaryDirectory()
with tempfile.TemporaryDirectory(prefix='seclab_') as tmp_dir:
    print(f"Temp dir: {tmp_dir}")
    # Directory and contents are automatically deleted""")

    scenario_block("Credential Discovery in Config Files", (
        "During a security assessment, you write a script that recursively searches "
        "a web server's document root for configuration files. The script finds a "
        ".env file containing database credentials, a config.php with an API key, "
        "and a backup.sql file with user password hashes. These files were "
        "accidentally deployed to the production server. Your file I/O skills let "
        "you quickly identify and report these exposures before an attacker finds them."
    ))

    # ── Practice Challenge ──
    sub_header("Practice Challenge")
    info("Write a script that scans a directory tree for files that might contain")
    info("secrets. Look for files named .env, *password*, *secret*, *credential*,")
    info("*.key, *.pem. For each file found, print its path and file permissions.\n")

    if ask_yes_no("Would you like a hint?"):
        hint_text("Use os.walk() to traverse directories, os.stat() for permissions.")
        hint_text("Use stat.filemode() to convert permission bits to a readable string.")

    press_enter()

    if ask_yes_no("Show the full solution?"):
        code_block("""\
import os
import stat

def scan_for_secrets(start_path):
    secret_patterns = ['.env', 'password', 'secret', 'credential', 'private']
    secret_extensions = ['.key', '.pem', '.p12', '.pfx', '.jks']
    findings = []

    for dirpath, dirnames, filenames in os.walk(start_path):
        dirnames[:] = [d for d in dirnames if not d.startswith('.')]
        for fname in filenames:
            fname_lower = fname.lower()
            is_suspicious = (
                any(pat in fname_lower for pat in secret_patterns) or
                any(fname_lower.endswith(ext) for ext in secret_extensions)
            )
            if is_suspicious:
                full_path = os.path.join(dirpath, fname)
                try:
                    st = os.stat(full_path)
                    mode = stat.filemode(st.st_mode)
                    size = st.st_size
                    findings.append((full_path, mode, size))
                except PermissionError:
                    findings.append((full_path, "ACCESS DENIED", 0))

    print(f"Scan of {start_path} complete. {len(findings)} suspicious files:")
    for path, mode, size in findings:
        print(f"  [{mode}] {size:>8} bytes  {path}")
    return findings

scan_for_secrets(os.path.expanduser("~"))""")
    press_enter()

    mark_lesson_complete(progress, MODULE_KEY, "lesson4")
    success("Lesson 4 complete: File I/O for Security")
    press_enter()


# ──────────────────────────────────────────────────────────────────────
#  Lesson 5 — Regex for Log Parsing
# ──────────────────────────────────────────────────────────────────────
def lesson_regex_logs(progress):
    section_header("Lesson 5: Regex for Log Parsing")

    lesson_block(
        "Regular expressions (regex) are an essential tool for security analysts. "
        "Log files — from web servers, firewalls, authentication systems, and "
        "applications — are your primary source of evidence during incident response "
        "and threat hunting. These logs can be millions of lines long, and regex lets "
        "you extract exactly the data you need: IP addresses, timestamps, usernames, "
        "URLs, error codes, and attack patterns."
    )

    lesson_block(
        "Python's 're' module provides full regex support. The key functions are: "
        "re.search() to find the first match in a string, re.findall() to find all "
        "matches, re.finditer() to iterate over matches with position info, "
        "re.match() to match only at the start of a string, and re.sub() to replace "
        "matches. You can compile patterns with re.compile() for better performance "
        "when using the same pattern many times."
    )

    lesson_block(
        "The most important regex metacharacters for log parsing are: \\d for digits, "
        "\\w for word characters, \\s for whitespace, . for any character, * for zero "
        "or more, + for one or more, ? for zero or one, {n} for exactly n, "
        "[a-z] for character classes, ^ for start of line, $ for end of line, and "
        "( ) for capture groups. Named groups (?P<name>...) make your patterns "
        "self-documenting and easier to maintain."
    )

    why_it_matters(
        "When a security incident occurs, the clock is ticking. You need to quickly "
        "sift through massive log files to answer critical questions: Which IP "
        "addresses were involved? When did the attack start? What credentials were "
        "targeted? What data was accessed? Regex mastery lets you answer these "
        "questions in minutes instead of hours. It is the difference between "
        "containing a breach quickly and letting it spread."
    )

    sub_header("Extracting IP Addresses from Logs")
    code_block("""\
import re

# IPv4 address pattern
ip_pattern = re.compile(
    r'\\b(\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3})\\b'
)

log_lines = [
    '2024-01-15 10:23:45 Failed login from 192.168.1.100 user=admin',
    '2024-01-15 10:23:46 Failed login from 192.168.1.100 user=root',
    '2024-01-15 10:23:47 Failed login from 10.0.0.55 user=admin',
    '2024-01-15 10:24:01 Successful login from 172.16.0.1 user=jsmith',
]

# Find all IPs across all log lines
all_ips = []
for line in log_lines:
    ips = ip_pattern.findall(line)
    all_ips.extend(ips)

# Count occurrences
from collections import Counter
ip_counts = Counter(all_ips)
print("IP Address Frequency:")
for ip, count in ip_counts.most_common():
    print(f"  {ip}: {count} occurrences")""")

    sub_header("Parsing Structured Log Entries")
    code_block("""\
import re

# Apache combined log format parser
log_pattern = re.compile(
    r'(?P<ip>[\\d.]+) - - '
    r'\\[(?P<timestamp>[^\\]]+)\\] '
    r'"(?P<method>\\w+) (?P<path>[^ ]+) [^"]*" '
    r'(?P<status>\\d{3}) '
    r'(?P<size>\\d+|-)'
)

apache_log = '192.168.1.50 - - [15/Jan/2024:10:30:45 +0000] "GET /admin/login HTTP/1.1" 401 512'

match = log_pattern.search(apache_log)
if match:
    print(f"IP: {match.group('ip')}")
    print(f"Time: {match.group('timestamp')}")
    print(f"Method: {match.group('method')}")
    print(f"Path: {match.group('path')}")
    print(f"Status: {match.group('status')}")""")

    sub_header("Detecting Attack Patterns")
    code_block("""\
import re

# SQL injection patterns in URLs/parameters
sqli_patterns = [
    r"(\\bUNION\\b.*\\bSELECT\\b)",
    r"(\\bOR\\b\\s+\\d+\\s*=\\s*\\d+)",
    r"(--\\s|#|/\\*)",
    r"(\\bDROP\\b.*\\bTABLE\\b)",
    r"('\\s*(OR|AND)\\s+')",
]
sqli_regex = re.compile('|'.join(sqli_patterns), re.IGNORECASE)

# XSS patterns
xss_patterns = [
    r"(<script[^>]*>)",
    r"(javascript\\s*:)",
    r"(on\\w+\\s*=)",
    r"(<img[^>]+onerror)",
]
xss_regex = re.compile('|'.join(xss_patterns), re.IGNORECASE)

test_inputs = [
    "/search?q=normal+query",
    "/search?q=1' OR '1'='1",
    "/page?id=1 UNION SELECT username,password FROM users",
    "/comment?text=<script>alert('xss')</script>",
    "/profile?name=<img src=x onerror=alert(1)>",
]

for inp in test_inputs:
    if sqli_regex.search(inp):
        print(f"  [SQLi] {inp}")
    elif xss_regex.search(inp):
        print(f"  [XSS]  {inp}")
    else:
        print(f"  [OK]   {inp}")""")

    sub_header("Extracting Timestamps and Building Timelines")
    code_block("""\
import re
from datetime import datetime

# Multiple timestamp formats you might encounter
timestamp_patterns = {
    "iso": re.compile(r'(\\d{4}-\\d{2}-\\d{2}[T ]\\d{2}:\\d{2}:\\d{2})'),
    "apache": re.compile(r'\\[(\\d{2}/\\w{3}/\\d{4}:\\d{2}:\\d{2}:\\d{2})'),
    "syslog": re.compile(r'(\\w{3}\\s+\\d{1,2} \\d{2}:\\d{2}:\\d{2})'),
}

sample_logs = [
    "2024-01-15T10:30:45 ERROR: Authentication failed",
    "[15/Jan/2024:10:31:00 +0000] 401 /admin",
    "Jan 15 10:31:15 server sshd: Failed password for root",
]

for line in sample_logs:
    for fmt_name, pattern in timestamp_patterns.items():
        match = pattern.search(line)
        if match:
            print(f"  [{fmt_name:>6}] {match.group(1)}: {line.strip()}")
            break""")

    sub_header("Practical: Failed Login Detector")
    code_block("""\
import re
from collections import defaultdict

def analyze_auth_log(log_lines):
    failed_pattern = re.compile(
        r'(?P<timestamp>[\\w:\\s/]+) '
        r'.*Failed password for (?:invalid user )?(?P<user>\\w+) '
        r'from (?P<ip>[\\d.]+)'
    )

    failures_by_ip = defaultdict(list)

    for line in log_lines:
        match = failed_pattern.search(line)
        if match:
            ip = match.group('ip')
            user = match.group('user')
            failures_by_ip[ip].append(user)

    # Flag IPs with more than 5 failures (possible brute force)
    print("\\nBrute Force Detection Report:")
    for ip, attempts in failures_by_ip.items():
        status = "ALERT" if len(attempts) >= 5 else "watch"
        unique_users = set(attempts)
        print(f"  [{status:>5}] {ip}: {len(attempts)} failures, "
              f"{len(unique_users)} unique usernames")

# Example usage
sample_auth = [
    "Jan 15 10:30:01 srv sshd: Failed password for admin from 10.0.0.99 port 22",
    "Jan 15 10:30:02 srv sshd: Failed password for root from 10.0.0.99 port 22",
    "Jan 15 10:30:03 srv sshd: Failed password for admin from 10.0.0.99 port 22",
    "Jan 15 10:30:04 srv sshd: Failed password for invalid user test from 10.0.0.99 port 22",
    "Jan 15 10:30:05 srv sshd: Failed password for admin from 10.0.0.99 port 22",
    "Jan 15 10:30:06 srv sshd: Failed password for root from 10.0.0.99 port 22",
    "Jan 15 10:30:10 srv sshd: Failed password for admin from 192.168.1.5 port 22",
]
analyze_auth_log(sample_auth)""")

    scenario_block("Incident Response at 3 AM", (
        "Your SIEM triggers an alert at 3 AM — a spike in 401 errors on the payment "
        "API. You SSH into the server and use regex to parse the nginx access logs. "
        "Within 5 minutes, you identify 47,000 requests from a single IP trying "
        "different credit card numbers against the payment endpoint. Your regex "
        "extracts the source IP, the endpoint pattern, and the time window. You "
        "block the IP, generate a report, and assess the damage — all using regex "
        "skills you practiced in advance."
    ))

    # ── Practice Challenge ──
    sub_header("Practice Challenge")
    info("Write a log analyzer that reads log lines and produces a summary report:")
    info("  - Total lines processed")
    info("  - Unique IP addresses with request counts")
    info("  - Any lines containing error status codes (4xx or 5xx)")
    info("  - Potential SQL injection attempts\n")

    if ask_yes_no("Would you like a hint?"):
        hint_text("Combine re.findall() for IPs, re.search() for status codes.")
        hint_text("Use Counter for aggregating IP counts.")

    press_enter()

    if ask_yes_no("Show the full solution?"):
        code_block("""\
import re
from collections import Counter

def analyze_logs(log_lines):
    ip_re = re.compile(r'\\b(\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3})\\b')
    status_re = re.compile(r'\\s([45]\\d{2})\\s')
    sqli_re = re.compile(
        r\"(UNION\\s+SELECT|OR\\s+1\\s*=\\s*1|'\\s*OR\\s*'|DROP\\s+TABLE)\",
        re.IGNORECASE
    )

    ips = []
    errors = []
    sqli_attempts = []

    for line in log_lines:
        ip_match = ip_re.search(line)
        if ip_match:
            ips.append(ip_match.group(1))

        status_match = status_re.search(line)
        if status_match:
            errors.append((status_match.group(1), line.strip()))

        if sqli_re.search(line):
            sqli_attempts.append(line.strip())

    print(f"Total lines: {len(log_lines)}")
    print(f"\\nTop IPs:")
    for ip, count in Counter(ips).most_common(10):
        print(f"  {ip}: {count}")
    print(f"\\nError responses: {len(errors)}")
    for code, line in errors[:5]:
        print(f"  [{code}] {line[:80]}")
    print(f"\\nSQLi attempts: {len(sqli_attempts)}")
    for line in sqli_attempts:
        print(f"  [!] {line[:80]}")""")
    press_enter()

    mark_lesson_complete(progress, MODULE_KEY, "lesson5")
    success("Lesson 5 complete: Regex for Log Parsing")
    press_enter()


# ──────────────────────────────────────────────────────────────────────
#  Lesson 6 — Building Security Tools
# ──────────────────────────────────────────────────────────────────────
def lesson_building_tools(progress):
    section_header("Lesson 6: Building Security Tools")

    lesson_block(
        "Now it is time to combine everything you have learned — sockets, HTTP "
        "requests, subprocess, file I/O, and regex — into real security tools. "
        "Professional security engineers build custom tools every day. Sometimes "
        "the available tools do not cover your specific use case. Sometimes you "
        "need to automate a repetitive task. And sometimes building a tool is the "
        "best way to deeply understand a protocol or vulnerability."
    )

    lesson_block(
        "Good security tools share common traits: they take command-line arguments "
        "or configuration files for flexibility, they handle errors gracefully, they "
        "produce clear output, they log their actions for audit trails, and they "
        "run within authorized scope. In this lesson we will build a comprehensive "
        "security scanner that demonstrates all of these qualities."
    )

    lesson_block(
        "The tool we will build is a 'Service Enumerator' — it takes a target host, "
        "scans a set of common ports, grabs service banners, checks HTTP headers for "
        "security misconfigurations, and produces a formatted report. This is the "
        "type of tool you might build for a first-pass assessment of a new target."
    )

    why_it_matters(
        "The ability to rapidly build custom security tools sets apart senior "
        "security engineers from those who can only use existing tools. When you "
        "encounter a novel situation — a custom protocol, a unique vulnerability, "
        "an internal application with no public tooling — you need to be able to "
        "write your own solution. This lesson brings together everything from the "
        "module into a practical, real-world skill."
    )

    sub_header("Tool Architecture")
    code_block("""\
#!/usr/bin/env python3
\"\"\"
service_enumerator.py — A simple service enumeration tool.
Scans ports, grabs banners, checks HTTP headers.
For authorized use only.
\"\"\"

import argparse
import socket
import re
import json
from datetime import datetime

# ── Argument Parsing ──

def parse_args():
    parser = argparse.ArgumentParser(
        description="Service Enumerator — scan and enumerate services"
    )
    parser.add_argument("target", help="Target hostname or IP")
    parser.add_argument(
        "-p", "--ports", default="21,22,25,53,80,110,143,443,993,995,3306,5432,8080,8443",
        help="Comma-separated list of ports to scan"
    )
    parser.add_argument("-t", "--timeout", type=float, default=2.0,
                        help="Connection timeout in seconds")
    parser.add_argument("-o", "--output", help="Output file (JSON)")
    parser.add_argument("-v", "--verbose", action="store_true")
    return parser.parse_args()""")

    sub_header("Port Scanning Component")
    code_block("""\
def scan_port(host, port, timeout=2.0):
    \"\"\"Attempt to connect to a port and grab the banner.\"\"\"
    result = {"port": port, "state": "closed", "banner": "", "service": ""}

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((host, port))
            result["state"] = "open"

            # Try to grab a banner
            try:
                s.sendall(b"\\r\\n")
                banner = s.recv(1024).decode("utf-8", errors="replace").strip()
                result["banner"] = banner[:200]
            except (socket.timeout, OSError):
                pass

            # Identify common services by port
            known_services = {
                21: "FTP", 22: "SSH", 25: "SMTP", 53: "DNS",
                80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS",
                993: "IMAPS", 995: "POP3S", 3306: "MySQL",
                5432: "PostgreSQL", 8080: "HTTP-Alt", 8443: "HTTPS-Alt"
            }
            result["service"] = known_services.get(port, "unknown")

    except (ConnectionRefusedError, socket.timeout, OSError):
        pass

    return result""")

    sub_header("HTTP Header Security Check")
    code_block("""\
import requests

def check_http_headers(url, timeout=5):
    \"\"\"Check for security-related HTTP headers.\"\"\"
    findings = []

    try:
        resp = requests.get(url, timeout=timeout, verify=False,
                           allow_redirects=True)
        headers = resp.headers

        # Security headers to check for
        security_headers = {
            "Strict-Transport-Security": "Missing HSTS header",
            "Content-Security-Policy": "Missing CSP header",
            "X-Content-Type-Options": "Missing X-Content-Type-Options",
            "X-Frame-Options": "Missing X-Frame-Options (clickjacking risk)",
            "X-XSS-Protection": "Missing X-XSS-Protection",
        }

        for header, message in security_headers.items():
            if header not in headers:
                findings.append({"severity": "medium", "detail": message})
            else:
                findings.append({
                    "severity": "info",
                    "detail": f"{header}: {headers[header]}"
                })

        # Check for information disclosure
        server = headers.get("Server", "")
        if re.search(r"[\\d]+\\.[\\d]+", server):
            findings.append({
                "severity": "low",
                "detail": f"Server version disclosed: {server}"
            })

        powered_by = headers.get("X-Powered-By", "")
        if powered_by:
            findings.append({
                "severity": "low",
                "detail": f"Technology disclosed: {powered_by}"
            })

    except requests.exceptions.RequestException as e:
        findings.append({"severity": "error", "detail": f"HTTP check failed: {e}"})

    return findings""")

    sub_header("Report Generation")
    code_block("""\
def generate_report(target, scan_results, header_findings, output_file=None):
    \"\"\"Generate a formatted report.\"\"\"
    report = {
        "target": target,
        "scan_date": datetime.now().isoformat(),
        "open_ports": [r for r in scan_results if r["state"] == "open"],
        "http_findings": header_findings,
    }

    # Console output
    print(f"\\n{'=' * 60}")
    print(f"  SERVICE ENUMERATION REPORT")
    print(f"  Target: {target}")
    print(f"  Date:   {report['scan_date']}")
    print(f"{'=' * 60}")

    print(f"\\n  Open Ports ({len(report['open_ports'])}):")
    for r in report["open_ports"]:
        banner_info = f" | {r['banner'][:50]}" if r["banner"] else ""
        print(f"    {r['port']:>5}/tcp  {r['service']:<12}{banner_info}")

    if header_findings:
        print(f"\\n  HTTP Security Headers:")
        for f in header_findings:
            icon = {"info": "[i]", "low": "[~]", "medium": "[!]",
                    "error": "[x]"}.get(f["severity"], "[ ]")
            print(f"    {icon} {f['detail']}")

    print(f"\\n{'=' * 60}")

    # Save to file if requested
    if output_file:
        with open(output_file, "w") as f:
            json.dump(report, f, indent=2)
        print(f"\\n  Report saved to: {output_file}")""")

    sub_header("Main Function — Putting It All Together")
    code_block("""\
def main():
    args = parse_args()
    target = args.target
    ports = [int(p.strip()) for p in args.ports.split(",")]

    print(f"\\n[*] Starting enumeration of {target}")
    print(f"[*] Scanning {len(ports)} ports...\\n")

    # Resolve hostname
    try:
        ip = socket.gethostbyname(target)
        print(f"[+] {target} resolves to {ip}")
    except socket.gaierror:
        print(f"[-] Could not resolve {target}")
        return

    # Scan ports
    scan_results = []
    for port in ports:
        if args.verbose:
            print(f"  Scanning port {port}...", end=" ", flush=True)
        result = scan_port(ip, port, args.timeout)
        scan_results.append(result)
        if args.verbose:
            print(f"{result['state']}")

    # Check HTTP headers if web ports are open
    header_findings = []
    open_ports = [r["port"] for r in scan_results if r["state"] == "open"]
    if 80 in open_ports:
        header_findings = check_http_headers(f"http://{target}", args.timeout)
    elif 443 in open_ports:
        header_findings = check_http_headers(f"https://{target}", args.timeout)

    # Generate report
    generate_report(target, scan_results, header_findings, args.output)

if __name__ == "__main__":
    main()""")

    sub_header("Running the Tool")
    code_block("""\
# Basic scan
python3 service_enumerator.py example.com

# Custom ports, verbose, save report
python3 service_enumerator.py 192.168.1.1 -p 22,80,443,8080 -v -o report.json

# Quick scan with short timeout
python3 service_enumerator.py 10.0.0.1 -t 1.0""", language="bash")

    scenario_block("Building a Custom Tool for a Client", (
        "You are assessing a client's network and discover they run a custom "
        "TCP service on port 9999 that speaks a proprietary protocol. No existing "
        "scanner can analyze it. You build a Python tool that connects to the "
        "service, sends the protocol's handshake sequence (which you reverse-"
        "engineered from packet captures), and enumerates available commands. "
        "Your custom tool discovers that the service accepts unauthenticated "
        "administrative commands — a critical finding that no off-the-shelf tool "
        "would have caught."
    ))

    # ── Practice Challenge ──
    sub_header("Practice Challenge")
    info("Extend the service enumerator with one of these features:")
    info("  1. Add threading to scan ports in parallel (use concurrent.futures)")
    info("  2. Add a function that checks SSL/TLS certificate details")
    info("  3. Add output in CSV format in addition to JSON\n")

    if ask_yes_no("Would you like a hint?"):
        hint_text("For threading: use concurrent.futures.ThreadPoolExecutor with max_workers=20.")
        hint_text("For SSL: use ssl.create_default_context() and getpeercert().")

    press_enter()

    if ask_yes_no("Show the threaded scanning solution?"):
        code_block("""\
from concurrent.futures import ThreadPoolExecutor, as_completed

def scan_ports_threaded(host, ports, timeout=2.0, max_workers=20):
    \"\"\"Scan multiple ports concurrently using a thread pool.\"\"\"
    results = []

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Submit all port scans
        future_to_port = {
            executor.submit(scan_port, host, port, timeout): port
            for port in ports
        }

        # Collect results as they complete
        for future in as_completed(future_to_port):
            port = future_to_port[future]
            try:
                result = future.result()
                results.append(result)
                if result["state"] == "open":
                    print(f"  [+] Port {port} is open ({result['service']})")
            except Exception as e:
                print(f"  [-] Error scanning port {port}: {e}")

    # Sort by port number
    results.sort(key=lambda r: r["port"])
    return results

# Usage:
# results = scan_ports_threaded("192.168.1.1", range(1, 1025), timeout=1.0)
# Scans 1024 ports in seconds instead of minutes!""")
    press_enter()

    mark_lesson_complete(progress, MODULE_KEY, "lesson6")
    mark_challenge_complete(progress, MODULE_KEY, "security_tool")
    success("Lesson 6 complete: Building Security Tools")
    success("You have completed all lessons in Module 1!")
    press_enter()


# ──────────────────────────────────────────────────────────────────────
#  Quiz
# ──────────────────────────────────────────────────────────────────────
QUIZ_QUESTIONS = [
    {
        "q": "Which socket type provides reliable, ordered data delivery?",
        "options": [
            "A) SOCK_DGRAM",
            "B) SOCK_STREAM",
            "C) SOCK_RAW",
            "D) SOCK_SEQPACKET",
        ],
        "answer": "b",
        "explanation": "SOCK_STREAM is TCP, which provides reliable, ordered, connection-based byte streams. SOCK_DGRAM is UDP, which is connectionless and unreliable.",
    },
    {
        "q": "What is the main danger of using subprocess.run() with shell=True?",
        "options": [
            "A) It runs slower than without shell=True",
            "B) It does not capture stdout",
            "C) It enables command injection if user input is included",
            "D) It only works on Linux",
        ],
        "answer": "c",
        "explanation": "shell=True passes the command string to the system shell for interpretation. If user input is included, an attacker can inject additional commands using characters like ; | && etc.",
    },
    {
        "q": "Why should you use yaml.safe_load() instead of yaml.load()?",
        "options": [
            "A) safe_load() is faster",
            "B) yaml.load() can execute arbitrary Python code embedded in the YAML",
            "C) safe_load() supports more YAML features",
            "D) yaml.load() is deprecated and removed in Python 3.10+",
        ],
        "answer": "b",
        "explanation": "yaml.load() can instantiate arbitrary Python objects specified in the YAML, leading to remote code execution. yaml.safe_load() only creates basic Python types (dicts, lists, strings, numbers).",
    },
    {
        "q": "What does requests.Response.raise_for_status() do?",
        "options": [
            "A) Prints the HTTP status code to the console",
            "B) Returns True if the status code is 200",
            "C) Raises an HTTPError exception for 4xx and 5xx status codes",
            "D) Retries the request if the status code indicates failure",
        ],
        "answer": "c",
        "explanation": "raise_for_status() raises a requests.exceptions.HTTPError if the response status code indicates an error (400-599). It does nothing for successful responses (200-399).",
    },
    {
        "q": "Which regex pattern correctly matches an IPv4 address?",
        "options": [
            r"A) \d{3}\.\d{3}\.\d{3}\.\d{3}",
            r"B) \d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",
            r"C) [0-9]+\.[0-9]+\.[0-9]+\.[0-9]+",
            "D) Both B and C would match IPv4 addresses",
        ],
        "answer": "d",
        "explanation": r"Both B (\d{1,3} repeated) and C ([0-9]+ repeated) will match IPv4-formatted strings. Option A only matches exactly 3 digits per octet, missing addresses like 10.0.0.1.",
    },
    {
        "q": "What is the recommended way to send all data through a TCP socket?",
        "options": [
            "A) sock.send(data) in a loop checking the return value",
            "B) sock.sendall(data) which guarantees complete transmission",
            "C) sock.write(data) which handles buffering",
            "D) sock.sendto(data, address) for TCP connections",
        ],
        "answer": "b",
        "explanation": "sendall() continues sending data until all bytes are transmitted or an error occurs. send() may only send part of the data, requiring manual loop logic. sendto() is for UDP.",
    },
    {
        "q": "When creating temporary files for a security tool, which approach is most secure?",
        "options": [
            "A) open('/tmp/my_scan_results.txt', 'w')",
            "B) open(f'/tmp/scan_{random.randint(1,1000)}.txt', 'w')",
            "C) tempfile.NamedTemporaryFile(mode='w', prefix='scan_')",
            "D) os.system('touch /tmp/scan_temp.txt')",
        ],
        "answer": "c",
        "explanation": "tempfile.NamedTemporaryFile creates a file with a random name and restrictive permissions (owner-only). Predictable filenames in /tmp are vulnerable to symlink attacks and race conditions.",
    },
    {
        "q": "In the service enumerator tool, why do we use concurrent.futures.ThreadPoolExecutor for port scanning?",
        "options": [
            "A) Because Python sockets require threads to function",
            "B) Because scanning ports sequentially is very slow — each connection waits for a timeout",
            "C) Because threads provide better error handling than sequential code",
            "D) Because the operating system requires multi-threaded network access",
        ],
        "answer": "b",
        "explanation": "With a 2-second timeout, scanning 1000 ports sequentially could take up to 2000 seconds (33 minutes). With threading, many connections happen in parallel, reducing the scan to seconds.",
    },
]


# ──────────────────────────────────────────────────────────────────────
#  Module entry point
# ──────────────────────────────────────────────────────────────────────
def run(progress):
    """Main entry point called from the menu system."""
    module_key = MODULE_KEY
    while True:
        choice = show_menu("Module 1: Python for Security", [
            ("lesson1", "Lesson 1: Socket Programming Basics"),
            ("lesson2", "Lesson 2: HTTP with Requests"),
            ("lesson3", "Lesson 3: Subprocess & OS Interaction"),
            ("lesson4", "Lesson 4: File I/O for Security"),
            ("lesson5", "Lesson 5: Regex for Log Parsing"),
            ("lesson6", "Lesson 6: Building Security Tools"),
            ("quiz", "Take the Quiz"),
        ])

        if choice == "back":
            return
        if choice == "quit":
            raise SystemExit

        if choice == "lesson1":
            lesson_socket_basics(progress)
        elif choice == "lesson2":
            lesson_http_requests(progress)
        elif choice == "lesson3":
            lesson_subprocess_os(progress)
        elif choice == "lesson4":
            lesson_file_io(progress)
        elif choice == "lesson5":
            lesson_regex_logs(progress)
        elif choice == "lesson6":
            lesson_building_tools(progress)
        elif choice == "quiz":
            run_quiz(QUIZ_QUESTIONS, "python_security", module_key, progress)
