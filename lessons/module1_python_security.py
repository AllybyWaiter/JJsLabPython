"""
Module 1: Python for Security
Teaches foundational Python skills used in security work — sockets, HTTP requests,
subprocess management, file I/O, regex log parsing, and building security tools.
"""

from utils.display import (
    section_header, sub_header, lesson_block, code_block,
    scenario_block, why_it_matters, info, success, warning, press_enter,
    show_menu, disclaimer, hint_text, ask_yes_no, C, G, Y, R, RESET, BRIGHT, DIM,
    pace, learning_goal, nice_work, tip
)
from utils.progress import mark_lesson_complete, mark_challenge_complete
from utils.quiz import run_quiz
from utils.guided_practice import guided_practice
from utils.case_studies import show_case_study


# ──────────────────────────────────────────────────────────────────────
#  Module metadata
# ──────────────────────────────────────────────────────────────────────
MODULE_KEY = "module1"


# ──────────────────────────────────────────────────────────────────────
#  Lesson 1 — Socket Programming Basics
# ──────────────────────────────────────────────────────────────────────
def lesson_socket_basics(progress):
    section_header("Lesson 1: Socket Programming Basics")

    learning_goal([
        "Understand what sockets are and why they matter in security",
        "Know the difference between TCP and UDP sockets",
        "Write basic TCP and UDP client code in Python",
        "Resolve hostnames to IP addresses",
    ])

    lesson_block(
        "Sockets are the building blocks of all network communication. "
        "Every time your browser loads a page or a security tool connects "
        "to a target, sockets are doing the work underneath."
    )

    lesson_block(
        "A socket is simply an endpoint for sending or receiving data "
        "across a network. Python's built-in 'socket' module gives us "
        "full control over this low-level networking."
    )

    pace()

    lesson_block(
        "There are two main types of sockets. TCP sockets (SOCK_STREAM) "
        "provide reliable, ordered delivery — every byte arrives in the "
        "right order. Web servers, SSH, and most services use TCP."
    )

    lesson_block(
        "UDP sockets (SOCK_DGRAM) are faster but unreliable — packets "
        "can arrive out of order or be lost entirely. DNS queries and "
        "some scanning techniques use UDP."
    )

    pace()

    lesson_block(
        "The socket lifecycle follows a simple pattern: create a socket, "
        "connect to a host and port, send and receive data, then close "
        "the socket. Always use context managers or try/finally blocks "
        "to make sure sockets get closed."
    )

    tip("Forgetting to close sockets is a common bug. The 'with' statement handles this for you automatically.")

    pace()

    why_it_matters(
        "Security professionals need socket programming for writing custom scanners, "
        "building proof-of-concept exploit code, crafting specialized payloads, and "
        "understanding how network services communicate at the lowest level. When a "
        "commercial tool does not support a specific protocol or edge case, you need "
        "to be able to write your own socket-level code. Understanding sockets also "
        "helps you recognize and debug network-level attacks."
    )

    pace()

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

    pace()

    lesson_block(
        "A few important details: we use sendall() instead of send() — "
        "sendall() guarantees all bytes are transmitted. We also set a "
        "timeout so our program does not hang forever."
    )

    lesson_block(
        "The recv() call takes a buffer size — 4096 bytes is a common "
        "choice. If the response is larger, you would need to call "
        "recv() in a loop."
    )

    tip("sendall() is almost always what you want. Plain send() might only send part of your data.")

    pace()

    nice_work("You just learned how to create a raw TCP connection. That is the foundation of every network tool.")

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

    pace()

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

    pace()

    lesson_block(
        "Notice that with UDP there is no connect() call — you use sendto() which "
        "includes the destination address each time. Similarly, recvfrom() returns "
        "both the data and the address it came from. This is because UDP is "
        "connectionless — each packet is independent."
    )

    pace()

    nice_work("You now know both TCP and UDP sockets. Most security tools use TCP, but UDP knowledge is important for DNS and scanning work.")

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

    pace()

    scenario_block("Detecting a Rogue Service", (
        "During a routine network audit, you discover that port 4444 is open on a "
        "workstation. This port is commonly associated with Metasploit reverse shells. "
        "Using socket programming, you write a quick script that connects to the port, "
        "reads any banner or data the service sends, and logs it. The banner reveals "
        "a Meterpreter payload. Because you understood sockets, you could confirm "
        "the compromise in minutes rather than waiting for a full scan tool to run."
    ))

    pace()

    # ── Guided Practice ──
    guided_practice(
        title="Connect and Send",
        intro="Build a script that connects to a host, sends a message, and receives the response.",
        difficulty=progress.get("difficulty", "beginner"),
        steps=[
            {
                "instruction": (
                    "Create a TCP socket using a context manager and set a 5-second timeout.\n"
                    "Example: with socket.socket(AF_INET, SOCK_STREAM) as s:"
                ),
                "required_keywords": ["socket", "with", "settimeout"],
                "hints": [
                    "Start with: with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:",
                    "After the 'with' line, call s.settimeout(5)",
                ],
                "solution": (
                    "with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:\n"
                    "    s.settimeout(5)"
                ),
            },
            {
                "instruction": (
                    "Connect to a host and port, then send a message using sendall().\n"
                    "Remember: sendall() guarantees all bytes are sent."
                ),
                "required_keywords": ["connect", "sendall"],
                "hints": [
                    "Use s.connect((host, port)) to establish the connection.",
                    "Use s.sendall(message.encode()) to send the data.",
                ],
                "solution": (
                    "    s.connect((host, port))\n"
                    "    s.sendall(message.encode())"
                ),
                "context_code": (
                    "with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:\n"
                    "    s.settimeout(5)"
                ),
            },
            {
                "instruction": (
                    "Receive the response with recv() and add error handling\n"
                    "with try/except for timeouts."
                ),
                "required_keywords": ["recv", "except"],
                "hints": [
                    "Use response = s.recv(4096) to read up to 4096 bytes.",
                    "Wrap everything in try/except socket.timeout:",
                ],
                "solution": (
                    "    try:\n"
                    "        s.connect((host, port))\n"
                    "        s.sendall(message.encode())\n"
                    "        response = s.recv(4096)\n"
                    "        print(response.decode(errors='replace'))\n"
                    "    except socket.timeout:\n"
                    "        print('Connection timed out')"
                ),
                "context_code": (
                    "with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:\n"
                    "    s.settimeout(5)"
                ),
            },
        ],
        complete_solution=(
            "import socket\n\n"
            "def connect_and_send(host, port, message):\n"
            "    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:\n"
            "        s.settimeout(5)\n"
            "        try:\n"
            "            s.connect((host, port))\n"
            "            s.sendall(message.encode())\n"
            "            response = s.recv(4096)\n"
            "            print(f'Response: {response.decode(errors=\"replace\")}')\n"
            "        except socket.timeout:\n"
            "            print('Connection timed out')\n"
            "        except ConnectionRefusedError:\n"
            "            print(f'Connection refused on {host}:{port}')\n\n"
            "connect_and_send('127.0.0.1', 80, 'GET / HTTP/1.1\\r\\nHost: localhost\\r\\n\\r\\n')"
        ),
    )

    mark_lesson_complete(progress, MODULE_KEY, "lesson1")
    success("Lesson 1 complete: Socket Programming Basics")
    press_enter()


# ──────────────────────────────────────────────────────────────────────
#  Lesson 2 — HTTP with Requests
# ──────────────────────────────────────────────────────────────────────
def lesson_http_requests(progress):
    section_header("Lesson 2: HTTP with Requests")

    learning_goal([
        "Use Python's 'requests' library for HTTP communication",
        "Make GET and POST requests with custom headers",
        "Handle sessions, errors, and timeouts",
        "Understand when to disable SSL verification (and why it is risky)",
    ])

    lesson_block(
        "While raw sockets give you complete control, the 'requests' "
        "library is the standard tool for HTTP in Python. It handles "
        "connection pooling, cookies, redirects, and TLS/SSL for you."
    )

    lesson_block(
        "In security work, you will use requests constantly — for "
        "testing web apps, interacting with APIs, downloading files, "
        "and automating web-based assessments."
    )

    pace()

    lesson_block(
        "The requests library supports all HTTP methods: GET for "
        "retrieving data, POST for submitting data, PUT for updating, "
        "and DELETE for removing resources."
    )

    lesson_block(
        "Each method returns a Response object with the status code, "
        "headers, and body. Key status codes: 200 = success, 301/302 = "
        "redirect, 403 = forbidden, 404 = not found, 500 = server error."
    )

    tip("Memorize the common status codes. You will see them constantly in security work.")

    pace()

    why_it_matters(
        "Web applications are the most common attack surface for organizations. "
        "Security testers need to automate HTTP requests to test for vulnerabilities "
        "like SQL injection, cross-site scripting, broken authentication, and "
        "insecure API endpoints. The requests library lets you script these tests "
        "efficiently and repeatably. It is also essential for interacting with "
        "security APIs like VirusTotal, Shodan, and your SIEM's REST API."
    )

    pace()

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

    pace()

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

    pace()

    nice_work("You can now make GET and POST requests. These two methods cover the majority of web testing scenarios.")

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
print(response.json())""")

    pace()

    code_block("""\
import requests

# Basic HTTP Authentication
response = requests.get(
    "https://httpbin.org/basic-auth/user/pass",
    auth=("user", "pass")
)
print(f"Auth result: {response.status_code}")""")

    pace()

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

    tip("Use sessions when you need to stay logged in across multiple requests, like testing authenticated web apps.")

    pace()

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

    pace()

    nice_work("Great job covering error handling. This is what separates reliable tools from fragile scripts.")

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

    pace()

    scenario_block("API Key Discovery", (
        "A penetration tester is reviewing a web application and notices that the "
        "JavaScript source code contains an API endpoint URL. Using the requests "
        "library, they write a script to systematically test the API with different "
        "authentication headers. They discover that the API accepts an old, "
        "deprecated API key that was supposed to have been revoked, granting access "
        "to sensitive customer data. The requests library made it trivial to test "
        "hundreds of header combinations in seconds."
    ))

    pace()

    # ── Guided Practice ──
    guided_practice(
        title="URL Inspector",
        intro="Build a script that inspects a URL's response: status, headers, and version disclosure.",
        difficulty=progress.get("difficulty", "beginner"),
        steps=[
            {
                "instruction": (
                    "Make a GET request to a URL and print the status code.\n"
                    "Use the requests library with a timeout."
                ),
                "required_keywords": ["requests", "get", "status_code"],
                "hints": [
                    "Use resp = requests.get(url, timeout=10)",
                    "Print with: print(f'Status: {resp.status_code}')",
                ],
                "solution": (
                    "import requests\n\n"
                    "resp = requests.get('https://example.com', timeout=10)\n"
                    "print(f'Status: {resp.status_code} {resp.reason}')"
                ),
            },
            {
                "instruction": (
                    "Loop through all response headers and print each key-value pair.\n"
                    "Use the .items() method on the headers dict."
                ),
                "required_keywords": ["headers", "for", "items"],
                "hints": [
                    "Response headers are in resp.headers — it works like a dict.",
                    "Use: for key, value in resp.headers.items():",
                ],
                "solution": (
                    "for key, value in resp.headers.items():\n"
                    "    print(f'  {key}: {value}')"
                ),
                "context_code": (
                    "resp = requests.get('https://example.com', timeout=10)\n"
                    "print(f'Status: {resp.status_code} {resp.reason}')"
                ),
            },
            {
                "instruction": (
                    "Check the Server header for version disclosure.\n"
                    "Use the re module to look for version numbers (digits with dots)."
                ),
                "required_keywords": ["Server", "re"],
                "hints": [
                    "Get the header with: server = resp.headers.get('Server', '')",
                    "Use re.search(r'\\d+\\.\\d+', server) to find version numbers.",
                ],
                "solution": (
                    "import re\n\n"
                    "server = resp.headers.get('Server', '')\n"
                    "if server and re.search(r'\\d+\\.\\d+', server):\n"
                    "    print(f'[!] Version disclosed: {server}')\n"
                    "else:\n"
                    "    print(f'[i] Server: {server or \"not present\"}')"
                ),
                "context_code": (
                    "resp = requests.get('https://example.com', timeout=10)\n"
                    "print(f'Status: {resp.status_code}')\n"
                    "for key, value in resp.headers.items():\n"
                    "    print(f'  {key}: {value}')"
                ),
            },
        ],
        complete_solution=(
            "import requests\nimport re\n\n"
            "def inspect_url(url):\n"
            "    try:\n"
            "        resp = requests.get(url, timeout=10, allow_redirects=True)\n"
            "        print(f'Status: {resp.status_code} {resp.reason}')\n"
            "        print()\n"
            "        print('Response Headers:')\n"
            "        for key, value in resp.headers.items():\n"
            "            print(f'  {key}: {value}')\n"
            "        print()\n"
            "        print(f'Body (first 500 chars):\\n{resp.text[:500]}')\n"
            "        print()\n"
            "        server = resp.headers.get('Server', '')\n"
            "        if server:\n"
            "            if re.search(r'\\d+\\.\\d+', server):\n"
            "                print(f'[!] Server header discloses version: {server}')\n"
            "            else:\n"
            "                print(f'[i] Server header: {server} (no version found)')\n"
            "        else:\n"
            "            print('[i] No Server header present')\n"
            "    except requests.exceptions.RequestException as e:\n"
            "        print(f'Error: {e}')\n\n"
            "inspect_url('https://example.com')"
        ),
    )

    mark_lesson_complete(progress, MODULE_KEY, "lesson2")
    success("Lesson 2 complete: HTTP with Requests")
    press_enter()


# ──────────────────────────────────────────────────────────────────────
#  Lesson 3 — Subprocess & OS Interaction
# ──────────────────────────────────────────────────────────────────────
def lesson_subprocess_os(progress):
    section_header("Lesson 3: Subprocess & OS Interaction")

    learning_goal([
        "Run system commands safely from Python using subprocess",
        "Understand why shell=True is dangerous",
        "Search the filesystem with os.walk()",
        "Read environment variables for security checks",
    ])

    lesson_block(
        "Security tools often need to run system commands — launching "
        "nmap, calling openssl, or reading system configurations. "
        "Python's 'subprocess' module is the right way to do this."
    )

    lesson_block(
        "It replaces older functions like os.system() and os.popen() "
        "with a more powerful and secure interface."
    )

    pace()

    lesson_block(
        "The most important function is subprocess.run(). It executes "
        "a command and waits for it to finish. It returns an object "
        "with the return code, stdout, and stderr."
    )

    lesson_block(
        "You should almost always pass the command as a list of strings "
        "rather than a single string. This avoids shell injection "
        "vulnerabilities, which we will cover in a moment."
    )

    tip("Think of the list form as a safety net: each item in the list becomes exactly one argument.")

    pace()

    lesson_block(
        "The 'os' module provides helpful extras. os.walk() recursively "
        "traverses directories. os.environ gives you access to "
        "environment variables. os.path provides safe path handling."
    )

    pace()

    why_it_matters(
        "Improper use of subprocess is one of the most common sources of command "
        "injection vulnerabilities in Python applications. As a security professional, "
        "you need to know both how to use subprocess safely in your own tools and "
        "how to find unsafe usage in code you are reviewing. Many real-world "
        "vulnerabilities come from developers passing user input directly to "
        "shell=True commands."
    )

    pace()

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

    pace()

    nice_work("You just ran a system command safely from Python. The list form protects you from injection.")

    sub_header("DANGEROUS: shell=True with User Input")

    lesson_block(
        "When you pass shell=True, the command is interpreted by the "
        "system shell. This means an attacker can inject extra commands "
        "using characters like ; | && or backticks."
    )

    pace()

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
# The attacker's 'cat /etc/passwd' command runs too!""")

    pace()

    code_block("""\
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

    pace()

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

    pace()

    nice_work("os.walk() is a powerful tool for security auditing. You will use it a lot when hunting for misconfigurations.")

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

    tip("Environment variables are a common place for leaked secrets. Always check them during assessments.")

    pace()

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

    pace()

    scenario_block("Command Injection in a Web App", (
        "A developer builds an internal network diagnostic tool that lets users "
        "enter an IP address to ping. The backend uses subprocess.run(f'ping {ip}', "
        "shell=True). An attacker enters '8.8.8.8; whoami' and gets command execution "
        "on the server. The fix: use subprocess.run(['ping', '-c', '3', ip]) which "
        "treats the IP as a single argument, preventing injection. Always validate "
        "input AND use list-form commands."
    ))

    pace()

    # ── Guided Practice ──
    guided_practice(
        title="Safe Command Runner",
        intro="Build a function that safely runs system commands with error handling.",
        difficulty=progress.get("difficulty", "beginner"),
        steps=[
            {
                "instruction": (
                    "Define a function called safe_run that takes a command list\n"
                    "and calls subprocess.run() with capture_output=True and text=True."
                ),
                "required_keywords": ["def", "subprocess", "run"],
                "hints": [
                    "Start with: def safe_run(cmd_list, timeout=10):",
                    "Inside, call: proc = subprocess.run(cmd_list, capture_output=True, text=True)",
                ],
                "solution": (
                    "import subprocess\n\n"
                    "def safe_run(cmd_list, timeout=10):\n"
                    "    proc = subprocess.run(\n"
                    "        cmd_list,\n"
                    "        capture_output=True,\n"
                    "        text=True,\n"
                    "        timeout=timeout\n"
                    "    )\n"
                    "    return proc"
                ),
            },
            {
                "instruction": (
                    "Add error handling for TimeoutExpired and capture_output.\n"
                    "Wrap the subprocess.run() call in try/except."
                ),
                "required_keywords": ["capture_output", "TimeoutExpired"],
                "hints": [
                    "Use try/except subprocess.TimeoutExpired to catch slow commands.",
                    "Don't forget capture_output=True to grab stdout and stderr.",
                ],
                "solution": (
                    "def safe_run(cmd_list, timeout=10):\n"
                    "    result = {'success': False, 'output': '', 'error': ''}\n"
                    "    try:\n"
                    "        proc = subprocess.run(\n"
                    "            cmd_list, capture_output=True, text=True, timeout=timeout\n"
                    "        )\n"
                    "        result['success'] = proc.returncode == 0\n"
                    "        result['output'] = proc.stdout.strip()\n"
                    "    except subprocess.TimeoutExpired:\n"
                    "        result['error'] = 'Command timed out'\n"
                    "    return result"
                ),
                "context_code": (
                    "import subprocess\n\n"
                    "def safe_run(cmd_list, timeout=10):"
                ),
            },
            {
                "instruction": (
                    "Use your safe_run function to get the system hostname and\n"
                    "current user (whoami). Print the results."
                ),
                "required_keywords": ["hostname", "whoami"],
                "hints": [
                    "Call safe_run(['hostname']) and safe_run(['whoami'])",
                    "Check result['success'] before printing result['output']",
                ],
                "solution": (
                    "for label, cmd in [('Hostname', ['hostname']), ('User', ['whoami'])]:\n"
                    "    r = safe_run(cmd)\n"
                    "    if r['success']:\n"
                    "        print(f'  {label}: {r[\"output\"]}')\n"
                    "    else:\n"
                    "        print(f'  {label}: ERROR - {r[\"error\"]}')"
                ),
            },
        ],
        complete_solution=(
            "import subprocess\n\n"
            "def safe_run(cmd_list, timeout=10):\n"
            "    result = {'success': False, 'output': '', 'error': '', 'returncode': -1}\n"
            "    try:\n"
            "        proc = subprocess.run(\n"
            "            cmd_list, capture_output=True, text=True, timeout=timeout\n"
            "        )\n"
            "        result['returncode'] = proc.returncode\n"
            "        result['output'] = proc.stdout.strip()\n"
            "        result['error'] = proc.stderr.strip()\n"
            "        result['success'] = proc.returncode == 0\n"
            "    except subprocess.TimeoutExpired:\n"
            "        result['error'] = f'Timed out after {timeout}s'\n"
            "    except FileNotFoundError:\n"
            "        result['error'] = f'Command not found: {cmd_list[0]}'\n"
            "    return result\n\n"
            "for label, cmd in [\n"
            "    ('Hostname', ['hostname']),\n"
            "    ('User', ['whoami']),\n"
            "    ('Python', ['python3', '--version']),\n"
            "]:\n"
            "    r = safe_run(cmd)\n"
            "    if r['success']:\n"
            "        print(f'  {label}: {r[\"output\"]}')\n"
            "    else:\n"
            "        print(f'  {label}: ERROR - {r[\"error\"]}')"
        ),
    )

    mark_lesson_complete(progress, MODULE_KEY, "lesson3")
    success("Lesson 3 complete: Subprocess & OS Interaction")
    press_enter()


# ──────────────────────────────────────────────────────────────────────
#  Lesson 4 — File I/O for Security
# ──────────────────────────────────────────────────────────────────────
def lesson_file_io(progress):
    section_header("Lesson 4: File I/O for Security")

    learning_goal([
        "Read and write files safely with context managers",
        "Set proper file permissions on sensitive output",
        "Parse common config file formats (INI, JSON, YAML)",
        "Create secure temporary files",
    ])

    lesson_block(
        "File I/O is fundamental to security work. You will read log "
        "files to hunt for threats, parse configuration files to find "
        "misconfigurations, and write reports."
    )

    lesson_block(
        "Getting file handling right matters both for your tools to "
        "work correctly and to avoid creating security vulnerabilities "
        "of your own."
    )

    pace()

    lesson_block(
        "Always use 'with' statements so files are properly closed, "
        "even if an exception occurs. For text files, specify the "
        "encoding explicitly — utf-8 is the most common."
    )

    lesson_block(
        "For binary files (executables, images, packets), use 'rb' or "
        "'wb' mode. Never use string mode for binary data."
    )

    tip("The 'with' pattern is your best friend for files, just like it is for sockets.")

    pace()

    lesson_block(
        "When writing security tools, also think about file permissions, "
        "race conditions, path traversal attacks, and secure handling of "
        "temporary files. The tempfile module provides secure defaults."
    )

    pace()

    why_it_matters(
        "Configuration files often contain hardcoded credentials, overly permissive "
        "settings, and default passwords. Log files contain evidence of attacks, "
        "unauthorized access, and data exfiltration. Your security tools need to "
        "read and write files safely — a vulnerability in your own tooling could "
        "be exploited by a sophisticated attacker. Insecure temp files have been "
        "the source of privilege escalation bugs in major software."
    )

    pace()

    sub_header("Reading Text Files Safely")
    code_block("""\
# Always use context managers and explicit encoding
with open("/var/log/auth.log", "r", encoding="utf-8", errors="replace") as f:
    for line_number, line in enumerate(f, 1):
        if "Failed password" in line:
            print(f"Line {line_number}: {line.strip()}")""")

    pace()

    code_block("""\
# Read entire file into memory (only for small files)
with open("config.txt", "r", encoding="utf-8") as f:
    content = f.read()
    print(f"File is {len(content)} characters long")

# Read lines into a list
with open("targets.txt", "r") as f:
    targets = [line.strip() for line in f if line.strip()]
    print(f"Loaded {len(targets)} targets")""")

    pace()

    nice_work("You have the basics of reading files safely. Now let's look at writing.")

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

    tip("Always restrict file permissions on scan reports and findings. You do not want other users reading sensitive results.")

    pace()

    sub_header("Parsing Configuration Files")

    lesson_block(
        "Security assessments often involve reviewing config files in "
        "several formats. Here is how to parse the most common ones."
    )

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
    print("[!] Password found in config file!")""")

    pace()

    code_block("""\
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

    pace()

    nice_work("Config file parsing is a core skill for security auditing. Great progress.")

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
print(f"SHA-256: {file_hash}")""")

    pace()

    code_block("""\
# Read binary file header (e.g., check for ELF magic bytes)
with open("/usr/bin/python3", "rb") as f:
    magic = f.read(4)
    if magic == b"\\x7fELF":
        print("This is an ELF binary")
    elif magic[:2] == b"MZ":
        print("This is a Windows PE binary")""")

    tip("File hashing is essential for verifying file integrity and comparing malware samples.")

    pace()

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
print("Temp file deleted")""")

    pace()

    code_block("""\
# For directories, use tempfile.TemporaryDirectory()
with tempfile.TemporaryDirectory(prefix='seclab_') as tmp_dir:
    print(f"Temp dir: {tmp_dir}")
    # Directory and contents are automatically deleted""")

    pace()

    scenario_block("Credential Discovery in Config Files", (
        "During a security assessment, you write a script that recursively searches "
        "a web server's document root for configuration files. The script finds a "
        ".env file containing database credentials, a config.php with an API key, "
        "and a backup.sql file with user password hashes. These files were "
        "accidentally deployed to the production server. Your file I/O skills let "
        "you quickly identify and report these exposures before an attacker finds them."
    ))

    pace()

    # ── Guided Practice ──
    guided_practice(
        title="Secret Scanner",
        intro="Build a script that scans directories for files that might contain secrets.",
        difficulty=progress.get("difficulty", "beginner"),
        steps=[
            {
                "instruction": (
                    "Define a function and use os.walk() to loop through all\n"
                    "files in a directory tree. os.walk() yields (dirpath, dirnames, filenames)."
                ),
                "required_keywords": ["def", "os.walk", "for"],
                "hints": [
                    "Start with: def scan_for_secrets(start_path):",
                    "Use: for dirpath, dirnames, filenames in os.walk(start_path):",
                ],
                "solution": (
                    "import os\n\n"
                    "def scan_for_secrets(start_path):\n"
                    "    for dirpath, dirnames, filenames in os.walk(start_path):\n"
                    "        for fname in filenames:\n"
                    "            print(fname)"
                ),
            },
            {
                "instruction": (
                    "Check each filename for suspicious patterns like .env and .key.\n"
                    "Look for filenames containing 'password', 'secret', or ending in '.key', '.pem'."
                ),
                "required_keywords": ["if", ".env", ".key"],
                "hints": [
                    "Check with: if '.env' in fname or fname.endswith('.key'):",
                    "You can also use: any(pat in fname for pat in ['.env', 'secret', 'password'])",
                ],
                "solution": (
                    "    for fname in filenames:\n"
                    "        fname_lower = fname.lower()\n"
                    "        if any(p in fname_lower for p in ['.env', 'password', 'secret']):\n"
                    "            print(f'Suspicious: {fname}')\n"
                    "        elif fname_lower.endswith(('.key', '.pem')):\n"
                    "            print(f'Suspicious: {fname}')"
                ),
                "context_code": (
                    "def scan_for_secrets(start_path):\n"
                    "    for dirpath, dirnames, filenames in os.walk(start_path):"
                ),
            },
            {
                "instruction": (
                    "Get file permissions using os.stat() and print results.\n"
                    "Use stat.filemode() to convert permission bits to a readable string."
                ),
                "required_keywords": ["stat", "print"],
                "hints": [
                    "Build the full path: full_path = os.path.join(dirpath, fname)",
                    "Get info: st = os.stat(full_path) then stat.filemode(st.st_mode)",
                ],
                "solution": (
                    "import stat\n\n"
                    "full_path = os.path.join(dirpath, fname)\n"
                    "st = os.stat(full_path)\n"
                    "mode = stat.filemode(st.st_mode)\n"
                    "print(f'  [{mode}] {st.st_size:>8} bytes  {full_path}')"
                ),
                "context_code": (
                    "def scan_for_secrets(start_path):\n"
                    "    for dirpath, dirnames, filenames in os.walk(start_path):\n"
                    "        for fname in filenames:\n"
                    "            if is_suspicious:  # (pattern matching from step 2)\n"
                    "                # Get file info here"
                ),
            },
        ],
        complete_solution=(
            "import os\nimport stat\n\n"
            "def scan_for_secrets(start_path):\n"
            "    secret_patterns = ['.env', 'password', 'secret', 'credential', 'private']\n"
            "    secret_extensions = ['.key', '.pem', '.p12', '.pfx', '.jks']\n"
            "    findings = []\n\n"
            "    for dirpath, dirnames, filenames in os.walk(start_path):\n"
            "        dirnames[:] = [d for d in dirnames if not d.startswith('.')]\n"
            "        for fname in filenames:\n"
            "            fname_lower = fname.lower()\n"
            "            is_suspicious = (\n"
            "                any(pat in fname_lower for pat in secret_patterns) or\n"
            "                any(fname_lower.endswith(ext) for ext in secret_extensions)\n"
            "            )\n"
            "            if is_suspicious:\n"
            "                full_path = os.path.join(dirpath, fname)\n"
            "                try:\n"
            "                    st = os.stat(full_path)\n"
            "                    mode = stat.filemode(st.st_mode)\n"
            "                    findings.append((full_path, mode, st.st_size))\n"
            "                except PermissionError:\n"
            "                    findings.append((full_path, 'ACCESS DENIED', 0))\n\n"
            "    print(f'Scan complete. {len(findings)} suspicious files:')\n"
            "    for path, mode, size in findings:\n"
            "        print(f'  [{mode}] {size:>8} bytes  {path}')\n"
            "    return findings\n\n"
            "scan_for_secrets(os.path.expanduser('~'))"
        ),
    )

    mark_lesson_complete(progress, MODULE_KEY, "lesson4")
    success("Lesson 4 complete: File I/O for Security")
    press_enter()


# ──────────────────────────────────────────────────────────────────────
#  Lesson 5 — Regex for Log Parsing
# ──────────────────────────────────────────────────────────────────────
def lesson_regex_logs(progress):
    section_header("Lesson 5: Regex for Log Parsing")

    learning_goal([
        "Use Python's 're' module to search and extract data",
        "Extract IP addresses, timestamps, and usernames from logs",
        "Detect attack patterns like SQL injection and XSS in log data",
        "Build a simple brute-force detection script",
    ])

    lesson_block(
        "Regular expressions (regex) are essential for security analysts. "
        "Log files are your primary source of evidence during incidents, "
        "and they can be millions of lines long."
    )

    lesson_block(
        "Regex lets you extract exactly the data you need: IP addresses, "
        "timestamps, usernames, URLs, error codes, and attack patterns."
    )

    pace()

    lesson_block(
        "Python's 're' module provides full regex support. The key "
        "functions are: re.search() to find the first match, "
        "re.findall() to find all matches, and re.sub() to replace."
    )

    lesson_block(
        "You can compile patterns with re.compile() for better "
        "performance when using the same pattern many times."
    )

    tip("Start simple and build up. Test your regex on a few sample lines before running it on a huge log file.")

    pace()

    lesson_block(
        "Key metacharacters: \\d for digits, \\w for word characters, "
        "\\s for whitespace, . for any character, * for zero or more, "
        "+ for one or more, and ( ) for capture groups."
    )

    lesson_block(
        "Named groups (?P<name>...) make your patterns easier to read "
        "and maintain — highly recommended for complex log parsing."
    )

    pace()

    why_it_matters(
        "When a security incident occurs, the clock is ticking. You need to quickly "
        "sift through massive log files to answer critical questions: Which IP "
        "addresses were involved? When did the attack start? What credentials were "
        "targeted? What data was accessed? Regex mastery lets you answer these "
        "questions in minutes instead of hours. It is the difference between "
        "containing a breach quickly and letting it spread."
    )

    pace()

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

    pace()

    nice_work("Extracting and counting IPs is one of the most common tasks in incident response. You just nailed it.")

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

    tip("Named groups like (?P<ip>...) make complex patterns much easier to understand when you revisit them later.")

    pace()

    sub_header("Detecting Attack Patterns")

    lesson_block(
        "Regex is great for spotting attack signatures in logs. Let's "
        "build patterns for SQL injection and cross-site scripting (XSS)."
    )

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
sqli_regex = re.compile('|'.join(sqli_patterns), re.IGNORECASE)""")

    pace()

    code_block("""\
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

    pace()

    nice_work("You can now detect common web attack patterns in log data. This is a core incident response skill.")

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

    pace()

    sub_header("Practical: Failed Login Detector")

    lesson_block(
        "Let's put it all together with a practical brute-force "
        "detection script that parses authentication logs."
    )

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
              f"{len(unique_users)} unique usernames")""")

    pace()

    code_block("""\
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

    pace()

    scenario_block("Incident Response at 3 AM", (
        "Your SIEM triggers an alert at 3 AM — a spike in 401 errors on the payment "
        "API. You SSH into the server and use regex to parse the nginx access logs. "
        "Within 5 minutes, you identify 47,000 requests from a single IP trying "
        "different credit card numbers against the payment endpoint. Your regex "
        "extracts the source IP, the endpoint pattern, and the time window. You "
        "block the IP, generate a report, and assess the damage — all using regex "
        "skills you practiced in advance."
    ))

    pace()

    # ── Guided Practice ──
    guided_practice(
        title="Log Analyzer",
        intro="Build a log analyzer that extracts IPs, status codes, and attack patterns.",
        difficulty=progress.get("difficulty", "beginner"),
        steps=[
            {
                "instruction": (
                    "Compile regex patterns for extracting IP addresses and\n"
                    "HTTP status codes. Use re.compile() with \\d for digits."
                ),
                "required_keywords": ["re", "compile", "\\d"],
                "hints": [
                    "IP pattern: re.compile(r'\\b(\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3})\\b')",
                    "Status pattern: re.compile(r'\\s([45]\\d{2})\\s') matches 4xx and 5xx codes.",
                ],
                "solution": (
                    "import re\n\n"
                    "ip_re = re.compile(r'\\b(\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3})\\b')\n"
                    "status_re = re.compile(r'\\s([45]\\d{2})\\s')"
                ),
            },
            {
                "instruction": (
                    "Loop through log lines and use .search() to find matches.\n"
                    "Append each found IP to a list for counting later."
                ),
                "required_keywords": ["for", "search", "append"],
                "hints": [
                    "Loop: for line in log_lines:",
                    "Search: match = ip_re.search(line) then ips.append(match.group(1))",
                ],
                "solution": (
                    "ips = []\nerrors = []\n\n"
                    "for line in log_lines:\n"
                    "    ip_match = ip_re.search(line)\n"
                    "    if ip_match:\n"
                    "        ips.append(ip_match.group(1))\n"
                    "    status_match = status_re.search(line)\n"
                    "    if status_match:\n"
                    "        errors.append((status_match.group(1), line.strip()))"
                ),
                "context_code": (
                    "ip_re = re.compile(r'\\b(\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3})\\b')\n"
                    "status_re = re.compile(r'\\s([45]\\d{2})\\s')"
                ),
            },
            {
                "instruction": (
                    "Print a summary report showing IP counts using Counter.\n"
                    "Import Counter from collections and use .most_common()."
                ),
                "required_keywords": ["print", "Counter"],
                "hints": [
                    "Import: from collections import Counter",
                    "Use: Counter(ips).most_common(10) to get the top 10 IPs.",
                ],
                "solution": (
                    "from collections import Counter\n\n"
                    "print(f'Total lines: {len(log_lines)}')\n"
                    "print('\\nTop IPs:')\n"
                    "for ip, count in Counter(ips).most_common(10):\n"
                    "    print(f'  {ip}: {count}')\n"
                    "print(f'\\nError responses: {len(errors)}')"
                ),
            },
        ],
        complete_solution=(
            "import re\nfrom collections import Counter\n\n"
            "def analyze_logs(log_lines):\n"
            "    ip_re = re.compile(r'\\b(\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3})\\b')\n"
            "    status_re = re.compile(r'\\s([45]\\d{2})\\s')\n"
            "    sqli_re = re.compile(\n"
            "        r'(UNION\\s+SELECT|OR\\s+1\\s*=\\s*1|DROP\\s+TABLE)',\n"
            "        re.IGNORECASE\n"
            "    )\n\n"
            "    ips = []\n"
            "    errors = []\n"
            "    sqli_attempts = []\n\n"
            "    for line in log_lines:\n"
            "        ip_match = ip_re.search(line)\n"
            "        if ip_match:\n"
            "            ips.append(ip_match.group(1))\n"
            "        status_match = status_re.search(line)\n"
            "        if status_match:\n"
            "            errors.append((status_match.group(1), line.strip()))\n"
            "        if sqli_re.search(line):\n"
            "            sqli_attempts.append(line.strip())\n\n"
            "    print(f'Total lines: {len(log_lines)}')\n"
            "    print('\\nTop IPs:')\n"
            "    for ip, count in Counter(ips).most_common(10):\n"
            "        print(f'  {ip}: {count}')\n"
            "    print(f'\\nError responses: {len(errors)}')\n"
            "    for code, line in errors[:5]:\n"
            "        print(f'  [{code}] {line[:80]}')\n"
            "    print(f'\\nSQLi attempts: {len(sqli_attempts)}')\n"
            "    for line in sqli_attempts:\n"
            "        print(f'  [!] {line[:80]}')"
        ),
    )

    mark_lesson_complete(progress, MODULE_KEY, "lesson5")
    success("Lesson 5 complete: Regex for Log Parsing")
    press_enter()


# ──────────────────────────────────────────────────────────────────────
#  Lesson 6 — Building Security Tools
# ──────────────────────────────────────────────────────────────────────
def lesson_building_tools(progress):
    section_header("Lesson 6: Building Security Tools")

    learning_goal([
        "Combine sockets, HTTP, subprocess, file I/O, and regex into a real tool",
        "Structure a security tool with argument parsing and error handling",
        "Build a service enumerator that scans ports and checks HTTP headers",
    ])

    lesson_block(
        "Now it is time to combine everything you have learned into "
        "real security tools. Professional security engineers build "
        "custom tools every day."
    )

    lesson_block(
        "Sometimes the available tools do not cover your use case. "
        "Sometimes you need to automate a repetitive task. And "
        "sometimes building a tool is the best way to deeply "
        "understand a protocol or vulnerability."
    )

    pace()

    lesson_block(
        "Good security tools share common traits: they accept "
        "command-line arguments, handle errors gracefully, produce "
        "clear output, and log their actions for audit trails."
    )

    lesson_block(
        "The tool we will build is a 'Service Enumerator' — it scans "
        "ports, grabs banners, checks HTTP headers, and produces a "
        "formatted report."
    )

    pace()

    why_it_matters(
        "The ability to rapidly build custom security tools sets apart senior "
        "security engineers from those who can only use existing tools. When you "
        "encounter a novel situation — a custom protocol, a unique vulnerability, "
        "an internal application with no public tooling — you need to be able to "
        "write your own solution. This lesson brings together everything from the "
        "module into a practical, real-world skill."
    )

    pace()

    sub_header("Tool Architecture")

    lesson_block(
        "We will build the tool in sections: argument parsing, port "
        "scanning, HTTP header checks, report generation, and a main "
        "function that ties it all together."
    )

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

    tip("argparse makes your tools flexible. Users can customize behavior without editing code.")

    pace()

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

    pace()

    nice_work("The port scanner is done. Notice how it reuses everything you learned about sockets.")

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

    pace()

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

    pace()

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

    pace()

    sub_header("Running the Tool")
    code_block("""\
# Basic scan
python3 service_enumerator.py example.com

# Custom ports, verbose, save report
python3 service_enumerator.py 192.168.1.1 -p 22,80,443,8080 -v -o report.json

# Quick scan with short timeout
python3 service_enumerator.py 10.0.0.1 -t 1.0""", language="bash")

    pace()

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

    pace()

    # ── Guided Practice ──
    guided_practice(
        title="Threaded Port Scanner",
        intro="Add threading to the service enumerator so it scans ports in parallel.",
        difficulty=progress.get("difficulty", "beginner"),
        steps=[
            {
                "instruction": (
                    "Import ThreadPoolExecutor from concurrent.futures.\n"
                    "This lets you run multiple port scans at the same time."
                ),
                "required_keywords": ["concurrent", "ThreadPoolExecutor"],
                "hints": [
                    "Use: from concurrent.futures import ThreadPoolExecutor, as_completed",
                    "ThreadPoolExecutor manages a pool of worker threads for you.",
                ],
                "solution": (
                    "from concurrent.futures import ThreadPoolExecutor, as_completed"
                ),
            },
            {
                "instruction": (
                    "Create an executor and submit a scan task for each port.\n"
                    "Use executor.submit() to queue each port scan."
                ),
                "required_keywords": ["submit", "executor"],
                "hints": [
                    "Use: with ThreadPoolExecutor(max_workers=20) as executor:",
                    "Submit tasks: future = executor.submit(scan_port, host, port, timeout)",
                ],
                "solution": (
                    "with ThreadPoolExecutor(max_workers=20) as executor:\n"
                    "    future_to_port = {\n"
                    "        executor.submit(scan_port, host, port, timeout): port\n"
                    "        for port in ports\n"
                    "    }"
                ),
                "context_code": (
                    "from concurrent.futures import ThreadPoolExecutor, as_completed"
                ),
            },
            {
                "instruction": (
                    "Collect results as they complete using as_completed().\n"
                    "Call future.result() to get each scan's return value."
                ),
                "required_keywords": ["as_completed", "result"],
                "hints": [
                    "Loop: for future in as_completed(future_to_port):",
                    "Get the value: result = future.result()",
                ],
                "solution": (
                    "    for future in as_completed(future_to_port):\n"
                    "        port = future_to_port[future]\n"
                    "        try:\n"
                    "            result = future.result()\n"
                    "            results.append(result)\n"
                    "            if result['state'] == 'open':\n"
                    "                print(f'  [+] Port {port} is open')\n"
                    "        except Exception as e:\n"
                    "            print(f'  [-] Error scanning port {port}: {e}')"
                ),
                "context_code": (
                    "with ThreadPoolExecutor(max_workers=20) as executor:\n"
                    "    future_to_port = {\n"
                    "        executor.submit(scan_port, host, port, timeout): port\n"
                    "        for port in ports\n"
                    "    }"
                ),
            },
        ],
        complete_solution=(
            "from concurrent.futures import ThreadPoolExecutor, as_completed\n\n"
            "def scan_ports_threaded(host, ports, timeout=2.0, max_workers=20):\n"
            "    results = []\n\n"
            "    with ThreadPoolExecutor(max_workers=max_workers) as executor:\n"
            "        future_to_port = {\n"
            "            executor.submit(scan_port, host, port, timeout): port\n"
            "            for port in ports\n"
            "        }\n\n"
            "        for future in as_completed(future_to_port):\n"
            "            port = future_to_port[future]\n"
            "            try:\n"
            "                result = future.result()\n"
            "                results.append(result)\n"
            "                if result['state'] == 'open':\n"
            "                    print(f'  [+] Port {port} is open ({result[\"service\"]})')\n"
            "            except Exception as e:\n"
            "                print(f'  [-] Error scanning port {port}: {e}')\n\n"
            "    results.sort(key=lambda r: r['port'])\n"
            "    return results\n\n"
            "# Usage:\n"
            "# results = scan_ports_threaded('192.168.1.1', range(1, 1025), timeout=1.0)\n"
            "# Scans 1024 ports in seconds instead of minutes!"
        ),
    )

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
    show_case_study("module1")
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
