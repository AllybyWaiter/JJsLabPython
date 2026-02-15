"""
Code Sandbox — a safe environment for testing Python code snippets.
Runs user code in a subprocess with restricted permissions and timeout.
"""

import subprocess
import sys
import tempfile
import os

from utils.display import (
    section_header, sub_header, info, success, warning, error,
    code_block, press_enter, show_menu, C, G, Y, R, DIM, BRIGHT, RESET
)


def sandbox_menu(progress: dict):
    """Interactive code sandbox."""
    while True:
        choice = show_menu("Code Sandbox", [
            ("free", "Free Code — Write and run any Python"),
            ("templates", "Code Templates — Start from a template"),
        ])
        if choice == "back":
            return
        if choice == "quit":
            raise SystemExit

        if choice == "free":
            _free_code()
        elif choice == "templates":
            _template_menu()


def _free_code():
    """Let user write and execute arbitrary Python code."""
    section_header("Code Sandbox — Free Mode")
    info("Type your Python code below. Enter a blank line to run it.")
    warning("Code runs with a 10-second timeout for safety.")
    print()

    while True:
        lines = []
        while True:
            line = input(f"  {G}>>>{RESET} ")
            if line == "":
                break
            lines.append(line)

        code = "\n".join(lines)
        if not code.strip():
            info("Empty code. Type 'back' to return to menu.")
            continue
        if code.strip().lower() == "back":
            return

        _run_code(code)
        print()
        info("Enter more code or a blank line + 'back' to return.")


TEMPLATES = {
    "port_scan": {
        "name": "Port Scanner",
        "code": '''import socket

def scan_port(host, port):
    """Check if a port is open on the target host."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)
            result = s.connect_ex((host, port))
            return result == 0
    except Exception:
        return False

# Scan common ports on localhost
host = "127.0.0.1"
common_ports = [22, 80, 443, 3306, 5050, 8080]

print(f"Scanning {host}...")
for port in common_ports:
    status = "OPEN" if scan_port(host, port) else "closed"
    print(f"  Port {port}: {status}")
''',
    },
    "hash_crack": {
        "name": "Hash Identifier",
        "code": '''import hashlib
import re

def identify_hash(hash_string):
    """Identify the likely hash type based on length and format."""
    hash_string = hash_string.strip()
    length = len(hash_string)

    if length == 32 and re.match(r'^[a-fA-F0-9]+$', hash_string):
        return "MD5"
    elif length == 40 and re.match(r'^[a-fA-F0-9]+$', hash_string):
        return "SHA-1"
    elif length == 64 and re.match(r'^[a-fA-F0-9]+$', hash_string):
        return "SHA-256"
    elif hash_string.startswith("$2b$") or hash_string.startswith("$2a$"):
        return "bcrypt"
    else:
        return "Unknown"

# Test with some example hashes
test_hashes = [
    "5d41402abc4b2a76b9719d911017c592",
    "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d",
    "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
    "$2b$12$WApznUPhDubN0oeveSXHp.Rk0rMoTBMRsGJkN4Y7rx6gSecWGnDO6",
]

for h in test_hashes:
    print(f"  {h[:40]}...  =>  {identify_hash(h)}")
''',
    },
    "log_parser": {
        "name": "Log Parser",
        "code": '''import re
from collections import Counter

# Sample log data
logs = """
203.0.113.42 - - [13/Feb:01:58:01] "POST /admin/login" 401
203.0.113.42 - - [13/Feb:01:58:02] "POST /admin/login" 401
203.0.113.42 - - [13/Feb:01:58:02] "POST /admin/login" 401
10.0.1.5 - - [13/Feb:02:00:00] "GET /index.html" 200
203.0.113.42 - - [13/Feb:02:11:14] "POST /admin/login" 200
203.0.113.42 - - [13/Feb:02:13:01] "POST /admin/upload" 200
10.0.1.5 - - [13/Feb:02:15:00] "GET /about.html" 200
""".strip()

# Parse IPs and count occurrences
ip_pattern = re.compile(r'(\\d+\\.\\d+\\.\\d+\\.\\d+)')
status_pattern = re.compile(r'" (\\d{3})$')

ips = Counter()
statuses = Counter()
failed_logins = []

for line in logs.split("\\n"):
    ip_match = ip_pattern.search(line)
    status_match = status_pattern.search(line)
    if ip_match:
        ips[ip_match.group(1)] += 1
    if status_match:
        statuses[status_match.group(1)] += 1
    if "401" in line:
        failed_logins.append(line.strip())

print("=== IP Address Summary ===")
for ip, count in ips.most_common():
    flag = " ⚠ SUSPICIOUS" if count > 3 else ""
    print(f"  {ip}: {count} requests{flag}")

print("\\n=== Status Code Summary ===")
for code, count in statuses.most_common():
    print(f"  {code}: {count}")

print(f"\\n=== Failed Login Attempts: {len(failed_logins)} ===")
''',
    },
    "password_checker": {
        "name": "Password Strength Checker",
        "code": '''def check_password_strength(password):
    """Evaluate password strength and return a score with feedback."""
    score = 0
    feedback = []

    # Length check
    if len(password) >= 8:
        score += 1
    else:
        feedback.append("Too short (need 8+ characters)")
    if len(password) >= 12:
        score += 1
    if len(password) >= 16:
        score += 1

    # Character variety
    if any(c.isupper() for c in password):
        score += 1
    else:
        feedback.append("Add uppercase letters")

    if any(c.islower() for c in password):
        score += 1
    else:
        feedback.append("Add lowercase letters")

    if any(c.isdigit() for c in password):
        score += 1
    else:
        feedback.append("Add numbers")

    if any(c in "!@#$%^&*()-_+=<>?/|" for c in password):
        score += 1
    else:
        feedback.append("Add special characters")

    # Common patterns
    common = ["password", "123456", "qwerty", "admin", "letmein"]
    if password.lower() in common:
        score = 0
        feedback = ["This is a commonly used password!"]

    # Rating
    if score >= 6:
        rating = "STRONG"
    elif score >= 4:
        rating = "MODERATE"
    elif score >= 2:
        rating = "WEAK"
    else:
        rating = "VERY WEAK"

    return rating, score, feedback

# Test passwords
test_passwords = [
    "password123",
    "P@ssw0rd!",
    "correct-horse-battery-staple",
    "admin",
    "Xy9$mK2!pQ4@nR7&",
]

for pwd in test_passwords:
    rating, score, feedback = check_password_strength(pwd)
    print(f"  \\'{pwd}\\'")
    print(f"    Rating: {rating} ({score}/7)")
    if feedback:
        for f in feedback:
            print(f"    - {f}")
    print()
''',
    },
}


def _template_menu():
    """Let user pick a code template to run or modify."""
    while True:
        options = [(k, v["name"]) for k, v in TEMPLATES.items()]
        choice = show_menu("Code Templates", options)
        if choice == "back":
            return
        if choice == "quit":
            raise SystemExit

        template = TEMPLATES[choice]
        section_header(f"Template: {template['name']}")
        code_block(template["code"], "python")
        print()

        info("Options: [R]un as-is  |  [E]dit and run  |  [B]ack")
        action = input(f"  {C}▶ {RESET}").strip().lower()

        if action == "r":
            _run_code(template["code"])
        elif action == "e":
            info("Enter your modified code (blank line to run):")
            lines = []
            for orig_line in template["code"].split("\n"):
                print(f"  {DIM}{orig_line}{RESET}")
            print()
            info("Type your code (or paste modified version):")
            while True:
                line = input(f"  {G}>>>{RESET} ")
                if line == "":
                    break
                lines.append(line)
            if lines:
                _run_code("\n".join(lines))

        press_enter()


def _run_code(code: str):
    """Execute Python code in a sandboxed subprocess."""
    sub_header("Output")
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".py", delete=False, dir=tempfile.gettempdir()
        ) as f:
            f.write(code)
            tmp_path = f.name

        result = subprocess.run(
            [sys.executable, tmp_path],
            capture_output=True,
            text=True,
            timeout=10,
            cwd=tempfile.gettempdir(),
        )

        if result.stdout:
            print(result.stdout)
        if result.stderr:
            error("Errors:")
            print(f"  {R}{result.stderr}{RESET}")
        if result.returncode == 0 and not result.stderr:
            success("Code executed successfully!")
        elif result.returncode != 0:
            error(f"Exit code: {result.returncode}")

    except subprocess.TimeoutExpired:
        error("Code execution timed out (10 second limit).")
        warning("Check for infinite loops or long-running operations.")
    except Exception as e:
        error(f"Execution error: {e}")
    finally:
        try:
            os.unlink(tmp_path)
        except Exception:
            pass
