# JJ's LAB — Ethical Hacking & Penetration Testing Learning Platform

A terminal-based interactive Python application for learning security fundamentals, designed for internal use to understand and improve your company's security posture.

> **DISCLAIMER**: This application is for EDUCATIONAL purposes only. All exercises run against localhost. Only test systems you own or have written authorization to test. Unauthorized access to computer systems is illegal.

## Features

- **8 Learning Modules** covering Python security, networking, web app security, passwords, OSINT, vulnerability scanning, log analysis, and secure coding
- **Hands-On Exercises** with code-along examples and practice challenges
- **Vulnerable Flask App** for safe local practice (SQL injection, XSS, IDOR, etc.)
- **Progress Tracking** with saved state, quiz scores, and completion stats
- **Security Audit Checklist Generator** based on completed modules
- **Site Testing Mode** to run safe checks on your own systems
- **Three Difficulty Levels**: Beginner, Intermediate, Advanced

## Quick Start

### Prerequisites

- Python 3.10 or higher
- pip (Python package manager)

### Installation

```bash
# Clone or download the project
cd securitylab

# Create a virtual environment (recommended)
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Run the application
python main.py
```

### Optional: nmap

Some exercises in Module 6 (Vulnerability Scanning) use `python-nmap`, which requires nmap to be installed on your system:

```bash
# macOS
brew install nmap

# Ubuntu/Debian
sudo apt install nmap

# Windows — download from https://nmap.org/download.html
```

## Project Structure

```
securitylab/
├── main.py                  # Application entry point
├── requirements.txt         # Python dependencies
├── README.md                # This file
├── progress.json            # Auto-generated progress file
│
├── lessons/                 # Learning modules
│   ├── module1_python_security.py       # Python for Security
│   ├── module2_network_fundamentals.py  # Network Fundamentals
│   ├── module3_web_security.py          # Web Application Security
│   ├── module4_password_security.py     # Password Security
│   ├── module5_recon_osint.py           # Reconnaissance & OSINT
│   ├── module6_vuln_scanning.py         # Vulnerability Scanning
│   ├── module7_log_analysis.py          # Log Analysis & Incident Response
│   └── module8_secure_coding.py         # Secure Coding Practices
│
├── exercises/               # Practice challenges
│   └── exercise_runner.py   # Challenge presentation engine
│
├── vulnerable_app/          # Intentionally vulnerable Flask app
│   ├── app.py               # Flask application (runs on localhost:5050)
│   └── templates/           # HTML templates
│
└── utils/                   # Shared utilities
    ├── display.py           # Terminal UI (colors, banners, menus)
    ├── progress.py          # Save/load progress (JSON)
    ├── quiz.py              # Quiz engine
    ├── audit_checklist.py   # Checklist generator
    └── site_tester.py       # "Test your own site" scanner
```

## Learning Modules

| # | Module | Topics |
|---|--------|--------|
| 1 | **Python for Security** | Sockets, requests, subprocess, file I/O, regex |
| 2 | **Network Fundamentals** | Port scanning, banner grabbing, TCP/UDP, network mapping |
| 3 | **Web Application Security** | OWASP Top 10, SQL injection, XSS, CSRF, security headers |
| 4 | **Password Security** | Hashing, brute-force concepts, strength checking, policies |
| 5 | **Reconnaissance & OSINT** | DNS lookups, WHOIS, subdomain enumeration, Google dorking |
| 6 | **Vulnerability Scanning** | CVEs, port scanning, outdated software, config auditing |
| 7 | **Log Analysis & IR** | Log parsing, anomaly detection, alerting, incident response |
| 8 | **Secure Coding** | Python vulnerabilities, input sanitization, API security, secrets |

## Each Lesson Includes

- Clear concept explanation
- Why it matters for your company's security
- Code-along example you can run
- Practice challenge with hints and solution
- Quiz to test understanding
- Real-world scenario showing business impact

## Vulnerable Practice App

The built-in Flask app (`vulnerable_app/app.py`) provides intentionally vulnerable endpoints for safe practice:

| Endpoint | Vulnerability |
|----------|--------------|
| `/login` | SQL Injection |
| `/search` | Reflected XSS |
| `/comment` | Stored XSS |
| `/profile/<id>` | IDOR (Insecure Direct Object Reference) |
| `/upload` | Unrestricted File Upload |
| `/redirect` | Open Redirect |
| `/api/users` | Broken Access Control |
| `/admin` | Hardcoded Credentials |

Each vulnerable endpoint has a corresponding `/safe/*` endpoint showing the secure implementation.

**Start it from the main menu** or manually:
```bash
python vulnerable_app/app.py
# Runs on http://127.0.0.1:5050
```

## Site Testing Mode

Run basic, non-intrusive security checks against your own systems:
- **Port scan** — common ports check
- **SSL certificate** — validity and configuration
- **HTTP security headers** — HSTS, CSP, X-Frame-Options, etc.
- **Server fingerprinting** — checks for information leakage

## Security Audit Checklist

Generate a tailored Markdown checklist based on modules you've completed. Use it for real internal security audits.

## Resources

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [NIST SP 800-53](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final)
- [SANS Top 25](https://www.sans.org/top25-software-errors/)
- [SANS Reading Room](https://www.sans.org/reading-room/)
- [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks)
- [MITRE ATT&CK](https://attack.mitre.org/)

## License

For internal educational use only. Not for distribution or use against unauthorized systems.
