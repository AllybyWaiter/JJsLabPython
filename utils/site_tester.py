"""
'Test Your Own Site' mode.
Runs basic, safe, non-intrusive checks against a target you own.
Checks: open ports, SSL certificate, HTTP security headers.
"""

import socket
import ssl
import json
from datetime import datetime
from urllib.parse import urlparse

from utils.display import (
    section_header, sub_header, info, success, warning, error,
    disclaimer, press_enter, ask_yes_no, G, R, Y, C, RESET, BRIGHT, DIM
)


SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "X-XSS-Protection",
    "Referrer-Policy",
    "Permissions-Policy",
]

COMMON_PORTS = [
    (21, "FTP"),
    (22, "SSH"),
    (23, "Telnet"),
    (25, "SMTP"),
    (53, "DNS"),
    (80, "HTTP"),
    (110, "POP3"),
    (143, "IMAP"),
    (443, "HTTPS"),
    (445, "SMB"),
    (993, "IMAPS"),
    (995, "POP3S"),
    (3306, "MySQL"),
    (3389, "RDP"),
    (5432, "PostgreSQL"),
    (6379, "Redis"),
    (8080, "HTTP-Alt"),
    (8443, "HTTPS-Alt"),
    (27017, "MongoDB"),
]


def scan_ports(host: str, ports: list[tuple[int, str]], timeout: float = 1.0) -> list[dict]:
    """Scan a list of common ports on the target host."""
    results = []
    for port, service in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            if result == 0:
                # Try banner grab
                banner = ""
                try:
                    sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
                    banner = sock.recv(256).decode("utf-8", errors="ignore").strip()
                except Exception:
                    pass
                results.append({"port": port, "service": service, "state": "open", "banner": banner[:100]})
            sock.close()
        except socket.gaierror:
            results.append({"port": port, "service": service, "state": "error", "banner": "DNS resolution failed"})
            break
        except Exception:
            pass
    return results


def check_ssl_cert(host: str, port: int = 443) -> dict:
    """Check SSL certificate details."""
    try:
        context = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                return {
                    "valid": True,
                    "subject": dict(x[0] for x in cert.get("subject", [])),
                    "issuer": dict(x[0] for x in cert.get("issuer", [])),
                    "expires": cert.get("notAfter", "Unknown"),
                    "version": ssock.version(),
                }
    except ssl.SSLCertVerificationError as e:
        return {"valid": False, "error": f"Certificate verification failed: {e}"}
    except Exception as e:
        return {"valid": False, "error": str(e)}


def check_headers(host: str) -> dict:
    """Check HTTP security headers using raw sockets (no requests dependency)."""
    try:
        import requests
        resp = requests.get(f"https://{host}", timeout=5, verify=True)
        headers = dict(resp.headers)
    except Exception:
        try:
            import requests
            resp = requests.get(f"http://{host}", timeout=5)
            headers = dict(resp.headers)
        except Exception as e:
            return {"error": str(e), "headers": {}}

    results = {}
    for h in SECURITY_HEADERS:
        if h.lower() in {k.lower() for k in headers}:
            val = next(v for k, v in headers.items() if k.lower() == h.lower())
            results[h] = {"present": True, "value": val}
        else:
            results[h] = {"present": False, "value": None}
    return {"error": None, "headers": results, "server": headers.get("Server", "Not disclosed")}


def site_tester_menu(progress: dict):
    """Interactive site testing interface."""
    section_header("Test Your Own Site")
    disclaimer()

    warning("Only test systems you OWN or have WRITTEN AUTHORIZATION to test.")
    print()

    if not ask_yes_no("Do you confirm you have authorization to test the target?"):
        info("Test cancelled. Always obtain proper authorization first.")
        press_enter()
        return

    target = input(f"\n{C}  Enter target hostname or IP: {RESET}").strip()
    if not target:
        error("No target specified.")
        press_enter()
        return

    # Resolve hostname
    sub_header(f"Testing: {target}")
    try:
        ip = socket.gethostbyname(target)
        info(f"Resolved to: {ip}")
    except socket.gaierror:
        error(f"Cannot resolve hostname: {target}")
        press_enter()
        return

    # Port scan
    sub_header("Port Scan (common ports)")
    info("Scanning common ports...")
    open_ports = scan_ports(target, COMMON_PORTS)
    if open_ports:
        for p in open_ports:
            if p["state"] == "open":
                status_color = Y if p["service"] in ("Telnet", "FTP", "Redis", "MongoDB") else G
                banner_info = f" — {p['banner'][:60]}" if p["banner"] else ""
                print(f"  {status_color}Port {p['port']:>5}/{p['service']:<12} OPEN{banner_info}{RESET}")
            elif p["state"] == "error":
                error(p["banner"])
                break
        open_count = sum(1 for p in open_ports if p["state"] == "open")
        info(f"{open_count} open port(s) found out of {len(COMMON_PORTS)} scanned.")
        # Warnings
        risky = [p for p in open_ports if p["state"] == "open" and p["service"] in ("Telnet", "FTP", "Redis", "MongoDB", "SMB")]
        if risky:
            warning("Potentially risky services detected:")
            for p in risky:
                warning(f"  Port {p['port']} ({p['service']}) — consider restricting access")
    else:
        info("No open ports found among common ports.")

    # SSL check
    sub_header("SSL/TLS Certificate Check")
    ssl_result = check_ssl_cert(target)
    if ssl_result.get("valid"):
        success(f"Valid SSL certificate")
        info(f"  Subject: {ssl_result['subject'].get('commonName', 'N/A')}")
        info(f"  Issuer:  {ssl_result['issuer'].get('organizationName', 'N/A')}")
        info(f"  Expires: {ssl_result['expires']}")
        info(f"  Protocol: {ssl_result['version']}")
    else:
        warning(f"SSL issue: {ssl_result.get('error', 'Unknown')}")

    # Header check
    sub_header("HTTP Security Headers")
    header_result = check_headers(target)
    if header_result.get("error"):
        warning(f"Could not fetch headers: {header_result['error']}")
    else:
        if header_result.get("server"):
            info(f"Server header: {header_result['server']}")
            if header_result["server"] != "Not disclosed":
                warning("Consider hiding the Server header to reduce fingerprinting.")

        for name, data in header_result.get("headers", {}).items():
            if data["present"]:
                success(f"{name}: {data['value'][:60]}")
            else:
                warning(f"{name}: MISSING — consider adding this header")

    # Summary
    sub_header("Summary")
    score = 0
    total = 0

    total += 1
    if ssl_result.get("valid"):
        score += 1

    for data in header_result.get("headers", {}).values():
        total += 1
        if data["present"]:
            score += 1

    risky_ports = [p for p in open_ports if p["state"] == "open" and p["service"] in ("Telnet", "FTP", "Redis", "MongoDB")]
    total += 1
    if not risky_ports:
        score += 1

    pct = (score / total * 100) if total else 0
    if pct >= 80:
        success(f"Security posture: {score}/{total} checks passed ({pct:.0f}%) — Good")
    elif pct >= 50:
        warning(f"Security posture: {score}/{total} checks passed ({pct:.0f}%) — Needs improvement")
    else:
        error(f"Security posture: {score}/{total} checks passed ({pct:.0f}%) — Significant issues found")

    progress["site_tests_run"] = progress.get("site_tests_run", 0) + 1
    from utils.progress import save_progress
    save_progress(progress)

    press_enter()
