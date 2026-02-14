"""
Security Audit Checklist Generator.
Creates a markdown checklist based on the user's completed modules.
"""

import os
from datetime import datetime
from utils.display import success, info, section_header, press_enter, warning
from utils.progress import MODULE_NAMES

CHECKLISTS = {
    "module1": [
        "Review all Python scripts for use of subprocess with shell=True",
        "Ensure no hard-coded credentials in Python source files",
        "Verify all file I/O uses context managers (with statements)",
        "Check that socket connections use timeouts",
        "Audit regex patterns for ReDoS vulnerabilities",
        "Confirm logging does not expose sensitive data",
    ],
    "module2": [
        "Run an internal port scan of all servers (authorized)",
        "Document all open ports and their associated services",
        "Verify unused ports are closed/firewalled",
        "Confirm banner information does not reveal software versions",
        "Review network segmentation between sensitive zones",
        "Test that TCP reset attacks are mitigated by firewall rules",
    ],
    "module3": [
        "Test all user inputs for SQL injection vulnerabilities",
        "Verify output encoding prevents XSS attacks",
        "Check CSRF tokens are present on all state-changing forms",
        "Review Content-Security-Policy headers",
        "Ensure authentication endpoints use rate limiting",
        "Verify session tokens are regenerated after login",
        "Check for open redirects in all redirect parameters",
        "Review API endpoints for broken access control",
    ],
    "module4": [
        "Verify passwords are hashed with bcrypt/argon2 (not MD5/SHA1)",
        "Confirm password policy enforces 12+ characters",
        "Check for password reuse across internal services",
        "Ensure failed login attempts trigger account lockout",
        "Review password reset flow for token expiration",
        "Audit stored hashes — no plaintext passwords anywhere",
    ],
    "module5": [
        "Review public DNS records for unnecessary exposure",
        "Check WHOIS privacy on company domains",
        "Search for leaked company credentials on breach databases",
        "Audit publicly visible metadata on company documents",
        "Review employee social media for information leakage",
        "Enumerate subdomains and verify each is intentionally public",
    ],
    "module6": [
        "Scan all servers for software with known CVEs",
        "Verify all software is at latest stable patch level",
        "Check for default credentials on all services",
        "Review SSL/TLS configurations for weak ciphers",
        "Audit firewall rules and network ACLs",
        "Test for directory traversal on web servers",
    ],
    "module7": [
        "Verify centralized logging is enabled for all critical systems",
        "Check log retention meets compliance requirements",
        "Set up alerts for multiple failed login attempts",
        "Create alerts for access from unusual geographic locations",
        "Review incident response plan and update contact list",
        "Run a tabletop exercise for a simulated breach scenario",
        "Ensure logs are immutable / tamper-evident",
    ],
    "module8": [
        "Audit all API endpoints for proper authentication",
        "Verify secrets are loaded from environment variables, not code",
        "Review all eval()/exec() usage — remove if possible",
        "Check that deserialization uses safe loaders (yaml.safe_load)",
        "Verify all dependencies are pinned and scanned for CVEs",
        "Ensure error messages don't leak stack traces in production",
        "Review file upload handling for path traversal",
    ],
}

RESOURCE_LINKS = """
## Further Reading & Resources

- **OWASP Top 10**: https://owasp.org/www-project-top-ten/
- **OWASP Testing Guide**: https://owasp.org/www-project-web-security-testing-guide/
- **NIST Cybersecurity Framework**: https://www.nist.gov/cyberframework
- **NIST SP 800-53 Security Controls**: https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final
- **SANS Top 25 Software Errors**: https://www.sans.org/top25-software-errors/
- **SANS Reading Room**: https://www.sans.org/reading-room/
- **CIS Benchmarks**: https://www.cisecurity.org/cis-benchmarks
- **MITRE ATT&CK Framework**: https://attack.mitre.org/
"""


def generate_checklist(progress: dict) -> str:
    """Generate a markdown checklist based on completed modules."""
    completed_modules = []
    for mod_key in MODULE_NAMES:
        if progress["modules"][mod_key]["completed_lessons"]:
            completed_modules.append(mod_key)

    now = datetime.now().strftime("%Y-%m-%d %H:%M")
    username = progress.get("user", "Security Analyst")

    lines = [
        f"# Security Audit Checklist",
        f"",
        f"**Generated**: {now}",
        f"**Analyst**: {username}",
        f"**Difficulty Level**: {progress.get('difficulty', 'beginner').title()}",
        f"",
        f"---",
        f"",
    ]

    if not completed_modules:
        lines.append("*Complete some modules first to generate a tailored checklist.*\n")
        lines.append("The checklist below covers all areas for reference:\n")
        completed_modules = list(MODULE_NAMES.keys())

    for mod_key in completed_modules:
        mod_name = MODULE_NAMES[mod_key]
        lines.append(f"## {mod_name}")
        lines.append("")
        for item in CHECKLISTS.get(mod_key, []):
            lines.append(f"- [ ] {item}")
        lines.append("")

    lines.append(RESOURCE_LINKS)
    return "\n".join(lines)


def checklist_menu(progress: dict):
    """Interactive checklist generation."""
    section_header("Security Audit Checklist Generator")
    info("This generates a checklist based on the modules you've studied.")
    info("It will be saved as a Markdown file you can use for real audits.\n")

    content = generate_checklist(progress)

    output_dir = os.path.dirname(os.path.dirname(__file__))
    filename = f"audit_checklist_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
    filepath = os.path.join(output_dir, filename)

    with open(filepath, "w") as f:
        f.write(content)

    success(f"Checklist saved to: {filepath}")
    progress["audit_checklists_generated"] = progress.get("audit_checklists_generated", 0) + 1

    from utils.progress import save_progress
    save_progress(progress)

    print(f"\n{'─' * 60}")
    print(content[:2000])
    if len(content) > 2000:
        info("... (see full file for complete checklist)")
    print(f"{'─' * 60}")
    press_enter()
