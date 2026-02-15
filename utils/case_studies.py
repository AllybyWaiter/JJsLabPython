"""Real-world breach case studies — one per module to motivate learning."""

from utils.display import (
    sub_header, info, warning, narrator, press_enter,
    C, G, Y, R, DIM, BRIGHT, RESET
)


CASE_STUDIES = {
    "module0": {
        "title": "Why Python Matters in Security",
        "year": "2024",
        "summary": (
            "Python is the #1 language used by security professionals. "
            "From automated scanning tools like Nmap scripts to incident response "
            "automation, Python is everywhere in cybersecurity. The SANS Institute "
            "reports that 80% of security tools are written in or scriptable with Python."
        ),
        "lesson": "Mastering Python fundamentals is the single most important skill for cybersecurity.",
    },
    "module1": {
        "title": "SolarWinds Supply Chain Attack",
        "year": "2020",
        "summary": (
            "Attackers compromised SolarWinds' Orion software build process, inserting "
            "a backdoor into updates sent to ~18,000 organizations including US government "
            "agencies. The malicious code used Python-like scripting for C2 communication, "
            "DNS tunneling, and process injection — all techniques that start with "
            "understanding sockets, HTTP requests, and subprocess management."
        ),
        "lesson": "Understanding Python networking and system tools helps you both detect and prevent supply chain attacks.",
    },
    "module2": {
        "title": "Target Data Breach",
        "year": "2013",
        "summary": (
            "Attackers breached Target through an HVAC vendor's network credentials, then "
            "moved laterally across network segments to reach point-of-sale systems. They "
            "exfiltrated 40 million credit card numbers because network segmentation was "
            "insufficient — the HVAC vendor had access to the corporate network, which "
            "connected to payment systems."
        ),
        "lesson": "Proper network segmentation and understanding network fundamentals could have prevented $162M in damages.",
    },
    "module3": {
        "title": "TalkTalk SQL Injection Breach",
        "year": "2015",
        "summary": (
            "A 17-year-old used basic SQL injection to steal personal data of 157,000 "
            "TalkTalk customers, including bank account details. The attack used one of "
            "the oldest and most well-known web vulnerabilities — simple string "
            "concatenation in SQL queries without parameterization."
        ),
        "lesson": "TalkTalk was fined £400,000. A single parameterized query would have prevented the entire breach.",
    },
    "module4": {
        "title": "LinkedIn Password Dump",
        "year": "2012",
        "summary": (
            "6.5 million LinkedIn passwords were leaked, stored as unsalted SHA-1 hashes. "
            "Security researchers cracked 90% of them within days. LinkedIn had no salts, "
            "used a fast hash algorithm (SHA-1), and had no rate limiting on authentication "
            "— a textbook example of every password storage mistake."
        ),
        "lesson": "Use bcrypt or Argon2 with per-user salts. Never use SHA-1 or MD5 for passwords.",
    },
    "module5": {
        "title": "Bellingcat MH17 Investigation",
        "year": "2014-2019",
        "summary": (
            "Bellingcat, a group of OSINT researchers, used publicly available satellite "
            "imagery, social media posts, and metadata analysis to identify the exact "
            "Russian military unit responsible for shooting down Malaysia Airlines Flight "
            "MH17. Their investigation used phone metadata, geotagged photos, and open "
            "source databases — no hacking required."
        ),
        "lesson": "OSINT is incredibly powerful. Public information, when analyzed systematically, can reveal hidden truths.",
    },
    "module6": {
        "title": "Equifax Data Breach",
        "year": "2017",
        "summary": (
            "Equifax failed to patch a known Apache Struts vulnerability (CVE-2017-5638) "
            "for over 2 months after the patch was released. Attackers exploited it to steal "
            "personal data of 147 million people including SSNs, birth dates, and addresses. "
            "A single vulnerability scan would have flagged the issue."
        ),
        "lesson": "Regular vulnerability scanning and timely patching are non-negotiable. Equifax paid $700M in settlements.",
    },
    "module7": {
        "title": "Sony Pictures Hack",
        "year": "2014",
        "summary": (
            "Attackers (attributed to North Korea) spent weeks inside Sony's network, "
            "exfiltrating 100TB of data before deploying destructive malware. Sony's "
            "security team had log monitoring in place but failed to correlate alerts "
            "that showed unusual data transfer patterns and after-hours access. The signs "
            "were in the logs — but nobody was watching."
        ),
        "lesson": "Log analysis and incident response aren't just reactive — proactive monitoring catches attackers early.",
    },
    "module8": {
        "title": "Heartbleed (OpenSSL Bug)",
        "year": "2014",
        "summary": (
            "A missing bounds check in OpenSSL's heartbeat extension allowed attackers to "
            "read up to 64KB of server memory per request — potentially exposing private "
            "keys, passwords, and session tokens. The bug existed for 2 years before "
            "discovery and affected ~17% of all web servers. The fix was literally "
            "adding a single bounds check: 'if (payload + padding > length) return;'"
        ),
        "lesson": "One missing input validation check affected millions of servers. Secure coding practices save the internet.",
    },
}


def show_case_study(module_key: str):
    """Display the case study for a module."""
    study = CASE_STUDIES.get(module_key)
    if not study:
        return

    sub_header(f"Real-World Case: {study['title']} ({study['year']})")
    narrator(study["summary"])
    print()
    info(f"Takeaway: {study['lesson']}")
    print()
