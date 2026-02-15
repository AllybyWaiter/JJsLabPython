"""
JJ's LAB -- Security Glossary
==============================
A searchable glossary of security terms used throughout the platform.
Supports browsing, keyword search, and a fun quiz mode.
"""

import random
from typing import Dict, List, Optional

from utils.display import (
    show_menu, section_header, sub_header, info, success, warning,
    press_enter, C, G, Y, R, DIM, BRIGHT, RESET,
)

# ---------------------------------------------------------------------------
# Glossary Data (30+ terms)
# ---------------------------------------------------------------------------

GLOSSARY: Dict[str, str] = {
    "SQL Injection": (
        "A code injection technique that exploits vulnerabilities in an "
        "application's database layer. Malicious SQL statements are inserted "
        "into input fields and executed by the database, potentially leading "
        "to data theft, modification, or full system compromise."
    ),
    "XSS (Cross-Site Scripting)": (
        "An attack where malicious scripts are injected into trusted "
        "websites. When other users load the page, the script runs in "
        "their browser and can steal cookies, tokens, or session data. "
        "Comes in reflected, stored, and DOM-based variants."
    ),
    "CSRF (Cross-Site Request Forgery)": (
        "An attack that tricks a logged-in user's browser into sending an "
        "unwanted request to a site where they are authenticated. The site "
        "cannot tell the forged request apart from a legitimate one. "
        "Mitigated with anti-CSRF tokens."
    ),
    "IDOR (Insecure Direct Object Reference)": (
        "A type of broken access control where an application exposes internal "
        "object identifiers (like database IDs) in URLs or parameters, and "
        "fails to verify that the requesting user is authorized to access "
        "the referenced object."
    ),
    "OWASP": (
        "The Open Web Application Security Project -- a nonprofit foundation "
        "that produces freely available articles, tools, and standards for "
        "web application security. Best known for the OWASP Top 10, a list "
        "of the most critical web security risks."
    ),
    "CVE": (
        "Common Vulnerabilities and Exposures -- a standardized ID system "
        "(e.g., CVE-2024-12345) for publicly known security flaws. Makes it "
        "easy to reference and track specific vulnerabilities across tools "
        "and organizations."
    ),
    "OSINT (Open-Source Intelligence)": (
        "The practice of collecting information from publicly available "
        "sources -- websites, social media, public records, DNS data -- to "
        "build a picture of a target before an engagement. A critical first "
        "step in reconnaissance."
    ),
    "NIST": (
        "The National Institute of Standards and Technology -- a U.S. federal "
        "agency that publishes cybersecurity frameworks, guidelines, and "
        "standards. The NIST Cybersecurity Framework (CSF) is widely adopted "
        "across industries."
    ),
    "Penetration Testing": (
        "An authorized, simulated cyberattack on a system to evaluate its "
        "security posture. The goal is to find vulnerabilities before real "
        "attackers do, document the findings, and help the owner remediate "
        "them. Also called pentesting."
    ),
    "Vulnerability": (
        "A weakness or flaw in a system's design, implementation, or "
        "configuration that could be exploited to compromise its security. "
        "Vulnerabilities can exist in code, network configurations, or even "
        "in human processes."
    ),
    "Exploit": (
        "A piece of code, a technique, or a sequence of commands that takes "
        "advantage of a vulnerability to cause unintended behavior, such as "
        "gaining unauthorized access, escalating privileges, or exfiltrating "
        "data."
    ),
    "Payload": (
        "The part of an exploit that performs the intended malicious action "
        "after the vulnerability has been triggered. Examples include opening "
        "a reverse shell, downloading malware, or exfiltrating sensitive data."
    ),
    "Hash / Hashing": (
        "A one-way mathematical function that converts data into a "
        "fixed-length string of characters (a digest). Used to verify data "
        "integrity and store passwords safely -- you store the hash, not the "
        "plaintext password. Common algorithms include SHA-256 and bcrypt."
    ),
    "Salt": (
        "A random value added to a password before hashing it. Each user "
        "gets a unique salt, so even if two users have the same password, "
        "their hashes will be different. Salting defeats precomputed rainbow "
        "table attacks."
    ),
    "Brute Force": (
        "An attack that systematically tries every possible combination of "
        "passwords, keys, or inputs until the correct one is found. Slow "
        "but guaranteed to work eventually without rate-limiting, account "
        "lockout, or CAPTCHAs."
    ),
    "Dictionary Attack": (
        "A type of brute-force attack that uses a precompiled list of likely "
        "passwords (a wordlist) rather than trying every possible combination. "
        "Faster than pure brute force because it targets common passwords "
        "first. Tools like Hydra and John the Ripper support this approach."
    ),
    "Firewall": (
        "A network security device or software that monitors incoming and "
        "outgoing traffic and decides whether to allow or block it based on "
        "a defined set of rules. Firewalls can be network-based (hardware) "
        "or host-based (software)."
    ),
    "IDS (Intrusion Detection System)": (
        "A system that monitors network traffic or system activity for "
        "suspicious behavior and generates alerts. An IDS is passive -- it "
        "detects and reports threats but does not block them. Snort and "
        "Suricata are popular open-source IDS tools."
    ),
    "IPS (Intrusion Prevention System)": (
        "A system that monitors network traffic like an IDS but can also "
        "take automatic action to block or prevent detected threats. An IPS "
        "sits inline with traffic and can drop malicious packets in real "
        "time."
    ),
    "Port Scanning": (
        "The process of sending packets to a range of port numbers on a "
        "host to discover which services are running and listening. Nmap "
        "is the most popular port scanning tool. Common scan types include "
        "SYN scan, TCP connect scan, and UDP scan."
    ),
    "Reconnaissance": (
        "The first phase of a penetration test where you gather information "
        "about the target -- domain names, IP addresses, employee names, "
        "technologies in use -- before launching any attacks. Can be passive "
        "(no direct contact) or active (probing the target)."
    ),
    "Social Engineering": (
        "Manipulating people into performing actions or divulging "
        "confidential information. It exploits human psychology rather "
        "than technical vulnerabilities. Techniques include phishing, "
        "pretexting, baiting, and tailgating."
    ),
    "Phishing": (
        "A social-engineering attack where the attacker sends a deceptive "
        "message (usually email) designed to trick the victim into revealing "
        "credentials, clicking a malicious link, or downloading malware. "
        "Spear phishing targets specific individuals."
    ),
    "Encryption": (
        "The process of converting readable data (plaintext) into an "
        "unreadable format (ciphertext) using a cryptographic algorithm and "
        "a key. Only someone with the correct key can reverse the process. "
        "Types include symmetric (AES) and asymmetric (RSA)."
    ),
    "Authentication": (
        "The process of verifying that a user or system is who they claim "
        "to be. Common methods include passwords, tokens, biometrics, and "
        "multi-factor authentication (MFA). Authentication answers the "
        "question: 'Who are you?'"
    ),
    "Authorization": (
        "The process of determining what an authenticated user is allowed "
        "to do. While authentication proves identity, authorization enforces "
        "permissions and access control. It answers: 'What are you allowed "
        "to do?'"
    ),
    "Session Hijacking": (
        "An attack where an attacker takes over a legitimate user's active "
        "session by stealing or predicting the session token (cookie). "
        "Methods include XSS-based cookie theft, session fixation, and "
        "network sniffing on unencrypted connections."
    ),
    "Privilege Escalation": (
        "Gaining higher-level permissions than originally granted. Vertical "
        "escalation means going from a normal user to admin or root. "
        "Horizontal escalation means accessing another user's resources "
        "at the same privilege level."
    ),
    "Lateral Movement": (
        "The technique of moving through a network after gaining initial "
        "access, compromising additional systems to reach higher-value "
        "targets. Attackers use stolen credentials, exploitation of trust "
        "relationships, and internal scanning."
    ),
    "Incident Response": (
        "The organized approach to addressing and managing the aftermath "
        "of a security breach or cyberattack. The goal is to limit damage, "
        "reduce recovery time, and prevent future incidents. Typically "
        "follows phases: preparation, identification, containment, "
        "eradication, recovery, and lessons learned."
    ),
    "Zero-Day": (
        "A vulnerability that is unknown to the software vendor and has no "
        "patch available. Called 'zero-day' because the vendor has had zero "
        "days to fix it. Zero-day exploits are highly valuable on both "
        "the offensive and defensive markets."
    ),
    "Malware": (
        "Short for malicious software. Any program designed to harm, "
        "exploit, or otherwise compromise a system. Categories include "
        "viruses, worms, trojans, ransomware, spyware, adware, and "
        "rootkits."
    ),
    "Reverse Shell": (
        "A type of shell where the target machine initiates an outbound "
        "connection back to the attacker's machine, giving the attacker "
        "command-line access. Useful for bypassing firewalls that block "
        "inbound connections but allow outbound traffic."
    ),
    "MFA (Multi-Factor Authentication)": (
        "A login method that requires two or more independent proofs of "
        "identity from different categories: something you know (password), "
        "something you have (phone/token), or something you are (biometrics). "
        "Significantly reduces the risk of compromised credentials."
    ),
    "API": (
        "Application Programming Interface -- a set of rules that lets "
        "programs communicate with each other. Web APIs typically use HTTP "
        "requests to send and receive data. Insecure APIs are a common "
        "attack vector in modern applications."
    ),
    "DNS": (
        "Domain Name System -- the internet's phone book. It translates "
        "human-readable domain names (like example.com) into IP addresses "
        "that computers use to route traffic. DNS attacks include spoofing, "
        "cache poisoning, and zone transfer exploits."
    ),
}


# ---------------------------------------------------------------------------
# Pagination Constants
# ---------------------------------------------------------------------------

TERMS_PER_PAGE = 10


# ---------------------------------------------------------------------------
# Interactive Glossary Menu
# ---------------------------------------------------------------------------

def glossary_menu(progress: dict):
    """Display the glossary with browse, search, and quiz options."""
    while True:
        choice = show_menu("Security Glossary", [
            ("browse", "Browse All Terms"),
            ("search", "Search by Keyword"),
            ("quiz", "Quiz Me  (test your knowledge)"),
        ])

        if choice == "back":
            return
        if choice == "quit":
            raise SystemExit

        if choice == "browse":
            _browse_all()
        elif choice == "search":
            _search_terms()
        elif choice == "quiz":
            _quiz_me()


# ---------------------------------------------------------------------------
# Browse All (paginated)
# ---------------------------------------------------------------------------

def _browse_all():
    """Display a paginated, alphabetical list of all glossary terms."""
    sorted_terms = sorted(GLOSSARY.keys(), key=str.lower)
    total = len(sorted_terms)
    page = 0
    total_pages = (total + TERMS_PER_PAGE - 1) // TERMS_PER_PAGE

    while True:
        section_header(f"Security Glossary -- Browse All  (page {page + 1}/{total_pages})")
        info(f"{total} terms available.\n")

        start = page * TERMS_PER_PAGE
        end = min(start + TERMS_PER_PAGE, total)
        page_terms = sorted_terms[start:end]

        for i, term in enumerate(page_terms, start + 1):
            print(f"  {C}{BRIGHT}{i:>3}.{RESET} {term}")

        print()
        nav_hints = []
        if page > 0:
            nav_hints.append(f"{DIM}p = previous page{RESET}")
        if page < total_pages - 1:
            nav_hints.append(f"{DIM}n = next page{RESET}")
        nav_hints.append(f"{DIM}0 = back{RESET}")
        print(f"  {'  |  '.join(nav_hints)}")
        print()

        choice = input(f"{C}  >> Enter a number to read, or p/n/0: {RESET}").strip().lower()

        if choice == "0":
            return
        if choice == "n" and page < total_pages - 1:
            page += 1
            continue
        if choice == "p" and page > 0:
            page -= 1
            continue

        try:
            idx = int(choice) - 1
            if 0 <= idx < total:
                term = sorted_terms[idx]
                _show_definition(term)
            else:
                warning("Number out of range. Try again.")
        except ValueError:
            # Try fuzzy match on typed text
            match = _fuzzy_find(choice, sorted_terms)
            if match:
                _show_definition(match)
            else:
                warning("Invalid input. Enter a number, p, n, or 0.")


# ---------------------------------------------------------------------------
# Search
# ---------------------------------------------------------------------------

def _search_terms():
    """Search glossary terms and definitions by keyword."""
    while True:
        section_header("Security Glossary -- Search")
        info("Type a keyword to search terms and definitions.")
        info("Type 0 to go back.\n")

        query = input(f"{C}  >> Search: {RESET}").strip()

        if query == "0" or query == "":
            return

        q_lower = query.lower()
        matches: List[str] = []

        for term, definition in sorted(GLOSSARY.items(), key=lambda x: x[0].lower()):
            if q_lower in term.lower() or q_lower in definition.lower():
                matches.append(term)

        if not matches:
            warning(f"No results for '{query}'. Try a different keyword.")
            press_enter()
            continue

        sub_header(f"Search Results for '{query}'  ({len(matches)} match{'es' if len(matches) != 1 else ''})")
        for i, term in enumerate(matches, 1):
            print(f"  {C}{BRIGHT}{i:>3}.{RESET} {term}")

        print(f"\n  {DIM}0 = back to search{RESET}")
        print()

        pick = input(f"{C}  >> Enter a number to read, or 0: {RESET}").strip()

        if pick == "0":
            continue

        try:
            idx = int(pick) - 1
            if 0 <= idx < len(matches):
                _show_definition(matches[idx])
            else:
                warning("Number out of range.")
        except ValueError:
            warning("Invalid input.")


# ---------------------------------------------------------------------------
# Quiz Me
# ---------------------------------------------------------------------------

def _quiz_me():
    """Show a random definition and ask the user to guess the term."""
    terms = list(GLOSSARY.keys())

    section_header("Security Glossary -- Quiz Me")
    info("You will be shown a definition. Try to guess the term!")
    info("This is just for fun -- it is not scored.\n")

    round_num = 0

    while True:
        round_num += 1
        term = random.choice(terms)
        definition = GLOSSARY[term]

        sub_header(f"Round {round_num}")
        print(f"  {BRIGHT}Definition:{RESET}")
        print(f"  {definition}")
        print()

        guess = input(f"{C}  >> Your guess (or 'hint' / 'skip' / 'quit'): {RESET}").strip()

        if guess.lower() in ("quit", "q", "0"):
            info("Thanks for playing!")
            press_enter()
            return

        if guess.lower() == "skip":
            print(f"\n  {Y}Skipped!{RESET} The answer was: {G}{BRIGHT}{term}{RESET}")
            press_enter()
            continue

        if guess.lower() == "hint":
            # Show first letter and length
            print(f"\n  {Y}Hint:{RESET} Starts with '{term[0]}' and has {len(term)} characters.")
            guess = input(f"{C}  >> Your guess: {RESET}").strip()
            if guess.lower() in ("quit", "q", "0"):
                info("Thanks for playing!")
                press_enter()
                return

        # Check answer -- case-insensitive, allow partial match
        if _is_correct_guess(guess, term):
            print(f"\n  {G}{BRIGHT}Correct!{RESET} The answer is: {G}{BRIGHT}{term}{RESET}")
            success("Nice work!")
        else:
            print(f"\n  {R}Not quite.{RESET} The answer was: {G}{BRIGHT}{term}{RESET}")

        print()
        again = input(f"{C}  >> Another round? (y/n): {RESET}").strip().lower()
        if again not in ("y", "yes", ""):
            info("Thanks for playing!")
            press_enter()
            return


def _is_correct_guess(guess: str, term: str) -> bool:
    """Check if the guess matches the term (case-insensitive, flexible)."""
    g = guess.lower().strip()
    t = term.lower().strip()

    # Exact match
    if g == t:
        return True

    # Match without parenthetical parts, e.g., "XSS" matches "XSS (Cross-Site Scripting)"
    # Strip everything in parentheses from the term
    base_term = t.split("(")[0].strip()
    if g == base_term:
        return True

    # Match the parenthetical part alone, e.g., "cross-site scripting"
    if "(" in t:
        paren_part = t.split("(", 1)[1].rstrip(")").strip().lower()
        if g == paren_part:
            return True

    # Match abbreviation part, e.g., "csrf" for "CSRF (Cross-Site Request Forgery)"
    # Also match the full term removing " / " separators
    simplified = t.replace(" / ", " ").replace("/", " ")
    if g == simplified:
        return True

    return False


# ---------------------------------------------------------------------------
# Shared Helpers
# ---------------------------------------------------------------------------

def _show_definition(term: str):
    """Print a single glossary definition with formatting."""
    definition = GLOSSARY.get(term, "Definition not found.")
    sub_header(term)
    print(f"  {definition}\n")
    press_enter()


def _fuzzy_find(query: str, terms: list) -> Optional[str]:
    """Try to find a term that starts with or contains the query (case-insensitive)."""
    q = query.lower()
    # Exact match first
    for t in terms:
        if t.lower() == q:
            return t
    # Starts-with match
    for t in terms:
        if t.lower().startswith(q):
            return t
    # Substring match
    for t in terms:
        if q in t.lower():
            return t
    return None


# ---------------------------------------------------------------------------
# Quick Lookup (for inline use from lessons)
# ---------------------------------------------------------------------------

def quick_lookup(term: str):
    """Print a compact definition inline -- handy for calling from lessons.

    Usage in a lesson module:
        from utils.glossary import quick_lookup
        quick_lookup("SQL Injection")
    """
    match = _fuzzy_find(term, list(GLOSSARY.keys()))
    if match:
        definition = GLOSSARY[match]
        print(f"\n  {G}{BRIGHT}{match}{RESET}{DIM} -- {definition}{RESET}\n")
    else:
        print(f"\n  {Y}[!]{RESET} Term '{term}' not found in glossary.\n")


# ---------------------------------------------------------------------------
# Main (for standalone testing)
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    glossary_menu({})
