"""
Module 5: Reconnaissance & OSINT
=================================
Teaches the fundamentals of information gathering — DNS lookups, WHOIS queries,
subdomain enumeration, and search-engine reconnaissance (Google Dorking).

All techniques must only be performed against domains you own or have explicit
written authorization to test.
"""

from utils.display import (
    section_header, sub_header, lesson_block, code_block,
    scenario_block, why_it_matters, info, success, warning, press_enter,
    show_menu, disclaimer, hint_text, ask_yes_no, C, G, Y, R, RESET, BRIGHT, DIM
)
from utils.progress import mark_lesson_complete, mark_challenge_complete
from utils.quiz import run_quiz


# ---------------------------------------------------------------------------
# Lesson 1 — DNS Lookups
# ---------------------------------------------------------------------------
def _lesson_dns_lookups(progress):
    module_key = "module5"
    lesson_id = "dns_lookups"

    section_header("Lesson 1: DNS Lookups")
    disclaimer()

    # ---------- Conceptual explanation ----------
    sub_header("How DNS Works")
    lesson_block(
        "The Domain Name System (DNS) is the phone book of the Internet. "
        "When you type 'example.com' into your browser, your computer asks a "
        "DNS resolver to translate that human-readable name into a numeric IP "
        "address (like 93.184.216.34). This process is called DNS resolution."
    )
    lesson_block(
        "DNS operates as a hierarchical, distributed database. Your query "
        "travels from a recursive resolver to root name servers, then to the "
        "TLD (.com, .org, etc.) name servers, and finally to the authoritative "
        "name server for the specific domain. Each level caches answers to "
        "speed up future lookups."
    )
    press_enter()

    # ---------- Record types ----------
    sub_header("Common DNS Record Types")
    lesson_block(
        "DNS stores different kinds of records, each serving a specific "
        "purpose. Understanding these is essential for reconnaissance:"
    )

    info(f"{BRIGHT}A Record{RESET}      — Maps a domain to an IPv4 address (e.g., 93.184.216.34).")
    info(f"{BRIGHT}AAAA Record{RESET}   — Maps a domain to an IPv6 address.")
    info(f"{BRIGHT}MX Record{RESET}     — Specifies the mail server(s) for the domain.")
    info(f"{BRIGHT}NS Record{RESET}     — Identifies the authoritative name servers for the domain.")
    info(f"{BRIGHT}TXT Record{RESET}    — Holds arbitrary text; commonly used for SPF, DKIM, and domain verification.")
    info(f"{BRIGHT}CNAME Record{RESET}  — An alias that points one domain name to another.")
    info(f"{BRIGHT}SOA Record{RESET}    — Start of Authority — administrative information about the zone.")
    print()

    lesson_block(
        "During reconnaissance, each record type reveals different things. "
        "MX records tell you which email provider a company uses. TXT records "
        "may expose SPF policies, third-party service verifications, or even "
        "internal notes. NS records reveal the hosting infrastructure."
    )
    press_enter()

    # ---------- Why it matters ----------
    why_it_matters(
        "A security assessor uses DNS lookups as the very first step of an "
        "engagement. Knowing the mail servers, hosting providers, and IP "
        "ranges of a target allows you to map the attack surface before "
        "touching a single port. Defensively, auditing your own DNS records "
        "helps ensure you have not leaked internal hostnames, left stale "
        "records pointing to decommissioned servers, or misconfigured SPF "
        "policies that allow email spoofing."
    )
    press_enter()

    # ---------- Python code ----------
    sub_header("DNS Resolution in Python")
    lesson_block(
        "Python's built-in 'socket' module can perform basic DNS lookups "
        "without any third-party libraries. The socket.getaddrinfo() function "
        "returns address information for a given hostname, including IPv4 and "
        "IPv6 addresses."
    )

    code_block(
        """import socket

def resolve_domain(domain):
    \"\"\"Resolve a domain to its IP addresses using socket.getaddrinfo.\"\"\"
    results = set()
    try:
        addr_info = socket.getaddrinfo(domain, None)
        for family, _, _, _, sockaddr in addr_info:
            ip = sockaddr[0]
            version = "IPv4" if family == socket.AF_INET else "IPv6"
            results.add((version, ip))
    except socket.gaierror as e:
        print(f"DNS resolution failed: {e}")
    return results

# Example usage (only on domains you own!)
for version, ip in resolve_domain("example.com"):
    print(f"  {version}: {ip}")""", "python"
    )

    lesson_block(
        "For more advanced lookups (MX, NS, TXT, SOA), you would typically "
        "use the 'dnspython' library (import dns.resolver). Here is an "
        "example that queries multiple record types:"
    )

    code_block(
        """import dns.resolver

def dns_enum(domain):
    \"\"\"Query common DNS record types for a domain.\"\"\"
    record_types = ["A", "AAAA", "MX", "NS", "TXT", "SOA"]
    for rtype in record_types:
        try:
            answers = dns.resolver.resolve(domain, rtype)
            print(f"\\n  [{rtype}] records:")
            for rdata in answers:
                print(f"    -> {rdata}")
        except dns.resolver.NoAnswer:
            print(f"\\n  [{rtype}] No records found.")
        except dns.resolver.NXDOMAIN:
            print(f"  Domain {domain} does not exist.")
            return
        except Exception as e:
            print(f"\\n  [{rtype}] Error: {e}")

# Only run against domains you own
dns_enum("yourdomain.com")""", "python"
    )
    press_enter()

    # ---------- What DNS reveals ----------
    sub_header("What DNS Reveals About a Target")
    lesson_block(
        "Even simple DNS lookups can expose a surprising amount of "
        "information about an organization:"
    )
    info("IP ranges and hosting provider (cloud vs. on-premises).")
    info("Email infrastructure (Google Workspace, Microsoft 365, self-hosted).")
    info("Third-party services via TXT verification records.")
    info("Internal naming conventions if hostnames are descriptive.")
    info("Geographic distribution if IPs map to multiple data centers.")
    info("Potential subdomain takeover targets if CNAME records point to decommissioned services.")
    print()
    press_enter()

    # ---------- Real-world scenario ----------
    scenario_block(
        "The Dangling CNAME",
        "A company set up a CNAME record 'blog.company.com' pointing to a "
        "third-party blogging platform. When they cancelled the blogging "
        "service, they forgot to remove the DNS record. An attacker noticed "
        "the dangling CNAME, registered a new account on the platform, claimed "
        "the subdomain, and served a convincing phishing page at "
        "blog.company.com. Regular DNS audits would have caught the stale record."
    )
    press_enter()

    # ---------- Practice challenge ----------
    sub_header("Practice Challenge")
    lesson_block(
        "Write a Python script that takes a domain name as input and uses "
        "socket.getaddrinfo() to resolve it. Print each unique IP address "
        "along with whether it is IPv4 or IPv6. Then add reverse DNS lookup "
        "using socket.gethostbyaddr() for each IP."
    )
    hint_text("socket.gethostbyaddr(ip) returns (hostname, aliases, addresses).")
    hint_text("Wrap the reverse lookup in a try/except for socket.herror.")

    code_block(
        """import socket

def full_dns_lookup(domain):
    \"\"\"Forward and reverse DNS lookup.\"\"\"
    print(f"Resolving {domain}...")
    seen = set()
    try:
        for family, _, _, _, sockaddr in socket.getaddrinfo(domain, None):
            ip = sockaddr[0]
            if ip in seen:
                continue
            seen.add(ip)
            version = "IPv4" if family == socket.AF_INET else "IPv6"
            # Reverse DNS
            try:
                hostname, aliases, _ = socket.gethostbyaddr(ip)
                print(f"  {version}: {ip} -> reverse: {hostname}")
            except socket.herror:
                print(f"  {version}: {ip} -> reverse: (no PTR record)")
    except socket.gaierror as e:
        print(f"  Resolution failed: {e}")

# Only use on domains you own or have permission to test
full_dns_lookup("example.com")""", "python"
    )

    if ask_yes_no("Mark this challenge as attempted?"):
        mark_challenge_complete(progress, module_key, "dns_lookup_challenge")
        success("Challenge marked complete!")

    press_enter()
    mark_lesson_complete(progress, module_key, lesson_id)
    success("Lesson 1 complete: DNS Lookups")
    press_enter()


# ---------------------------------------------------------------------------
# Lesson 2 — WHOIS Queries
# ---------------------------------------------------------------------------
def _lesson_whois(progress):
    module_key = "module5"
    lesson_id = "whois_queries"

    section_header("Lesson 2: WHOIS Queries")
    disclaimer()

    # ---------- What is WHOIS ----------
    sub_header("What is WHOIS?")
    lesson_block(
        "WHOIS is a query/response protocol used to look up information about "
        "the registered owner of a domain name or IP address block. When a "
        "domain is registered, the registrar collects contact information and "
        "publishes it (or a redacted version) in a WHOIS database."
    )
    lesson_block(
        "WHOIS data is maintained by domain registrars and Regional Internet "
        "Registries (RIRs) such as ARIN (North America), RIPE NCC (Europe), "
        "and APNIC (Asia-Pacific). Each registry operates its own WHOIS server."
    )
    press_enter()

    # ---------- What WHOIS contains ----------
    sub_header("What WHOIS Data Contains")
    lesson_block(
        "A typical WHOIS response for a domain includes several categories "
        "of information:"
    )
    info(f"{BRIGHT}Registrant{RESET}     — The person or organization that registered the domain.")
    info(f"{BRIGHT}Admin Contact{RESET}  — Administrative contact for the domain.")
    info(f"{BRIGHT}Tech Contact{RESET}   — Technical contact responsible for DNS.")
    info(f"{BRIGHT}Registrar{RESET}      — The company through which the domain was registered.")
    info(f"{BRIGHT}Name Servers{RESET}   — The authoritative DNS servers for the domain.")
    info(f"{BRIGHT}Creation Date{RESET}  — When the domain was first registered.")
    info(f"{BRIGHT}Expiration{RESET}     — When the registration expires.")
    info(f"{BRIGHT}Updated Date{RESET}   — When the record was last modified.")
    info(f"{BRIGHT}Status Codes{RESET}   — Domain status flags (clientTransferProhibited, etc.).")
    print()
    press_enter()

    # ---------- Why it matters ----------
    why_it_matters(
        "WHOIS data helps security professionals identify who owns a domain, "
        "when it was created (newly created domains are often suspicious), and "
        "what infrastructure supports it. Defenders can monitor WHOIS records "
        "for their own domains to detect unauthorized transfers or expiration "
        "risks. Attackers use WHOIS to map out an organization's digital "
        "footprint, find related domains, and identify employee names and "
        "email addresses for social engineering."
    )
    press_enter()

    # ---------- Privacy considerations ----------
    sub_header("Privacy Considerations")
    lesson_block(
        "Since GDPR and similar privacy regulations took effect, many "
        "registrars now redact personal information from public WHOIS results. "
        "You will often see 'REDACTED FOR PRIVACY' in place of names, emails, "
        "and phone numbers. Some registrars offer 'WHOIS privacy' or 'domain "
        "privacy' services that replace registrant details with the proxy "
        "service's information."
    )
    lesson_block(
        "Even with redacted WHOIS data, you can still extract useful "
        "information: the registrar name, creation/expiration dates, name "
        "servers, and domain status codes are almost always visible."
    )
    press_enter()

    # ---------- Python code ----------
    sub_header("Querying WHOIS in Python")
    lesson_block(
        "The 'python-whois' library provides a simple interface for WHOIS "
        "lookups. Below is an example that queries a domain and parses the "
        "key fields from the response:"
    )

    code_block(
        """import whois  # pip install python-whois

def whois_lookup(domain):
    \"\"\"Perform a WHOIS lookup and display key fields.\"\"\"
    try:
        w = whois.whois(domain)
        fields = {
            "Domain Name": w.domain_name,
            "Registrar": w.registrar,
            "Creation Date": w.creation_date,
            "Expiration Date": w.expiration_date,
            "Updated Date": w.updated_date,
            "Name Servers": w.name_servers,
            "Status": w.status,
            "Registrant": w.get("registrant_name", "REDACTED"),
            "Org": w.get("org", "REDACTED"),
            "Country": w.get("country", "Unknown"),
        }
        for label, value in fields.items():
            print(f"  {label:20s}: {value}")
    except Exception as e:
        print(f"  WHOIS lookup failed: {e}")

# Only query domains you own or have permission to investigate
whois_lookup("yourdomain.com")""", "python"
    )
    press_enter()

    # ---------- Raw WHOIS parsing ----------
    sub_header("Parsing Raw WHOIS Responses")
    lesson_block(
        "Sometimes you need to parse raw WHOIS text yourself — for example, "
        "when the python-whois library does not handle a particular TLD well. "
        "WHOIS responses are plain text with 'Key: Value' lines. Here is a "
        "simple parser:"
    )

    code_block(
        """import subprocess

def raw_whois(domain):
    \"\"\"Run the system whois command and parse key fields.\"\"\"
    try:
        result = subprocess.run(
            ["whois", domain],
            capture_output=True, text=True, timeout=15
        )
        data = {}
        for line in result.stdout.splitlines():
            if ":" in line:
                key, _, value = line.partition(":")
                key = key.strip().lower()
                value = value.strip()
                if key and value:
                    data.setdefault(key, []).append(value)
        return data
    except FileNotFoundError:
        print("  'whois' command not found — install it via your OS package manager.")
        return {}
    except subprocess.TimeoutExpired:
        print("  WHOIS query timed out.")
        return {}

# Example
parsed = raw_whois("example.com")
for key in ["registrar", "creation date", "name server"]:
    if key in parsed:
        for val in parsed[key]:
            print(f"  {key}: {val}")""", "python"
    )
    press_enter()

    # ---------- Real-world scenario ----------
    scenario_block(
        "Domain Expiration Hijack",
        "A well-known open-source project let its domain registration expire. "
        "An attacker monitored the WHOIS expiration date, purchased the domain "
        "the moment it became available, and served a trojanized version of the "
        "software. Users who downloaded from the original URL received malware. "
        "Monitoring WHOIS expiration dates for critical domains is a basic but "
        "essential defensive practice."
    )
    press_enter()

    # ---------- Practice challenge ----------
    sub_header("Practice Challenge")
    lesson_block(
        "Write a Python script that performs a WHOIS lookup on a domain, "
        "extracts the creation date and expiration date, calculates how many "
        "days until expiration, and prints a warning if the domain expires "
        "within 90 days."
    )
    hint_text("Use the 'whois' library and datetime.datetime for date math.")
    hint_text("creation_date and expiration_date may be lists; handle both cases.")

    code_block(
        """import whois
from datetime import datetime

def check_domain_expiry(domain):
    \"\"\"Check how many days until a domain expires.\"\"\"
    w = whois.whois(domain)
    exp = w.expiration_date
    # Some TLDs return a list of dates
    if isinstance(exp, list):
        exp = exp[0]
    if exp is None:
        print("  Could not determine expiration date.")
        return
    days_left = (exp - datetime.now()).days
    print(f"  Domain: {domain}")
    print(f"  Expires: {exp.strftime('%Y-%m-%d')}")
    print(f"  Days remaining: {days_left}")
    if days_left < 90:
        print("  *** WARNING: Domain expires in less than 90 days! ***")
    elif days_left < 365:
        print("  Note: Consider renewing within the next year.")
    else:
        print("  Domain registration is healthy.")

check_domain_expiry("yourdomain.com")""", "python"
    )

    if ask_yes_no("Mark this challenge as attempted?"):
        mark_challenge_complete(progress, module_key, "whois_challenge")
        success("Challenge marked complete!")

    press_enter()
    mark_lesson_complete(progress, module_key, lesson_id)
    success("Lesson 2 complete: WHOIS Queries")
    press_enter()


# ---------------------------------------------------------------------------
# Lesson 3 — Subdomain Enumeration
# ---------------------------------------------------------------------------
def _lesson_subdomain_enum(progress):
    module_key = "module5"
    lesson_id = "subdomain_enum"

    section_header("Lesson 3: Subdomain Enumeration")
    disclaimer()

    # ---------- Introduction ----------
    sub_header("Why Subdomains Matter")
    lesson_block(
        "Subdomains are a critical part of an organization's attack surface. "
        "While the main domain (example.com) is typically well-secured, "
        "subdomains often host forgotten development servers, staging "
        "environments, internal tools, or legacy applications that may not "
        "receive the same level of security attention."
    )
    lesson_block(
        "Common subdomain examples include: mail.example.com, vpn.example.com, "
        "dev.example.com, staging.example.com, api.example.com, "
        "jenkins.example.com, jira.example.com, and admin.example.com. Each "
        "of these represents a potential entry point for an attacker."
    )
    press_enter()

    # ---------- Enumeration techniques ----------
    sub_header("Subdomain Enumeration Techniques")
    lesson_block(
        "There are several approaches to discovering subdomains:"
    )

    info(f"{BRIGHT}1. Brute-Force / Wordlist{RESET} — Try resolving common subdomain names "
         f"from a wordlist (admin, mail, vpn, dev, staging, etc.).")
    info(f"{BRIGHT}2. Certificate Transparency{RESET} — SSL certificates are logged in "
         f"public CT logs. Querying sites like crt.sh reveals subdomains that "
         f"have had certificates issued.")
    info(f"{BRIGHT}3. DNS Zone Transfers{RESET} — If misconfigured, a DNS server may "
         f"return all records in a zone via AXFR queries. This is rare today "
         f"but still worth checking.")
    info(f"{BRIGHT}4. Search Engine Indexing{RESET} — Search engines may have indexed "
         f"subdomains. Use 'site:example.com' in Google.")
    info(f"{BRIGHT}5. Passive DNS Databases{RESET} — Services like VirusTotal, "
         f"SecurityTrails, and Shodan aggregate historical DNS data.")
    print()
    press_enter()

    # ---------- Why it matters ----------
    why_it_matters(
        "Subdomain enumeration is one of the highest-value reconnaissance "
        "activities. Forgotten subdomains running outdated software are one of "
        "the most common initial access vectors in real-world breaches. By "
        "enumerating your own subdomains regularly, you can identify shadow IT, "
        "decommission unused services, and ensure every externally-facing "
        "system meets your security standards."
    )
    press_enter()

    # ---------- Wordlist-based enumeration ----------
    sub_header("Wordlist-Based Subdomain Enumeration")
    lesson_block(
        "The simplest enumeration technique is to take a list of common "
        "subdomain names and attempt to resolve each one. If DNS returns an "
        "IP address, the subdomain exists. This is brute-force enumeration."
    )

    code_block(
        """import socket

# A small sample wordlist — real tools use thousands of entries
COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "admin", "dev", "staging", "test",
    "api", "vpn", "remote", "portal", "blog", "shop", "store",
    "cdn", "media", "static", "docs", "wiki", "git", "jenkins",
    "jira", "confluence", "grafana", "monitor", "status", "beta",
    "internal", "intranet", "helpdesk", "support", "crm", "erp",
]

def enumerate_subdomains(domain, wordlist=None):
    \"\"\"Brute-force subdomain enumeration via DNS resolution.\"\"\"
    wordlist = wordlist or COMMON_SUBDOMAINS
    found = []
    for sub in wordlist:
        fqdn = f"{sub}.{domain}"
        try:
            answers = socket.getaddrinfo(fqdn, None)
            ips = set(sa[0] for _, _, _, _, sa in answers)
            print(f"  [+] {fqdn} -> {', '.join(ips)}")
            found.append((fqdn, ips))
        except socket.gaierror:
            pass  # Subdomain does not resolve
    print(f"\\n  Found {len(found)} subdomains out of {len(wordlist)} tested.")
    return found

# ONLY run against domains you own!
# enumerate_subdomains("yourdomain.com")""", "python"
    )
    press_enter()

    # ---------- Certificate Transparency ----------
    sub_header("Certificate Transparency Lookup")
    lesson_block(
        "Certificate Transparency (CT) logs are public records of SSL/TLS "
        "certificates. When a certificate authority issues a certificate, it "
        "is logged. We can query these logs to find subdomains that have been "
        "issued certificates — even internal ones."
    )

    code_block(
        """import requests

def ct_subdomain_search(domain):
    \"\"\"Search Certificate Transparency logs via crt.sh.\"\"\"
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    try:
        resp = requests.get(url, timeout=15)
        resp.raise_for_status()
        data = resp.json()
        subdomains = set()
        for entry in data:
            name = entry.get("name_value", "")
            for line in name.splitlines():
                line = line.strip().lower()
                if line.endswith(f".{domain}") or line == domain:
                    subdomains.add(line)
        print(f"  Found {len(subdomains)} unique subdomains via CT logs:")
        for sub in sorted(subdomains):
            print(f"    {sub}")
        return sorted(subdomains)
    except requests.RequestException as e:
        print(f"  CT lookup failed: {e}")
        return []

# ONLY use on domains you own
# ct_subdomain_search("yourdomain.com")""", "python"
    )
    press_enter()

    # ---------- Zone transfer check ----------
    sub_header("DNS Zone Transfer Check")
    lesson_block(
        "A DNS zone transfer (AXFR) is a mechanism for replicating DNS "
        "databases between servers. If a DNS server is misconfigured to allow "
        "zone transfers to anyone, an attacker can obtain every DNS record in "
        "the zone — a complete inventory of subdomains."
    )

    code_block(
        """import dns.zone
import dns.query
import dns.resolver

def attempt_zone_transfer(domain):
    \"\"\"Attempt an AXFR zone transfer against all NS servers.\"\"\"
    try:
        ns_records = dns.resolver.resolve(domain, "NS")
    except Exception as e:
        print(f"  Could not find NS records: {e}")
        return

    for ns in ns_records:
        ns_host = str(ns).rstrip(".")
        print(f"  Trying zone transfer from {ns_host}...")
        try:
            zone = dns.zone.from_xfr(
                dns.query.xfr(ns_host, domain, timeout=10)
            )
            print(f"  [!] Zone transfer SUCCEEDED from {ns_host}!")
            for name, node in zone.nodes.items():
                print(f"    {name}.{domain}")
            return
        except Exception:
            print(f"    Transfer denied (expected).")
    print("  All NS servers denied zone transfers (good configuration).")

# ONLY test on your own domains
# attempt_zone_transfer("yourdomain.com")""", "python"
    )
    press_enter()

    # ---------- Real-world scenario ----------
    scenario_block(
        "The Forgotten Staging Server",
        "During a penetration test, the assessor enumerated subdomains and "
        "found 'staging-v2.client.com'. This server was running an older "
        "version of the application with debug mode enabled, default database "
        "credentials, and no WAF protection. The assessor gained full database "
        "access within minutes. The staging server had been set up two years "
        "prior for a demo and was never decommissioned."
    )
    press_enter()

    # ---------- Practice challenge ----------
    sub_header("Practice Challenge")
    lesson_block(
        "Build a combined subdomain enumerator that: (1) performs wordlist-"
        "based brute forcing using DNS resolution, (2) queries crt.sh for "
        "Certificate Transparency data, and (3) merges the results into a "
        "single deduplicated list sorted alphabetically. Include a flag to "
        "write results to a file."
    )
    hint_text("Use a set() to merge results from both techniques.")
    hint_text("Use argparse for the domain input and optional --output flag.")

    code_block(
        """import socket
import requests
import argparse

WORDLIST = ["www", "mail", "ftp", "admin", "dev", "staging",
            "test", "api", "vpn", "portal", "blog", "cdn"]

def brute_force(domain, wordlist):
    found = set()
    for sub in wordlist:
        fqdn = f"{sub}.{domain}"
        try:
            socket.getaddrinfo(fqdn, None)
            found.add(fqdn)
        except socket.gaierror:
            pass
    return found

def ct_search(domain):
    found = set()
    try:
        r = requests.get(f"https://crt.sh/?q=%.{domain}&output=json", timeout=15)
        for entry in r.json():
            for name in entry["name_value"].splitlines():
                name = name.strip().lower()
                if name.endswith(f".{domain}"):
                    found.add(name)
    except Exception:
        pass
    return found

def main():
    parser = argparse.ArgumentParser(description="Subdomain enumerator")
    parser.add_argument("domain", help="Target domain (you must own it)")
    parser.add_argument("--output", "-o", help="Output file path")
    args = parser.parse_args()

    print(f"Enumerating subdomains for {args.domain}...")
    all_subs = brute_force(args.domain, WORDLIST) | ct_search(args.domain)
    for sub in sorted(all_subs):
        print(f"  {sub}")
    print(f"\\nTotal: {len(all_subs)} unique subdomains")

    if args.output:
        with open(args.output, "w") as f:
            f.write("\\n".join(sorted(all_subs)))
        print(f"Results saved to {args.output}")

if __name__ == "__main__":
    main()""", "python"
    )

    if ask_yes_no("Mark this challenge as attempted?"):
        mark_challenge_complete(progress, module_key, "subdomain_enum_challenge")
        success("Challenge marked complete!")

    press_enter()
    mark_lesson_complete(progress, module_key, lesson_id)
    success("Lesson 3 complete: Subdomain Enumeration")
    press_enter()


# ---------------------------------------------------------------------------
# Lesson 4 — Google Dorking Theory
# ---------------------------------------------------------------------------
def _lesson_google_dorking(progress):
    module_key = "module5"
    lesson_id = "google_dorking"

    section_header("Lesson 4: Google Dorking Theory")
    disclaimer()

    # ---------- Introduction ----------
    sub_header("What is Google Dorking?")
    lesson_block(
        "Google Dorking (also called Google Hacking) is the practice of using "
        "advanced search engine operators to find information that is publicly "
        "indexed but not easily discoverable through normal searches. These "
        "operators filter results by domain, URL path, file type, page title, "
        "and more."
    )
    lesson_block(
        "Google Dorking is not 'hacking' Google itself — it simply leverages "
        "the search engine's own features to find data that website owners may "
        "not have intended to be publicly accessible. The information was "
        "already public; the dork just makes it findable."
    )
    press_enter()

    # ---------- Search operators ----------
    sub_header("Essential Search Operators")

    info(f"{BRIGHT}site:{RESET}       — Restrict results to a specific domain.")
    info(f"  Example: site:example.com")
    print()
    info(f"{BRIGHT}inurl:{RESET}      — Find pages with a specific string in the URL.")
    info(f"  Example: inurl:admin")
    print()
    info(f"{BRIGHT}intitle:{RESET}    — Find pages with a specific string in the title.")
    info(f"  Example: intitle:\"login page\"")
    print()
    info(f"{BRIGHT}filetype:{RESET}   — Find specific file types.")
    info(f"  Example: filetype:pdf site:example.com")
    print()
    info(f"{BRIGHT}intext:{RESET}     — Find pages containing specific text in the body.")
    info(f"  Example: intext:\"confidential\"")
    print()
    info(f"{BRIGHT}cache:{RESET}      — View Google's cached version of a page.")
    info(f"  Example: cache:example.com/page")
    print()
    info(f"{BRIGHT}ext:{RESET}        — Alias for filetype.")
    info(f"  Example: ext:sql site:example.com")
    print()
    info(f"{BRIGHT}- (minus){RESET}   — Exclude results matching a term.")
    info(f"  Example: site:example.com -www")
    print()
    press_enter()

    # ---------- Attacker use cases ----------
    sub_header("How Attackers Use Search Engines")
    lesson_block(
        "Attackers combine these operators to find sensitive data that has been "
        "accidentally exposed. Here are common patterns (shown for educational "
        "awareness so you can defend against them):"
    )

    info(f"{BRIGHT}Finding login pages:{RESET}")
    info(f"  site:example.com inurl:login OR inurl:admin OR inurl:signin")
    print()
    info(f"{BRIGHT}Finding exposed configuration files:{RESET}")
    info(f"  site:example.com filetype:env OR filetype:cfg OR filetype:conf")
    print()
    info(f"{BRIGHT}Finding database dumps:{RESET}")
    info(f"  site:example.com filetype:sql OR filetype:bak OR filetype:dump")
    print()
    info(f"{BRIGHT}Finding directory listings:{RESET}")
    info(f"  site:example.com intitle:\"index of /\"")
    print()
    info(f"{BRIGHT}Finding exposed documents:{RESET}")
    info(f"  site:example.com filetype:xlsx OR filetype:docx confidential")
    print()
    info(f"{BRIGHT}Finding error messages with stack traces:{RESET}")
    info(f"  site:example.com \"Fatal error\" OR \"Stack trace\" OR \"Traceback\"")
    print()

    warning("These examples are for DEFENSIVE awareness only. Never use dorks "
            "to access data you are not authorized to view.")
    press_enter()

    # ---------- Why it matters ----------
    why_it_matters(
        "Organizations frequently leak sensitive information without realizing "
        "it is being indexed by search engines. Configuration files, database "
        "backups, internal documents, API keys embedded in JavaScript files, "
        "and employee directories can all end up in search results. Running "
        "Google Dorks against your own domain is one of the simplest and most "
        "effective ways to discover accidental exposures before an attacker does."
    )
    press_enter()

    # ---------- The Google Hacking Database ----------
    sub_header("The Google Hacking Database (GHDB)")
    lesson_block(
        "The Google Hacking Database (GHDB), maintained by Offensive Security "
        "at exploit-db.com, is a collection of thousands of documented Google "
        "dorks organized by category. Categories include:"
    )
    info("Sensitive directories and files")
    info("Error messages revealing server information")
    info("Files containing usernames and passwords")
    info("Sensitive online shopping information")
    info("Network and vulnerability data")
    info("Pages containing login portals")
    info("Web server detection queries")
    print()
    lesson_block(
        "Security teams should periodically review the GHDB for new dorks "
        "relevant to their technology stack and test them against their own "
        "domains."
    )
    press_enter()

    # ---------- Defensive measures ----------
    sub_header("Defensive Measures Against Google Dorking")
    lesson_block(
        "Protecting your organization from information exposure via search "
        "engines requires multiple layers of defense:"
    )

    info(f"{BRIGHT}1. robots.txt{RESET} — Use the Robots Exclusion Protocol to tell search "
         f"engine crawlers not to index sensitive directories. Note: this is a "
         f"request, not enforcement. Malicious bots will ignore it.")
    info(f"{BRIGHT}2. Meta Tags{RESET} — Add <meta name='robots' content='noindex'> to "
         f"pages you do not want indexed.")
    info(f"{BRIGHT}3. Authentication{RESET} — Require authentication for all sensitive pages. "
         f"Search engines cannot index what they cannot access.")
    info(f"{BRIGHT}4. Access Controls{RESET} — Use firewalls and network rules to restrict "
         f"access to internal tools and staging environments.")
    info(f"{BRIGHT}5. Regular Auditing{RESET} — Periodically run Google dorks against your "
         f"own domain to discover what is publicly visible.")
    info(f"{BRIGHT}6. Google Search Console{RESET} — Use Google's tools to request removal "
         f"of specific URLs from search results.")
    info(f"{BRIGHT}7. .htaccess / Server Config{RESET} — Configure your web server to "
         f"return 403 Forbidden for sensitive file types (.env, .sql, .bak).")
    print()
    press_enter()

    # ---------- Building a dork scanner ----------
    sub_header("Building a Dork Awareness Scanner")
    lesson_block(
        "While we should not automate Google searches (it violates their ToS), "
        "we can build a tool that generates relevant dorks for a given domain "
        "so a security analyst can manually review them:"
    )

    code_block(
        """def generate_dorks(domain):
    \"\"\"Generate a list of Google dorks for a given domain.\"\"\"
    dorks = [
        # Exposed files
        f'site:{domain} filetype:env',
        f'site:{domain} filetype:sql',
        f'site:{domain} filetype:log',
        f'site:{domain} filetype:bak',
        f'site:{domain} filetype:cfg',
        f'site:{domain} filetype:conf',
        f'site:{domain} filetype:xml',
        f'site:{domain} ext:json "api_key" OR "apikey" OR "secret"',
        # Login and admin pages
        f'site:{domain} inurl:login',
        f'site:{domain} inurl:admin',
        f'site:{domain} inurl:dashboard',
        f'site:{domain} intitle:"admin" OR intitle:"login"',
        # Directory listings
        f'site:{domain} intitle:"index of /"',
        f'site:{domain} intitle:"directory listing"',
        # Error pages
        f'site:{domain} "Fatal error" OR "Warning:" OR "Stack trace"',
        f'site:{domain} "PHP Parse error" OR "MySQL error"',
        # Sensitive content
        f'site:{domain} filetype:pdf "confidential" OR "internal"',
        f'site:{domain} filetype:xlsx OR filetype:csv "password"',
        # Subdomains and non-www content
        f'site:{domain} -www',
        f'site:*.{domain}',
    ]
    print(f"Generated {len(dorks)} dorks for {domain}:\\n")
    for i, dork in enumerate(dorks, 1):
        print(f"  {i:2d}. {dork}")
    return dorks

# Generate dorks for your own domain only
# generate_dorks("yourdomain.com")""", "python"
    )
    press_enter()

    # ---------- Real-world scenario ----------
    scenario_block(
        "Exposed .env File",
        "A developer accidentally deployed a Laravel application with the "
        ".env file accessible via the web. This file contained the database "
        "password, email API keys, and the application secret key. A simple "
        "Google dork ('site:company.com filetype:env') would have revealed "
        "it. An attacker found it, extracted the database credentials, and "
        "accessed the production database. Proper .htaccess rules blocking "
        "access to dotfiles would have prevented the exposure."
    )
    press_enter()

    # ---------- Practice challenge ----------
    sub_header("Practice Challenge")
    lesson_block(
        "Create a Python script that: (1) accepts a domain as input, "
        "(2) generates a comprehensive list of Google dorks organized by "
        "category, (3) outputs them to a text file, and (4) also checks "
        "whether the domain's robots.txt file disallows sensitive paths."
    )
    hint_text("Use requests to fetch https://domain/robots.txt and parse Disallow lines.")
    hint_text("Compare the disallowed paths against common sensitive paths.")

    code_block(
        """import requests

def check_robots_txt(domain):
    \"\"\"Fetch and analyze a domain's robots.txt for security.\"\"\"
    url = f"https://{domain}/robots.txt"
    sensitive_paths = [
        "/admin", "/login", "/dashboard", "/api", "/config",
        "/backup", "/db", "/env", "/.git", "/.env", "/wp-admin",
        "/phpmyadmin", "/server-status", "/server-info",
    ]
    try:
        resp = requests.get(url, timeout=10)
        if resp.status_code == 200:
            print(f"  robots.txt found ({len(resp.text)} bytes):\\n")
            disallowed = []
            for line in resp.text.splitlines():
                line = line.strip()
                if line.lower().startswith("disallow:"):
                    path = line.split(":", 1)[1].strip()
                    disallowed.append(path)
                    print(f"    Disallow: {path}")

            print(f"\\n  Checking for missing protections:")
            for sensitive in sensitive_paths:
                if not any(sensitive.startswith(d) or d == "/"
                           for d in disallowed):
                    print(f"    [!] {sensitive} is NOT disallowed in robots.txt")
                else:
                    print(f"    [ok] {sensitive} is covered")
        else:
            print(f"  No robots.txt found (HTTP {resp.status_code})")
    except requests.RequestException as e:
        print(f"  Could not fetch robots.txt: {e}")

# check_robots_txt("yourdomain.com")""", "python"
    )

    if ask_yes_no("Mark this challenge as attempted?"):
        mark_challenge_complete(progress, module_key, "google_dorking_challenge")
        success("Challenge marked complete!")

    press_enter()
    mark_lesson_complete(progress, module_key, lesson_id)
    success("Lesson 4 complete: Google Dorking Theory")
    press_enter()


# ---------------------------------------------------------------------------
# Quiz
# ---------------------------------------------------------------------------
def _run_module_quiz(progress):
    questions = [
        {
            "q": "Which DNS record type maps a domain name to an IPv4 address?",
            "options": [
                "A) MX",
                "B) A",
                "C) CNAME",
                "D) TXT",
            ],
            "answer": "b",
            "explanation": (
                "The A (Address) record maps a hostname to a 32-bit IPv4 address. "
                "AAAA records serve the same purpose for IPv6."
            ),
        },
        {
            "q": "What type of DNS record would reveal which email servers a company uses?",
            "options": [
                "A) A record",
                "B) NS record",
                "C) MX record",
                "D) SOA record",
            ],
            "answer": "c",
            "explanation": (
                "MX (Mail Exchange) records specify the mail servers responsible "
                "for receiving email for a domain."
            ),
        },
        {
            "q": "What is a DNS zone transfer (AXFR)?",
            "options": [
                "A) Moving a domain to a new registrar",
                "B) Replicating all DNS records from a server",
                "C) Changing the DNS TTL values",
                "D) Encrypting DNS queries with TLS",
            ],
            "answer": "b",
            "explanation": (
                "A zone transfer (AXFR) replicates the entire DNS zone from one "
                "name server to another. If misconfigured, it exposes all records "
                "to anyone who requests them."
            ),
        },
        {
            "q": "Which Google search operator restricts results to a specific domain?",
            "options": [
                "A) inurl:",
                "B) intitle:",
                "C) site:",
                "D) filetype:",
            ],
            "answer": "c",
            "explanation": (
                "The 'site:' operator limits Google results to pages hosted on "
                "the specified domain or subdomain."
            ),
        },
        {
            "q": "What does WHOIS data typically NOT include for GDPR-compliant registrations?",
            "options": [
                "A) Name servers",
                "B) Registrant's personal email address",
                "C) Domain creation date",
                "D) Registrar name",
            ],
            "answer": "b",
            "explanation": (
                "Under GDPR, personal data like the registrant's name, email, "
                "and phone number are typically redacted from public WHOIS results."
            ),
        },
        {
            "q": "Why are subdomains considered a significant part of the attack surface?",
            "options": [
                "A) They always use weaker encryption",
                "B) They often host forgotten or less-secured services",
                "C) They are not protected by the main domain's SSL certificate",
                "D) They are not subject to the same laws as the main domain",
            ],
            "answer": "b",
            "explanation": (
                "Subdomains frequently host staging environments, legacy apps, "
                "and internal tools that may not receive the same security attention "
                "as the main domain."
            ),
        },
        {
            "q": "Which of the following is a passive reconnaissance technique?",
            "options": [
                "A) Port scanning the target",
                "B) Sending phishing emails to employees",
                "C) Querying Certificate Transparency logs",
                "D) Running a vulnerability scanner against the web server",
            ],
            "answer": "c",
            "explanation": (
                "Querying CT logs is passive because you are searching public "
                "databases without directly interacting with the target's systems."
            ),
        },
        {
            "q": "What defensive measure can help prevent sensitive files from appearing in Google results?",
            "options": [
                "A) Using a stronger password",
                "B) Enabling two-factor authentication",
                "C) Adding authentication and proper server configuration",
                "D) Using HTTPS instead of HTTP",
            ],
            "answer": "c",
            "explanation": (
                "Requiring authentication prevents search engines from accessing "
                "sensitive pages. Proper server configuration (blocking .env, .sql, "
                "etc.) adds another layer of protection."
            ),
        },
    ]
    run_quiz(questions, "recon_osint_quiz", "module5", progress)


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------
def run(progress):
    """Main entry point called from the menu system."""
    module_key = "module5"
    while True:
        choice = show_menu("Module 5: Reconnaissance & OSINT", [
            ("dns_lookups", "Lesson 1: DNS Lookups"),
            ("whois_queries", "Lesson 2: WHOIS Queries"),
            ("subdomain_enum", "Lesson 3: Subdomain Enumeration"),
            ("google_dorking", "Lesson 4: Google Dorking Theory"),
            ("quiz", "Take the Quiz"),
        ])
        if choice == "back":
            return
        if choice == "quit":
            raise SystemExit

        if choice == "dns_lookups":
            _lesson_dns_lookups(progress)
        elif choice == "whois_queries":
            _lesson_whois(progress)
        elif choice == "subdomain_enum":
            _lesson_subdomain_enum(progress)
        elif choice == "google_dorking":
            _lesson_google_dorking(progress)
        elif choice == "quiz":
            _run_module_quiz(progress)
