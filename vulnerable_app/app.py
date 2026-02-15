"""
JJ's LAB - Intentionally Vulnerable Flask Application
=========================================================
WARNING: This application contains INTENTIONAL security vulnerabilities.
It is designed for LOCAL EDUCATIONAL USE ONLY.

DO NOT deploy this application on any public-facing server.
DO NOT use any of the vulnerable patterns in production code.

Purpose: Practice identifying and exploiting common web vulnerabilities
         in a safe, localhost-only environment.
"""

import os
import sqlite3
import hashlib
from urllib.parse import urlparse
from functools import wraps

from flask import (
    Flask,
    request,
    render_template,
    render_template_string,
    redirect,
    url_for,
    session,
    jsonify,
    flash,
    g,
    abort,
    escape,
)
from markupsafe import Markup
from werkzeug.utils import secure_filename

# ---------------------------------------------------------------------------
# App Configuration
# ---------------------------------------------------------------------------

app = Flask(__name__)
app.secret_key = "supersecretkey123"  # VULN: Hardcoded weak secret key

UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), "uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

# Hardcoded admin credentials -- VULNERABILITY: Hardcoded credentials
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "password123"


# ---------------------------------------------------------------------------
# Database helpers (SQLite in-memory)
# ---------------------------------------------------------------------------

def get_db():
    """Return a per-request database connection."""
    if "db" not in g:
        g.db = sqlite3.connect(":memory:")
        g.db.row_factory = sqlite3.Row
        _init_db(g.db)
    return g.db


def _init_db(db):
    """Create tables and seed data."""
    db.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            email TEXT,
            role TEXT DEFAULT 'user',
            bio TEXT DEFAULT ''
        );

        CREATE TABLE IF NOT EXISTS comments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            author TEXT NOT NULL,
            content TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        INSERT OR IGNORE INTO users (username, password, email, role, bio)
        VALUES
            ('admin',    'password123',    'admin@seclab.local',    'admin', 'FLAG{SQL_INJECTION_BYPASSED}'),
            ('alice',    'alice2024',      'alice@seclab.local',    'user',  'Security researcher'),
            ('bob',      'bob_secure!',    'bob@seclab.local',      'user',  'Pentesting enthusiast'),
            ('charlie',  'charlie789',     'charlie@seclab.local',  'user',  'Bug bounty hunter'),
            ('diana',    'diana_pass',     'diana@seclab.local',    'user',  'FLAG{IDOR_BROKEN_ACCESS}');

        INSERT OR IGNORE INTO comments (author, content)
        VALUES
            ('alice',   'Welcome to the comment section!'),
            ('bob',     'This app is great for learning.'),
            ('charlie', 'Remember: never use these patterns in production.');
        """
    )
    db.commit()


@app.teardown_appcontext
def close_db(exception):
    db = g.pop("db", None)
    if db is not None:
        db.close()


# ---------------------------------------------------------------------------
# Startup Banner
# ---------------------------------------------------------------------------

BANNER = r"""
================================================================================

   ____                       _ _         _          _
  / ___|  ___  ___ _   _ _ __(_) |_ _   _| |    __ _| |__
  \___ \ / _ \/ __| | | | '__| | __| | | | |   / _` | '_ \
   ___) |  __/ (__| |_| | |  | | |_| |_| | |__| (_| | |_) |
  |____/ \___|\___|\__,_|_|  |_|\__|\__, |_____\__,_|_.__/
                                     |___/

  VULNERABLE WEB APPLICATION  --  FOR EDUCATIONAL USE ONLY

  WARNING:  This application contains INTENTIONAL security vulnerabilities.
            Run ONLY on localhost. NEVER expose to a network.

  Binding to: 127.0.0.1:5050

================================================================================
"""


# ============================================================================
#  VULNERABLE ENDPOINTS
# ============================================================================


@app.route("/")
def index():
    """Home page -- lists all vulnerable and safe endpoints."""
    return render_template("index.html")


# ---------- 1. SQL Injection (Login) ----------

@app.route("/login", methods=["GET", "POST"])
def login():
    """
    VULNERABILITY: SQL Injection
    The username and password are interpolated directly into the SQL query
    using Python string formatting. An attacker can supply input such as:
        username: ' OR 1=1 --
    to bypass authentication entirely.
    """
    error = None
    user = None

    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        db = get_db()

        # VULN: Raw string formatting in SQL query -- classic SQL injection
        query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
        try:
            result = db.execute(query).fetchone()
            if result:
                session["user_id"] = result["id"]
                session["username"] = result["username"]
                session["role"] = result["role"]
                user = dict(result)
                flash(f"Logged in as {result['username']}", "success")
            else:
                error = "Invalid credentials."
        except Exception as e:
            error = f"SQL Error: {e}"

    return render_template("login.html", error=error, user=user)


# ---------- 2. Reflected XSS (Search) ----------

@app.route("/search")
def search():
    """
    VULNERABILITY: Reflected Cross-Site Scripting (XSS)
    The search query parameter is rendered directly into the page without
    escaping or sanitisation. An attacker can inject arbitrary HTML/JS:
        /search?q=<script>alert('XSS')</script>
    """
    query = request.args.get("q", "")
    results = []

    if query:
        db = get_db()
        # The search itself is parameterised (safe), but the *display* is not.
        results = db.execute(
            "SELECT username, email, bio FROM users WHERE username LIKE ?",
            (f"%{query}%",),
        ).fetchall()

    # VULN: Rendering the raw query back into the template without escaping
    return render_template("search.html", query=query, results=results)


# ---------- 3. Stored XSS (Comments) ----------

@app.route("/comment", methods=["GET", "POST"])
def comment():
    """
    VULNERABILITY: Stored Cross-Site Scripting (XSS)
    Comment content is stored in the database without sanitisation and
    rendered with the |safe filter, so any embedded <script> tags execute
    when the page is viewed by any user.
    """
    db = get_db()

    if request.method == "POST":
        author = request.form.get("author", "anonymous")
        content = request.form.get("content", "")

        # VULN: Storing raw user input (no sanitisation)
        db.execute(
            "INSERT INTO comments (author, content) VALUES (?, ?)",
            (author, content),
        )
        db.commit()
        flash("Comment posted!", "success")
        return redirect(url_for("comment"))

    comments = db.execute(
        "SELECT * FROM comments ORDER BY created_at DESC"
    ).fetchall()

    # Comments are rendered with |safe in the template -- stored XSS
    return render_template("comment.html", comments=comments)


# ---------- 4. IDOR (Profile) ----------

@app.route("/profile/<int:user_id>")
def profile(user_id):
    """
    VULNERABILITY: Insecure Direct Object Reference (IDOR)
    Any user can view any other user's profile (including email, role, bio)
    simply by changing the id in the URL. There is no authorisation check
    to verify that the requesting user should have access.
    """
    db = get_db()

    # VULN: No authorisation check -- anyone can access any profile
    user = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if not user:
        abort(404)

    return render_template("profile.html", user=dict(user))


# ---------- 5. Unrestricted File Upload ----------

@app.route("/upload", methods=["GET", "POST"])
def upload():
    """
    VULNERABILITY: Unrestricted File Upload
    The application accepts any file type and saves it to disk without
    validation. An attacker could upload a web shell, executable, or
    overwrite critical files if path traversal is combined.
    """
    message = None

    if request.method == "POST":
        uploaded = request.files.get("file")
        if uploaded and uploaded.filename:
            # VULN: No file type validation, no size limit, using original filename
            filename = uploaded.filename  # Not using secure_filename!
            filepath = os.path.join(app.config["UPLOAD_FOLDER"], filename)
            uploaded.save(filepath)
            message = f"File '{filename}' uploaded successfully to {filepath}"
            # Flag for CTF: detect dangerous extensions
            dangerous = filename.rsplit('.', 1)[-1].lower() if '.' in filename else ''
            if dangerous in ('php', 'jsp', 'asp', 'sh', 'py', 'exe'):
                message += " | FLAG{FILE_UPLOAD_UNRESTRICTED}"
        else:
            message = "No file selected."

    return render_template("upload.html", message=message)


# ---------- 6. Open Redirect ----------

@app.route("/redirect")
def open_redirect():
    """
    VULNERABILITY: Open Redirect
    The application redirects to whatever URL the 'url' query parameter
    contains, without validating the destination. An attacker can craft a
    link like:
        /redirect?url=https://evil.com
    to phish users who trust the application domain.
    """
    target = request.args.get("url", "/")

    # VULN: Redirecting to an unvalidated user-supplied URL
    # CTF: If target is an external URL, show flag instead of actually redirecting
    parsed = urlparse(target)
    if parsed.scheme in ("http", "https") and parsed.netloc not in ("127.0.0.1:5050", "localhost:5050", "127.0.0.1", "localhost"):
        return render_template_string(
            "<h1 style='color:#58a6ff;font-family:monospace;text-align:center;margin-top:80px;'>"
            "Open Redirect Detected!</h1>"
            "<p style='text-align:center;color:#c9d1d9;'>You would have been redirected to: {{ target }}</p>"
            "<p style='text-align:center;color:#2ea043;font-size:24px;font-family:monospace;'>FLAG{OPEN_REDIRECT_FOUND}</p>"
            "<p style='text-align:center;'><a href='/' style='color:#58a6ff;'>Back to Home</a></p>",
            target=target,
        )
    return redirect(target)


# ---------- 7. Broken Access Control (API) ----------

@app.route("/api/users")
def api_users():
    """
    VULNERABILITY: Broken Access Control
    This API endpoint returns the full list of users -- including passwords
    and emails -- without requiring any authentication or authorisation.
    """
    db = get_db()

    # VULN: No authentication, exposes sensitive fields including passwords
    users = db.execute("SELECT id, username, password, email, role, bio FROM users").fetchall()
    user_list = [dict(u) for u in users]
    # CTF: Add flag to admin user's data
    for u in user_list:
        if u.get("role") == "admin":
            u["flag"] = "FLAG{API_NO_AUTH_REQUIRED}"
    return jsonify(user_list)


# ---------- 8. Hardcoded Credentials (Admin) ----------

@app.route("/admin", methods=["GET", "POST"])
def admin():
    """
    VULNERABILITY: Hardcoded Credentials
    The admin login compares user input against credentials that are
    hardcoded directly in the source code. Anyone who reads the source
    (or guesses common defaults) gains admin access.
    """
    error = None
    authenticated = False

    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        # VULN: Credentials hardcoded in source code
        if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
            session["is_admin"] = True
            authenticated = True
            flash("Admin access granted.", "success")
        else:
            error = "Invalid admin credentials."

    if session.get("is_admin"):
        authenticated = True

    return render_template("admin.html", authenticated=authenticated, error=error)


# ============================================================================
#  SAFE (FIXED) ENDPOINTS -- showing the correct way to handle each issue
# ============================================================================


@app.route("/safe/login", methods=["GET", "POST"])
def safe_login():
    """SAFE: Parameterised query prevents SQL injection."""
    error = None
    user = None

    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        db = get_db()

        # SAFE: Using parameterised queries -- no string formatting
        result = db.execute(
            "SELECT * FROM users WHERE username = ? AND password = ?",
            (username, password),
        ).fetchone()

        if result:
            user = dict(result)
            flash(f"Logged in as {result['username']}", "success")
        else:
            error = "Invalid credentials."

    return render_template_string(
        SAFE_PAGE_TEMPLATE,
        title="Safe Login",
        vuln_name="SQL Injection",
        fix_description="Uses parameterised queries (?) instead of string formatting.",
        form_html=Markup(
            """
            <form method="POST">
                <label>Username: <input type="text" name="username"></label><br><br>
                <label>Password: <input type="password" name="password"></label><br><br>
                <button type="submit">Login (Safe)</button>
            </form>
            """
        ),
        result=f"User: {user}" if user else (f"Error: {error}" if error else ""),
    )


@app.route("/safe/search")
def safe_search():
    """SAFE: Escapes output to prevent reflected XSS."""
    query = request.args.get("q", "")
    results = []

    if query:
        db = get_db()
        results = db.execute(
            "SELECT username, email, bio FROM users WHERE username LIKE ?",
            (f"%{query}%",),
        ).fetchall()

    # SAFE: Using escape() so user input is rendered as text, not HTML
    escaped_query = escape(query)
    result_html = ""
    if results:
        result_html = "<ul>" + "".join(
            f"<li>{escape(r['username'])} - {escape(r['bio'])}</li>" for r in results
        ) + "</ul>"

    return render_template_string(
        SAFE_PAGE_TEMPLATE,
        title="Safe Search",
        vuln_name="Reflected XSS",
        fix_description="User input is escaped with markupsafe.escape() before rendering.",
        form_html=Markup(
            f"""
            <form method="GET">
                <label>Search: <input type="text" name="q" value="{escaped_query}"></label>
                <button type="submit">Search (Safe)</button>
            </form>
            """
        ),
        result=Markup(f"<p>Results for: {escaped_query}</p>{result_html}") if query else "",
    )


@app.route("/safe/comment", methods=["GET", "POST"])
def safe_comment():
    """SAFE: Escapes comment content to prevent stored XSS."""
    db = get_db()

    if request.method == "POST":
        author = request.form.get("author", "anonymous")
        content = request.form.get("content", "")

        # Still storing raw -- but rendering is escaped
        db.execute(
            "INSERT INTO comments (author, content) VALUES (?, ?)",
            (author, content),
        )
        db.commit()
        return redirect(url_for("safe_comment"))

    comments = db.execute(
        "SELECT * FROM comments ORDER BY created_at DESC"
    ).fetchall()

    # SAFE: Comments are escaped before rendering
    comments_html = ""
    for c in comments:
        comments_html += (
            f"<div style='border:1px solid #444;padding:10px;margin:8px 0;border-radius:6px;'>"
            f"<strong>{escape(c['author'])}</strong>: {escape(c['content'])}"
            f"</div>"
        )

    return render_template_string(
        SAFE_PAGE_TEMPLATE,
        title="Safe Comments",
        vuln_name="Stored XSS",
        fix_description="Comment content is escaped on output so HTML/JS is rendered as text.",
        form_html=Markup(
            """
            <form method="POST">
                <label>Name: <input type="text" name="author"></label><br><br>
                <label>Comment: <textarea name="content" rows="3" cols="40"></textarea></label><br><br>
                <button type="submit">Post (Safe)</button>
            </form>
            """
        ),
        result=Markup(comments_html),
    )


@app.route("/safe/profile/<int:user_id>")
def safe_profile(user_id):
    """SAFE: Checks that the logged-in user matches the requested profile."""
    if "user_id" not in session:
        return render_template_string(
            SAFE_PAGE_TEMPLATE,
            title="Safe Profile",
            vuln_name="IDOR",
            fix_description="Requires authentication and checks that the logged-in user matches the requested profile ID.",
            form_html="",
            result="You must be logged in, and you can only view your own profile.",
        )

    if session["user_id"] != user_id and session.get("role") != "admin":
        abort(403)

    db = get_db()
    user = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if not user:
        abort(404)

    return render_template_string(
        SAFE_PAGE_TEMPLATE,
        title="Safe Profile",
        vuln_name="IDOR",
        fix_description="Requires authentication and verifies the requesting user is authorised to view this profile.",
        form_html="",
        result=f"Profile: {dict(user)}",
    )


@app.route("/safe/upload", methods=["GET", "POST"])
def safe_upload():
    """SAFE: Validates file type, size, and uses secure_filename."""
    message = ""
    ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif", "pdf", "txt"}
    MAX_SIZE = 2 * 1024 * 1024  # 2 MB

    if request.method == "POST":
        uploaded = request.files.get("file")
        if uploaded and uploaded.filename:
            filename = secure_filename(uploaded.filename)
            ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""

            if ext not in ALLOWED_EXTENSIONS:
                message = f"File type '.{ext}' not allowed. Permitted: {ALLOWED_EXTENSIONS}"
            else:
                # Check size
                uploaded.seek(0, 2)
                size = uploaded.tell()
                uploaded.seek(0)
                if size > MAX_SIZE:
                    message = f"File too large ({size} bytes). Max is {MAX_SIZE} bytes."
                else:
                    filepath = os.path.join(app.config["UPLOAD_FOLDER"], filename)
                    uploaded.save(filepath)
                    message = f"File '{filename}' uploaded safely."
        else:
            message = "No file selected."

    return render_template_string(
        SAFE_PAGE_TEMPLATE,
        title="Safe Upload",
        vuln_name="Unrestricted File Upload",
        fix_description="Validates file extension against an allow-list, enforces a size limit, and uses secure_filename().",
        form_html=Markup(
            """
            <form method="POST" enctype="multipart/form-data">
                <label>Choose file: <input type="file" name="file"></label><br><br>
                <button type="submit">Upload (Safe)</button>
            </form>
            """
        ),
        result=message,
    )


@app.route("/safe/redirect")
def safe_redirect():
    """SAFE: Validates that the redirect target is a relative path on the same host."""
    target = request.args.get("url", "/")
    parsed = urlparse(target)

    # SAFE: Only allow relative redirects (no scheme, no netloc)
    if parsed.scheme or parsed.netloc:
        flash("External redirects are not allowed.", "danger")
        return redirect(url_for("index"))

    return redirect(target)


@app.route("/safe/api/users")
def safe_api_users():
    """SAFE: Requires authentication and omits sensitive fields."""
    if "user_id" not in session:
        return jsonify({"error": "Authentication required"}), 401

    db = get_db()

    # SAFE: Only return non-sensitive fields
    users = db.execute("SELECT id, username, bio FROM users").fetchall()
    return jsonify([dict(u) for u in users])


# Generic safe-page template used by all /safe/* routes
SAFE_PAGE_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>{{ title }} - JJ's LAB</title>
<style>
  body { background:#0d1117; color:#c9d1d9; font-family:'Segoe UI',sans-serif; margin:0; padding:0; }
  .container { max-width:800px; margin:40px auto; padding:0 20px; }
  h1 { color:#58a6ff; }
  .safe-banner { background:#1b4332; border:1px solid #2d6a4f; padding:14px 20px; border-radius:8px; margin-bottom:24px; }
  .safe-banner h2 { margin:0 0 6px; color:#52b788; }
  .safe-banner p { margin:0; color:#b7e4c7; }
  form { background:#161b22; padding:20px; border-radius:8px; margin-bottom:20px; }
  input, textarea { background:#0d1117; color:#c9d1d9; border:1px solid #30363d; padding:8px; border-radius:4px; }
  button { background:#238636; color:#fff; border:none; padding:10px 20px; border-radius:6px; cursor:pointer; font-size:14px; }
  button:hover { background:#2ea043; }
  a { color:#58a6ff; }
  .result { background:#161b22; padding:16px; border-radius:8px; border:1px solid #30363d; margin-top:12px; word-break:break-all; }
  .back { display:inline-block; margin-top:20px; }
</style>
</head>
<body>
<div class="container">
  <h1>{{ title }}</h1>
  <div class="safe-banner">
    <h2>SAFE VERSION -- {{ vuln_name }} Fixed</h2>
    <p>{{ fix_description }}</p>
  </div>
  {{ form_html }}
  {% if result %}
  <div class="result">{{ result }}</div>
  {% endif %}
  <a class="back" href="/">Back to Home</a>
</div>
</body>
</html>
"""


# ============================================================================
#  Error handlers
# ============================================================================

@app.errorhandler(403)
def forbidden(e):
    return render_template_string(
        "<h1 style='color:#f85149;font-family:monospace;text-align:center;margin-top:80px;'>"
        "403 -- Forbidden</h1><p style='text-align:center;color:#8b949e;'>You are not authorised.</p>"
    ), 403


@app.errorhandler(404)
def not_found(e):
    return render_template_string(
        "<h1 style='color:#f85149;font-family:monospace;text-align:center;margin-top:80px;'>"
        "404 -- Not Found</h1><p style='text-align:center;color:#8b949e;'>Resource does not exist.</p>"
    ), 404


# ============================================================================
#  Main
# ============================================================================

if __name__ == "__main__":
    print(BANNER)
    app.run(host="127.0.0.1", port=5050, debug=True)
