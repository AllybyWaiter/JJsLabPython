"""
CTF challenge definitions for JJ's LAB.
8 challenges targeting the vulnerable app's 8 vulnerability types.
"""

CTF_CHALLENGES = [
    {
        "id": "ctf_sqli_login",
        "title": "Break the Login",
        "category": "SQL Injection",
        "difficulty": "Easy",
        "points": 100,
        "flag": "FLAG{SQL_INJECTION_BYPASSED}",
        "validation": "exact",
        "hint_penalty": 20,
        "requires_vuln_app": True,
        "description": (
            "The login page at http://127.0.0.1:5050/login is vulnerable to SQL injection.\n"
            "  Bypass authentication and find the flag hidden in the admin user's bio.\n"
            "  The flag format is: FLAG{...}"
        ),
        "hints": [
            "Try entering a single quote (') in the username field and see what happens",
            "Classic SQL injection: try ' OR 1=1 -- as the username",
            "After logging in as admin, look at the bio field in the response",
        ],
    },
    {
        "id": "ctf_xss_reflect",
        "title": "Script Injection",
        "category": "Reflected XSS",
        "difficulty": "Easy",
        "points": 100,
        "flag": "FLAG{XSS_REFLECTED_SUCCESS}",
        "validation": "exact",
        "hint_penalty": 20,
        "requires_vuln_app": True,
        "description": (
            "The search page at http://127.0.0.1:5050/search is vulnerable to reflected XSS.\n"
            "  Inject a script that reveals the hidden flag on the page.\n"
            "  The flag format is: FLAG{...}"
        ),
        "hints": [
            "Try searching for <script>alert('test')</script> to confirm XSS works",
            "There is a hidden div with id='ctf-flag' on the page -- inspect the HTML source",
            "Try: /search?q=<script>document.getElementById('ctf-flag').style.display='block'</script>",
        ],
    },
    {
        "id": "ctf_idor_profile",
        "title": "Access Denied",
        "category": "IDOR",
        "difficulty": "Easy",
        "points": 75,
        "flag": "FLAG{IDOR_BROKEN_ACCESS}",
        "validation": "exact",
        "hint_penalty": 15,
        "requires_vuln_app": True,
        "description": (
            "User profiles at http://127.0.0.1:5050/profile/<id> have no access control.\n"
            "  Find the flag hidden in one of the user profiles.\n"
            "  The flag format is: FLAG{...}"
        ),
        "hints": [
            "Try accessing different profile IDs: /profile/1, /profile/2, etc.",
            "There are 5 users in the database (IDs 1-5)",
            "Check Diana's profile (user ID 5) -- her bio contains the flag",
        ],
    },
    {
        "id": "ctf_file_upload",
        "title": "Unrestricted Upload",
        "category": "File Upload",
        "difficulty": "Medium",
        "points": 125,
        "flag": "FLAG{FILE_UPLOAD_UNRESTRICTED}",
        "validation": "exact",
        "hint_penalty": 25,
        "requires_vuln_app": True,
        "description": (
            "The upload page at http://127.0.0.1:5050/upload accepts any file type.\n"
            "  Upload a file with a dangerous extension to reveal the flag.\n"
            "  The flag format is: FLAG{...}"
        ),
        "hints": [
            "The upload form has no file type restrictions -- try uploading a .php or .py file",
            "Create a small text file and rename it with a dangerous extension like .php, .sh, or .exe",
            "Upload a file named test.php -- the response will include the flag",
        ],
    },
    {
        "id": "ctf_open_redirect",
        "title": "Redirect to Victory",
        "category": "Open Redirect",
        "difficulty": "Easy",
        "points": 75,
        "flag": "FLAG{OPEN_REDIRECT_FOUND}",
        "validation": "exact",
        "hint_penalty": 15,
        "requires_vuln_app": True,
        "description": (
            "The redirect endpoint at http://127.0.0.1:5050/redirect accepts a 'url' parameter.\n"
            "  Exploit the open redirect to find the flag.\n"
            "  The flag format is: FLAG{...}"
        ),
        "hints": [
            "Try: /redirect?url=https://example.com and see what happens",
            "The app redirects to any URL you provide without validation",
            "Try redirecting to an external URL (starting with http) -- the flag will be shown instead",
        ],
    },
    {
        "id": "ctf_api_exposure",
        "title": "API Exposure",
        "category": "Broken Access Control",
        "difficulty": "Easy",
        "points": 100,
        "flag": "FLAG{API_NO_AUTH_REQUIRED}",
        "validation": "exact",
        "hint_penalty": 20,
        "requires_vuln_app": True,
        "description": (
            "There is an API endpoint that exposes sensitive user data without authentication.\n"
            "  Find and access it to discover the flag.\n"
            "  The flag format is: FLAG{...}"
        ),
        "hints": [
            "Check the home page at http://127.0.0.1:5050 for a list of all endpoints",
            "The API endpoint is at /api/users -- try accessing it directly",
            "Look at the JSON response -- one of the entries contains the flag",
        ],
    },
    {
        "id": "ctf_hardcoded",
        "title": "Hardcoded Secrets",
        "category": "Hardcoded Credentials",
        "difficulty": "Medium",
        "points": 125,
        "flag": "FLAG{HARDCODED_ADMIN_ACCESS}",
        "validation": "exact",
        "hint_penalty": 25,
        "requires_vuln_app": True,
        "description": (
            "The admin panel at http://127.0.0.1:5050/admin uses hardcoded credentials.\n"
            "  Find the credentials, log in, and capture the flag.\n"
            "  The flag format is: FLAG{...}"
        ),
        "hints": [
            "The credentials are stored as constants in the application source code",
            "Look at the source code of app.py for ADMIN_USERNAME and ADMIN_PASSWORD",
            "Try admin / password123 -- the flag is visible in the admin dashboard",
        ],
    },
    {
        "id": "ctf_headers",
        "title": "Missing Headers",
        "category": "Security Misconfiguration",
        "difficulty": "Medium",
        "points": 150,
        "flag": "FLAG{MISSING_HEADERS_4}",
        "validation": "exact",
        "hint_penalty": 30,
        "requires_vuln_app": True,
        "description": (
            "The vulnerable app is missing critical security headers.\n"
            "  Analyze the HTTP response headers and count how many of the\n"
            "  4 key security headers are missing. The flag includes the count.\n"
            "  The flag format is: FLAG{MISSING_HEADERS_<count>}"
        ),
        "hints": [
            "Use curl -I http://127.0.0.1:5050 or Python requests to inspect headers",
            "Check for: Strict-Transport-Security, Content-Security-Policy, X-Content-Type-Options, X-Frame-Options",
            "The Flask dev server does not set any of these 4 headers -- the count is 4",
        ],
    },
]
