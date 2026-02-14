"""
Module 7: Log Analysis & Incident Response

Teaches students how to read, parse, and analyze system logs to detect
suspicious activity, build alerting scripts, and automate daily security
checks.  Covers incident-response fundamentals: contain, eradicate,
recover, lessons learned.
"""

from utils.display import (
    section_header, sub_header, lesson_block, code_block,
    scenario_block, why_it_matters, info, success, warning, press_enter,
    show_menu, disclaimer, hint_text, ask_yes_no, C, G, Y, R, RESET, BRIGHT, DIM,
    pace, learning_goal, nice_work, tip,
)
from utils.progress import mark_lesson_complete, mark_challenge_complete
from utils.quiz import run_quiz

# ---------------------------------------------------------------------------
# Sample log data used across lessons and exercises
# ---------------------------------------------------------------------------

SAMPLE_SYSLOG = """\
Feb  5 08:12:01 webserver01 CRON[12345]: (root) CMD (/usr/bin/backup.sh)
Feb  5 08:14:33 webserver01 kernel: [UFW BLOCK] IN=eth0 OUT= SRC=203.0.113.50 DST=10.0.0.5 PROTO=TCP DPT=22
Feb  5 08:14:34 webserver01 kernel: [UFW BLOCK] IN=eth0 OUT= SRC=203.0.113.50 DST=10.0.0.5 PROTO=TCP DPT=22
Feb  5 08:14:35 webserver01 kernel: [UFW BLOCK] IN=eth0 OUT= SRC=203.0.113.50 DST=10.0.0.5 PROTO=TCP DPT=22
Feb  5 08:15:00 webserver01 systemd[1]: Starting Daily apt download activities...
Feb  5 08:15:02 webserver01 systemd[1]: Started Daily apt download activities.
Feb  5 09:00:01 webserver01 CRON[12400]: (www-data) CMD (/usr/bin/php /var/www/cron.php)
"""

SAMPLE_AUTH_LOG = """\
Feb  5 03:22:11 prodserver sshd[9821]: Failed password for root from 198.51.100.23 port 48120 ssh2
Feb  5 03:22:13 prodserver sshd[9821]: Failed password for root from 198.51.100.23 port 48120 ssh2
Feb  5 03:22:14 prodserver sshd[9821]: Failed password for root from 198.51.100.23 port 48120 ssh2
Feb  5 03:22:16 prodserver sshd[9821]: Failed password for root from 198.51.100.23 port 48120 ssh2
Feb  5 03:22:18 prodserver sshd[9821]: Failed password for root from 198.51.100.23 port 48120 ssh2
Feb  5 03:22:20 prodserver sshd[9824]: Accepted publickey for deploy from 10.0.0.100 port 52200 ssh2
Feb  5 03:22:22 prodserver sshd[9825]: Failed password for admin from 198.51.100.23 port 48130 ssh2
Feb  5 03:22:24 prodserver sshd[9825]: Failed password for admin from 198.51.100.23 port 48130 ssh2
Feb  5 03:22:26 prodserver sshd[9825]: Failed password for admin from 198.51.100.23 port 48130 ssh2
Feb  5 03:23:01 prodserver sshd[9830]: Failed password for invalid user test from 198.51.100.23 port 48140 ssh2
Feb  5 03:23:03 prodserver sshd[9830]: Failed password for invalid user guest from 198.51.100.23 port 48141 ssh2
Feb  5 04:10:00 prodserver sshd[9900]: Accepted password for devuser from 10.0.0.55 port 60100 ssh2
Feb  5 22:45:33 prodserver sshd[11200]: Accepted password for devuser from 185.220.101.44 port 33210 ssh2
"""

SAMPLE_ACCESS_LOG = """\
10.0.0.20 - - [05/Feb/2025:10:15:30 +0000] "GET /index.html HTTP/1.1" 200 3421
10.0.0.20 - - [05/Feb/2025:10:15:31 +0000] "GET /style.css HTTP/1.1" 200 1122
203.0.113.77 - - [05/Feb/2025:10:16:00 +0000] "GET /admin/login HTTP/1.1" 200 512
203.0.113.77 - - [05/Feb/2025:10:16:02 +0000] "POST /admin/login HTTP/1.1" 401 58
203.0.113.77 - - [05/Feb/2025:10:16:03 +0000] "POST /admin/login HTTP/1.1" 401 58
203.0.113.77 - - [05/Feb/2025:10:16:04 +0000] "POST /admin/login HTTP/1.1" 401 58
203.0.113.77 - - [05/Feb/2025:10:16:05 +0000] "POST /admin/login HTTP/1.1" 401 58
203.0.113.77 - - [05/Feb/2025:10:16:06 +0000] "POST /admin/login HTTP/1.1" 401 58
203.0.113.77 - - [05/Feb/2025:10:16:07 +0000] "POST /admin/login HTTP/1.1" 200 1024
10.0.0.20 - - [05/Feb/2025:10:17:00 +0000] "GET /dashboard HTTP/1.1" 200 8192
203.0.113.77 - - [05/Feb/2025:10:17:05 +0000] "GET /admin/users HTTP/1.1" 200 2048
203.0.113.77 - - [05/Feb/2025:10:17:10 +0000] "GET /admin/export?table=users HTTP/1.1" 200 51200
203.0.113.77 - - [05/Feb/2025:10:17:15 +0000] "GET /admin/export?table=credentials HTTP/1.1" 200 102400
198.51.100.5 - - [05/Feb/2025:10:20:00 +0000] "GET /../../etc/passwd HTTP/1.1" 400 0
198.51.100.5 - - [05/Feb/2025:10:20:01 +0000] "GET /cgi-bin/test.cgi HTTP/1.1" 404 0
198.51.100.5 - - [05/Feb/2025:10:20:02 +0000] "GET /wp-admin/ HTTP/1.1" 404 0
198.51.100.5 - - [05/Feb/2025:10:20:03 +0000] "GET /phpmyadmin/ HTTP/1.1" 404 0
"""

SAMPLE_APP_LOG = """\
2025-02-05 11:00:01 INFO  app.startup: Application started on port 8080
2025-02-05 11:05:22 WARN  app.auth: Rate limit approaching for IP 203.0.113.77 (45/50 requests)
2025-02-05 11:05:30 ERROR app.auth: Authentication failure for user 'admin' from 203.0.113.77
2025-02-05 11:05:31 ERROR app.auth: Authentication failure for user 'admin' from 203.0.113.77
2025-02-05 11:05:32 ERROR app.auth: Authentication failure for user 'admin' from 203.0.113.77
2025-02-05 11:05:33 ERROR app.auth: Account locked: user 'admin' after 5 failed attempts
2025-02-05 11:10:00 INFO  app.db: Scheduled backup completed (23 tables, 1.2GB)
2025-02-05 11:15:44 ERROR app.db: Query timeout: SELECT * FROM transactions WHERE amount > 10000
2025-02-05 11:20:00 WARN  app.security: Possible SQL injection attempt from 198.51.100.5: ' OR 1=1--
2025-02-05 11:20:01 WARN  app.security: XSS attempt blocked from 198.51.100.5: <script>alert(1)</script>
2025-02-05 14:00:00 INFO  app.deploy: Deployment v2.4.1 started by user deploy_bot
2025-02-05 14:02:00 INFO  app.deploy: Deployment v2.4.1 completed successfully
"""


# ╔═══════════════════════════════════════════════════════════════════════════╗
# ║  Lesson 1 — Log Fundamentals                                            ║
# ╚═══════════════════════════════════════════════════════════════════════════╝

def _lesson_log_fundamentals(progress):
    """Lesson 1: Log Fundamentals."""
    section_header("Lesson 1: Log Fundamentals")

    learning_goal([
        "Understand what logs are and why they matter",
        "Recognize the four main types of logs",
        "Know where to find logs on different systems",
        "Read common log formats",
    ])

    pace()

    lesson_block(
        "Logs are the black-box recorder of every computer system. They capture "
        "events, errors, access attempts, and state changes."
    )

    lesson_block(
        "Security analysts use logs to figure out what happened -- and when -- "
        "during a breach or incident. Without logs, incident response is "
        "little more than guesswork."
    )

    pace()

    tip("Think of logs like a security camera for your server -- they record everything.")

    # --- Types of logs ---
    sub_header("Types of Logs")

    lesson_block(
        "1. SYSLOG / SYSTEM LOGS -- Generated by the operating system and its "
        "services. On Linux they live in /var/log/syslog or /var/log/messages."
    )

    lesson_block(
        "Syslog records kernel messages, service starts/stops, cron jobs, and "
        "firewall events."
    )

    info("Example syslog entries:")
    code_block(SAMPLE_SYSLOG, "syslog")

    pace()

    lesson_block(
        "2. AUTH / AUTHENTICATION LOGS -- Record every login attempt, whether it "
        "succeeded or failed, and from which IP address."
    )

    lesson_block(
        "On Linux: /var/log/auth.log (Debian/Ubuntu) or /var/log/secure "
        "(RHEL/CentOS). These are the first place to look when investigating "
        "brute-force attacks or unauthorized access."
    )

    info("Example auth.log entries:")
    code_block(SAMPLE_AUTH_LOG, "auth.log")

    pace()

    lesson_block(
        "3. WEB SERVER ACCESS LOGS -- Apache and Nginx write a line for every "
        "HTTP request. The Common Log Format includes: client IP, timestamp, "
        "request method/URI, HTTP status, and response size."
    )

    info("Example Apache access.log entries:")
    code_block(SAMPLE_ACCESS_LOG, "access.log")

    pace()

    lesson_block(
        "4. APPLICATION LOGS -- Your own software should produce structured logs "
        "at multiple severity levels: DEBUG, INFO, WARN, ERROR, CRITICAL."
    )

    lesson_block(
        "App logs capture business-logic events such as failed logins, "
        "rate-limit hits, database errors, and deployment activities."
    )

    info("Example application log entries:")
    code_block(SAMPLE_APP_LOG, "app.log")

    pace()

    nice_work("You just learned the four main log types -- that's a big deal!")

    press_enter()

    # --- Where to find logs ---
    sub_header("Where to Find Logs")

    lesson_block(
        "On a typical Linux server, the key log files are:"
    )
    code_block(
        "/var/log/syslog          # General system log (Debian/Ubuntu)\n"
        "/var/log/messages        # General system log (RHEL/CentOS)\n"
        "/var/log/auth.log        # Authentication events\n"
        "/var/log/secure          # Authentication events (RHEL/CentOS)\n"
        "/var/log/kern.log        # Kernel messages\n"
        "/var/log/apache2/        # Apache web server logs",
        "bash"
    )

    pace()

    code_block(
        "/var/log/nginx/          # Nginx web server logs\n"
        "/var/log/mysql/          # MySQL database logs\n"
        "/var/log/faillog         # Failed login attempts\n"
        "~/.bash_history          # User command history\n"
        "journalctl               # systemd journal (binary, use journalctl CLI)",
        "bash"
    )

    pace()

    lesson_block(
        "On macOS, system logs are accessed via Console.app or the 'log' CLI "
        "command. On Windows, use Event Viewer (eventvwr.msc) for Security, "
        "Application, and System event logs."
    )

    pace()

    # --- Log formats ---
    sub_header("Common Log Formats")

    lesson_block(
        "SYSLOG FORMAT (RFC 5424) in practice usually looks like the BSD-style "
        "variant: 'Month Day HH:MM:SS hostname process[PID]: message'."
    )

    pace()

    lesson_block(
        "COMMON LOG FORMAT (CLF) for web servers: "
        "host ident authuser [date] \"request\" status bytes. "
        "The Combined Log Format adds referer and user-agent fields."
    )

    pace()

    lesson_block(
        "JSON-STRUCTURED LOGS are popular in modern apps because they are easy "
        "to parse with tools like jq, Python, or log systems (ELK, Splunk)."
    )

    code_block(
        '{"timestamp": "2025-02-05T11:05:30Z", "level": "ERROR",\n'
        ' "service": "auth", "message": "Authentication failure",\n'
        ' "user": "admin", "source_ip": "203.0.113.77",\n'
        ' "request_id": "abc-123-def"}',
        "json"
    )

    pace()

    nice_work("You now know where to find logs and how to read them. Great progress!")

    press_enter()

    # --- Why logging matters ---
    why_it_matters(
        "Logs are legally admissible evidence when properly collected and stored. "
        "Many compliance frameworks (PCI-DSS, HIPAA, SOC 2) mandate centralized "
        "logging with retention periods of 90 days to one year."
    )

    pace()

    tip(
        "Without adequate logging, your organization cannot detect breaches, "
        "satisfy auditors, or perform forensic analysis after an incident."
    )

    pace()

    # --- Scenario ---
    scenario_block(
        "The Missing Logs",
        "A financial services company discovered unauthorized wire transfers "
        "totaling $2.3 million. When forensic investigators arrived, they found "
        "that the attackers had deleted /var/log/auth.log and rotated the web "
        "server logs to cover their tracks. Because the company had no "
        "centralized log aggregation, there was no off-box copy of the evidence. "
        "The lesson: always ship logs to a remote, append-only log collector "
        "that attackers cannot tamper with even if they gain root on the server."
    )

    press_enter()

    # --- Practice challenge ---
    sub_header("Practice Challenge: Identify the Log Type")

    lesson_block(
        "Look at the following log line and determine what TYPE of log it came "
        "from (syslog, auth, web access, or application):"
    )
    code_block(
        '198.51.100.5 - - [05/Feb/2025:10:20:00 +0000] '
        '"GET /../../etc/passwd HTTP/1.1" 400 0',
        "log"
    )
    hint_text("Look at the format: IP, date in brackets, HTTP request, status code...")

    if ask_yes_no("Ready to see the answer?"):
        success(
            "This is a WEB SERVER ACCESS LOG (Common Log Format). The giveaway "
            "is the IP address at the front, the bracketed date, the quoted HTTP "
            "request, and the numeric status code. This particular line also "
            "shows a path-traversal attack attempt (../../etc/passwd)."
        )

    mark_lesson_complete(progress, "module7", "log_fundamentals")
    success("Lesson 1 complete: Log Fundamentals")
    press_enter()


# ╔═══════════════════════════════════════════════════════════════════════════╗
# ║  Lesson 2 — Parsing Logs for Suspicious Activity                        ║
# ╚═══════════════════════════════════════════════════════════════════════════╝

def _lesson_parsing_logs(progress):
    """Lesson 2: Parsing Logs for Suspicious Activity."""
    section_header("Lesson 2: Parsing Logs for Suspicious Activity")

    learning_goal([
        "Use Python regex to pull data from log lines",
        "Build a brute-force login detector",
        "Parse web access logs for suspicious patterns",
    ])

    pace()

    lesson_block(
        "Manually reading log files is not practical when a busy server makes "
        "millions of lines per day. Security analysts write parsers -- small "
        "programs that pull structured data from raw log text."
    )

    lesson_block(
        "Python, with its built-in 're' (regular expression) module, is a "
        "great tool for this kind of work."
    )

    pace()

    # --- Regex primer ---
    sub_header("Regex Patterns for Security Log Parsing")

    lesson_block(
        "Regular expressions let you describe text patterns concisely. Here are "
        "the patterns most useful for log analysis:"
    )

    code_block(
        "# Detect failed SSH logins\n"
        'FAILED_SSH = r"Failed password for (\\S+) from (\\d+\\.\\d+\\.\\d+\\.\\d+)"\n\n'
        "# Detect successful SSH logins\n"
        'ACCEPTED_SSH = r"Accepted (\\w+) for (\\S+) from (\\d+\\.\\d+\\.\\d+\\.\\d+)"',
        "python"
    )

    pace()

    code_block(
        "# Detect HTTP 401/403 responses (access denied)\n"
        'HTTP_DENIED = r\'"\\w+ .+ HTTP/\\d\\.\\d" (401|403) \'\n\n'
        "# Detect path traversal attempts\n"
        'PATH_TRAVERSAL = r"\\.\\./|%2e%2e/|%2e%2e%5c"',
        "python"
    )

    pace()

    code_block(
        "# Detect SQL injection keywords in URLs\n"
        "SQL_INJECTION = r\"(UNION\\s+SELECT|OR\\s+1\\s*=\\s*1|'\\s*OR\\s*'|--\\s*$)\"\n\n"
        "# Detect common web scanner paths\n"
        'SCANNER_PATHS = r"/(wp-admin|phpmyadmin|cgi-bin|wp-login\\.php|xmlrpc\\.php)"',
        "python"
    )

    pace()

    tip("You don't have to memorize these patterns. Save them in a file and reuse them!")

    press_enter()

    # --- Building a log parser ---
    sub_header("Building a Brute-Force Detector")

    lesson_block(
        "Below is a Python script that reads auth.log data, counts failed SSH "
        "login attempts per IP, and flags any IP that exceeds a threshold."
    )

    pace()

    lesson_block(
        "Study the code carefully -- it is a pattern you can adapt to many "
        "log-analysis tasks."
    )

    code_block(
        'import re\n'
        'from collections import Counter\n'
        '\n'
        'AUTH_LOG = """  # <-- paste SAMPLE_AUTH_LOG here\n'
        '"""\n'
        '\n'
        'FAILED_PATTERN = re.compile(\n'
        '    r"Failed password for (?:invalid user )?(\\S+) from (\\d+\\.\\d+\\.\\d+\\.\\d+)"\n'
        ')\n'
        'THRESHOLD = 3  # flag IPs with more than 3 failures',
        "python"
    )

    pace()

    code_block(
        'def detect_brute_force(log_text, threshold=THRESHOLD):\n'
        '    """Return dict of {ip: count} for IPs exceeding the threshold."""\n'
        '    ip_counts = Counter()\n'
        '    for line in log_text.strip().splitlines():\n'
        '        match = FAILED_PATTERN.search(line)\n'
        '        if match:\n'
        '            user, ip = match.groups()\n'
        '            ip_counts[ip] += 1\n'
        '    return {\n'
        '        ip: count for ip, count in ip_counts.items()\n'
        '        if count > threshold\n'
        '    }\n'
        '\n'
        'flagged = detect_brute_force(AUTH_LOG)\n'
        'for ip, count in flagged.items():\n'
        '    print(f"ALERT: {ip} had {count} failed login attempts")',
        "python"
    )

    pace()

    nice_work("You just saw a real brute-force detector in Python. That's a valuable skill!")

    press_enter()

    # --- Live demo ---
    sub_header("Live Demo: Running the Parser on Sample Data")

    import re
    from collections import Counter

    failed_pattern = re.compile(
        r"Failed password for (?:invalid user )?(\S+) from (\d+\.\d+\.\d+\.\d+)"
    )

    ip_counts = Counter()
    user_counts = Counter()
    for line in SAMPLE_AUTH_LOG.strip().splitlines():
        match = failed_pattern.search(line)
        if match:
            user, ip = match.groups()
            ip_counts[ip] += 1
            user_counts[user] += 1

    info("Parsing SAMPLE_AUTH_LOG for failed SSH attempts...")
    print()
    for ip, count in ip_counts.most_common():
        severity = f"{R}CRITICAL" if count >= 5 else f"{Y}WARNING"
        print(f"  {severity}{RESET}  IP {ip}: {count} failed attempts")
    print()

    pace()

    info("Targeted usernames:")
    for user, count in user_counts.most_common():
        print(f"    {user}: {count} attempts")

    press_enter()

    # --- Web log parser ---
    sub_header("Parsing Web Access Logs")

    lesson_block(
        "The same approach works for web server logs. Here we parse the "
        "Combined Log Format to find suspicious patterns."
    )

    lesson_block(
        "We look for repeated 401s, path-traversal attempts, and common "
        "scanner probes."
    )

    pace()

    code_block(
        'import re\n'
        'from collections import Counter\n'
        '\n'
        'CLF_PATTERN = re.compile(\n'
        '    r\'(?P<ip>\\S+) \\S+ \\S+ \\[(?P<date>[^\\]]+)\\] \'\n'
        '    r\'"(?P<method>\\S+) (?P<path>\\S+) \\S+" (?P<status>\\d+) (?P<size>\\d+)\'\n'
        ')\n'
        '\n'
        'SUSPICIOUS_PATHS = re.compile(\n'
        '    r"\\.\\./|/etc/passwd|/wp-admin|/phpmyadmin|/cgi-bin"\n'
        ')',
        "python"
    )

    pace()

    code_block(
        'def analyze_access_log(log_text):\n'
        '    results = {"total": 0, "by_ip": Counter(), "errors": Counter(),\n'
        '              "suspicious": []}\n'
        '    for line in log_text.strip().splitlines():\n'
        '        m = CLF_PATTERN.search(line)\n'
        '        if not m:\n'
        '            continue\n'
        '        results["total"] += 1\n'
        '        ip = m.group("ip")\n'
        '        status = int(m.group("status"))\n'
        '        path = m.group("path")\n'
        '        results["by_ip"][ip] += 1\n'
        '        if status >= 400:\n'
        '            results["errors"][ip] += 1\n'
        '        if SUSPICIOUS_PATHS.search(path):\n'
        '            results["suspicious"].append(\n'
        '                {"ip": ip, "path": path, "status": status}\n'
        '            )\n'
        '    return results',
        "python"
    )

    pace()

    press_enter()

    # --- Live demo: web log ---
    sub_header("Live Demo: Analyzing Sample Access Logs")

    clf_pattern = re.compile(
        r'(?P<ip>\S+) \S+ \S+ \[(?P<date>[^\]]+)\] '
        r'"(?P<method>\S+) (?P<path>\S+) \S+" (?P<status>\d+) (?P<size>\d+)'
    )
    suspicious_paths = re.compile(
        r"\.\./|/etc/passwd|/wp-admin|/phpmyadmin|/cgi-bin"
    )

    ip_requests = Counter()
    ip_errors = Counter()
    suspicious = []
    for line in SAMPLE_ACCESS_LOG.strip().splitlines():
        m = clf_pattern.search(line)
        if not m:
            continue
        ip = m.group("ip")
        status = int(m.group("status"))
        path = m.group("path")
        ip_requests[ip] += 1
        if status >= 400:
            ip_errors[ip] += 1
        if suspicious_paths.search(path):
            suspicious.append({"ip": ip, "path": path, "status": status})

    info("Request counts by IP:")
    for ip, count in ip_requests.most_common():
        print(f"    {ip}: {count} requests")
    print()

    pace()

    if ip_errors:
        warning("IPs generating errors:")
        for ip, count in ip_errors.most_common():
            print(f"    {ip}: {count} error responses")
    print()

    pace()

    if suspicious:
        warning("Suspicious requests detected:")
        for s in suspicious:
            print(f"    {R}[!]{RESET} {s['ip']} -> {s['path']} (HTTP {s['status']})")

    press_enter()

    nice_work("You can now parse both auth logs and web logs for threats. Keep it up!")

    why_it_matters(
        "Automated log parsing is how security operations centers (SOCs) scale. "
        "A human cannot review millions of log lines, but a well-written parser "
        "can process them in seconds and surface only the events that need "
        "human attention."
    )

    pace()

    tip(
        "This is the foundation of SIEM systems like Splunk, Elastic SIEM, "
        "and Microsoft Sentinel."
    )

    pace()

    scenario_block(
        "Brute Force at 3 AM",
        "A startup's on-call engineer was paged at 3 AM when their monitoring "
        "detected 12,000 failed SSH login attempts in 10 minutes from a single "
        "IP in Eastern Europe.  Their Python-based log parser, running as a "
        "cron job every 5 minutes, caught it immediately.  The automated "
        "response script added the IP to the firewall blocklist within seconds, "
        "and the engineer confirmed the block and went back to sleep.  Without "
        "that parser, the attack might have continued for hours."
    )

    press_enter()

    # --- Practice challenge ---
    sub_header("Practice Challenge: Count 401 Responses per IP")

    lesson_block(
        "Using the SAMPLE_ACCESS_LOG data above, figure out how many HTTP 401 "
        "responses each IP received. Which IP has the most 401s, and how many?"
    )
    hint_text(
        "Look for lines where the status code is 401.  "
        "IP 203.0.113.77 makes several POST /admin/login requests..."
    )

    if ask_yes_no("Ready to see the answer?"):
        success(
            "IP 203.0.113.77 received 5 HTTP 401 responses, all from rapid-fire "
            "POST requests to /admin/login. This is a classic brute-force login "
            "pattern against a web application."
        )
        mark_challenge_complete(progress, "module7", "count_401_challenge")

    mark_lesson_complete(progress, "module7", "parsing_logs")
    success("Lesson 2 complete: Parsing Logs for Suspicious Activity")
    press_enter()


# ╔═══════════════════════════════════════════════════════════════════════════╗
# ║  Lesson 3 — Building Alerting Scripts                                   ║
# ╚═══════════════════════════════════════════════════════════════════════════╝

def _lesson_alerting_scripts(progress):
    """Lesson 3: Building Alerting Scripts."""
    section_header("Lesson 3: Building Alerting Scripts")

    learning_goal([
        "Set smart alert thresholds to avoid alert fatigue",
        "Send alerts via email and Slack",
        "Build a real-time log monitoring script",
    ])

    pace()

    lesson_block(
        "A log parser that runs once is useful. A log parser that runs "
        "continuously and alerts you when something bad happens is essential."
    )

    lesson_block(
        "In this lesson we build toward a monitoring script that watches a log "
        "file in near-real-time and fires alerts when suspicious patterns "
        "exceed configurable thresholds."
    )

    pace()

    # --- Thresholds ---
    sub_header("Defining Alert Thresholds")

    lesson_block(
        "Before you can alert, you need to decide WHEN to alert. Thresholds "
        "should be tuned to your environment to avoid alert fatigue (too many "
        "false positives) while still catching real threats."
    )

    pace()

    lesson_block(
        "Here are sensible starting points:"
    )

    code_block(
        "ALERT_THRESHOLDS = {\n"
        '    "failed_ssh_per_ip":       5,    # per 10-minute window\n'
        '    "failed_web_login_per_ip": 10,   # per 10-minute window\n'
        '    "404_per_ip":              50,   # per 10-minute window (scanners)\n'
        '    "path_traversal":          1,    # any attempt is suspicious\n'
        '    "sql_injection":           1,    # any attempt is suspicious\n'
        '    "new_root_login":          1,    # any root login is notable\n'
        '    "off_hours_login":         1,    # login outside business hours\n'
        "}",
        "python"
    )

    pace()

    lesson_block(
        "Notice that some thresholds are count-based (N occurrences in a time "
        "window) while others are binary (any single occurrence is an alert)."
    )

    tip(
        "The time window matters: 5 failed logins in 10 minutes is suspicious, "
        "but 5 over an entire month is normal human forgetfulness."
    )

    pace()

    nice_work("Understanding thresholds is key to effective alerting!")

    press_enter()

    # --- Email notification ---
    sub_header("Email Notification Concepts")

    lesson_block(
        "The most common alert delivery methods are email, Slack/Teams webhooks, "
        "PagerDuty, and writing to a SIEM."
    )

    lesson_block(
        "Here is how you would send an email alert from Python using the "
        "built-in smtplib:"
    )

    code_block(
        'import smtplib\n'
        'from email.mime.text import MIMEText\n'
        '\n'
        'def send_alert_email(subject, body, to_addr, smtp_host="localhost"):\n'
        '    """Send a plain-text email alert.\n\n'
        '    In production, use TLS and authenticate with the SMTP server.\n'
        '    Never hardcode credentials — use environment variables.\n'
        '    """\n'
        '    msg = MIMEText(body)\n'
        '    msg["Subject"] = f"[SECURITY ALERT] {subject}"\n'
        '    msg["From"] = "securitylab@example.com"\n'
        '    msg["To"] = to_addr',
        "python"
    )

    pace()

    code_block(
        '    with smtplib.SMTP(smtp_host, 25) as server:\n'
        '        # In production:\n'
        '        # server.starttls()\n'
        '        # server.login(os.environ["SMTP_USER"], os.environ["SMTP_PASS"])\n'
        '        server.send_message(msg)\n'
        '        print(f"Alert sent to {to_addr}: {subject}")',
        "python"
    )

    pace()

    lesson_block(
        "For Slack webhooks, you POST a JSON payload to a webhook URL. "
        "This is often preferred because it puts alerts where the team is "
        "already communicating:"
    )

    code_block(
        'import json\n'
        'import urllib.request\n'
        '\n'
        'def send_slack_alert(webhook_url, message):\n'
        '    """Send an alert to a Slack channel via webhook."""\n'
        '    payload = json.dumps({"text": f":rotating_light: {message}"}).encode()\n'
        '    req = urllib.request.Request(\n'
        '        webhook_url,\n'
        '        data=payload,\n'
        '        headers={"Content-Type": "application/json"},\n'
        '    )\n'
        '    urllib.request.urlopen(req)',
        "python"
    )

    pace()

    press_enter()

    # --- Monitoring script ---
    sub_header("A Complete Log Monitoring Script")

    lesson_block(
        "This script shows how to watch a log file for new entries and check "
        "them against alert rules. It uses a 'tail -f' style approach."
    )

    tip("In production you would run this as a systemd service or in a container.")

    pace()

    code_block(
        'import re\n'
        'import time\n'
        'from collections import Counter, defaultdict\n'
        'from datetime import datetime, timedelta\n'
        '\n'
        'FAILED_SSH = re.compile(\n'
        '    r"Failed password for (?:invalid user )?(\\S+) from (\\d+\\.\\d+\\.\\d+\\.\\d+)"\n'
        ')\n'
        '\n'
        'class LogMonitor:\n'
        '    """Watch a log file and alert on suspicious patterns."""\n'
        '\n'
        '    def __init__(self, log_path, threshold=5, window_minutes=10):\n'
        '        self.log_path = log_path\n'
        '        self.threshold = threshold\n'
        '        self.window = timedelta(minutes=window_minutes)\n'
        '        self.events = defaultdict(list)  # ip -> [timestamps]\n'
        '        self.alerted = set()  # IPs already alerted',
        "python"
    )

    pace()

    code_block(
        '    def check_line(self, line):\n'
        '        """Analyze a single log line for threats."""\n'
        '        match = FAILED_SSH.search(line)\n'
        '        if match:\n'
        '            user, ip = match.groups()\n'
        '            now = datetime.now()\n'
        '            self.events[ip].append(now)\n'
        '            # Prune events outside the window\n'
        '            cutoff = now - self.window\n'
        '            self.events[ip] = [\n'
        '                t for t in self.events[ip] if t > cutoff\n'
        '            ]\n'
        '            if (len(self.events[ip]) >= self.threshold\n'
        '                    and ip not in self.alerted):\n'
        '                self.fire_alert(ip, len(self.events[ip]))\n'
        '                self.alerted.add(ip)',
        "python"
    )

    pace()

    code_block(
        '    def fire_alert(self, ip, count):\n'
        '        """Handle an alert — log it, email it, etc."""\n'
        '        msg = (f"BRUTE FORCE ALERT: {ip} has {count} failed "\n'
        '               f"SSH attempts in the last {self.window}")\n'
        '        print(f"[{datetime.now().isoformat()}] {msg}")\n'
        '\n'
        '    def tail(self):\n'
        '        """Continuously read new lines from the log file."""\n'
        '        with open(self.log_path, "r") as f:\n'
        '            f.seek(0, 2)  # jump to end of file\n'
        '            while True:\n'
        '                line = f.readline()\n'
        '                if line:\n'
        '                    self.check_line(line)\n'
        '                else:\n'
        '                    time.sleep(1)  # wait for new data\n'
        '\n'
        '# Usage:\n'
        '# monitor = LogMonitor("/var/log/auth.log", threshold=5)\n'
        '# monitor.tail()',
        "python"
    )

    pace()

    nice_work("You now know how to build a real-time log monitor from scratch!")

    press_enter()

    # --- Simulated alert ---
    sub_header("Simulated Alert: Processing Sample Auth Log")

    from collections import defaultdict
    from datetime import datetime, timedelta
    import re

    failed_ssh = re.compile(
        r"Failed password for (?:invalid user )?(\S+) from (\d+\.\d+\.\d+\.\d+)"
    )

    ip_events = defaultdict(int)
    alerts_fired = []
    threshold = 3

    for line in SAMPLE_AUTH_LOG.strip().splitlines():
        match = failed_ssh.search(line)
        if match:
            user, ip = match.groups()
            ip_events[ip] += 1
            if ip_events[ip] == threshold:
                alerts_fired.append(
                    f"ALERT: {ip} reached {threshold} failed attempts "
                    f"(targeting user '{user}')"
                )

    if alerts_fired:
        warning("Alerts fired during simulation:")
        for alert in alerts_fired:
            print(f"    {R}{alert}{RESET}")
    else:
        info("No alerts fired (all IPs below threshold).")

    pace()

    # Show final counts
    print()
    info("Final failed-attempt counts:")
    for ip, count in sorted(ip_events.items(), key=lambda x: -x[1]):
        print(f"    {ip}: {count}")

    press_enter()

    why_it_matters(
        "Real-time alerting is what separates a reactive security posture from "
        "a proactive one. The average time to detect a breach is 204 days "
        "(IBM Cost of a Data Breach Report). Automated monitoring can reduce "
        "that to minutes or seconds."
    )

    pace()

    scenario_block(
        "Alert Fatigue at a Hospital",
        "A hospital IT team configured their SIEM to alert on every single "
        "failed login across all systems.  Within a week, the security inbox had "
        "over 50,000 unread alerts.  Staff began ignoring them entirely.  When a "
        "real compromise occurred — a nurse's credentials were phished and used "
        "to access patient records — the alert was buried among thousands of "
        "routine failures.  The fix: tiered thresholds, deduplication, and "
        "severity-based routing so critical alerts go to PagerDuty while low-"
        "severity events go to a weekly report."
    )

    press_enter()

    # --- Practice challenge ---
    sub_header("Practice Challenge: Design Alert Rules")

    lesson_block(
        "Look at the SAMPLE_ACCESS_LOG data. If you were building an alerting "
        "script for this web server, list at least THREE alert rules you would "
        "create, each with a specific threshold."
    )
    hint_text(
        "Think about: repeated 401s, path traversal, scanner paths, "
        "large response sizes from admin endpoints, login followed by "
        "data export..."
    )

    if ask_yes_no("Ready to see suggested answers?"):
        success("Suggested alert rules:")
        print(f"    1. {G}Brute-force login{RESET}: >5 HTTP 401 from same IP in 1 minute")
        print(f"    2. {G}Path traversal{RESET}: Any request containing '../' (threshold: 1)")
        print(f"    3. {G}Scanner detection{RESET}: >3 requests to known scanner paths")
        print(f"       (wp-admin, phpmyadmin, cgi-bin) from same IP in 5 minutes")
        print(f"    4. {G}Data exfiltration{RESET}: Requests to /admin/export with")
        print(f"       response size > 50KB, especially for sensitive tables")
        print(f"    5. {G}Credential access after brute-force{RESET}: A 200 on /admin/login")
        print(f"       after multiple 401s indicates a successful breach")
        mark_challenge_complete(progress, "module7", "design_alert_rules_challenge")

    mark_lesson_complete(progress, "module7", "alerting_scripts")
    success("Lesson 3 complete: Building Alerting Scripts")
    press_enter()


# ╔═══════════════════════════════════════════════════════════════════════════╗
# ║  Lesson 4 — Automating Security Checks                                  ║
# ╚═══════════════════════════════════════════════════════════════════════════╝

def _lesson_automating_checks(progress):
    """Lesson 4: Automating Security Checks."""
    section_header("Lesson 4: Automating Security Checks")

    learning_goal([
        "Build a daily security check script",
        "Schedule automated tasks with cron",
        "Understand the four phases of incident response",
    ])

    pace()

    lesson_block(
        "Continuous security is not a one-time effort. Mature organizations "
        "run automated daily, weekly, and monthly security checks that surface "
        "problems before attackers find them."
    )

    lesson_block(
        "In this lesson we build a daily security check script, learn how to "
        "schedule it with cron, and cover the fundamentals of incident response."
    )

    pace()

    # --- Daily security check script ---
    sub_header("Building a Daily Security Check Script")

    lesson_block(
        "A daily security check script performs several automated inspections "
        "and compiles the results into a report. Here is a comprehensive example."
    )

    tip("Don't worry about memorizing every line -- focus on the overall pattern.")

    pace()

    code_block(
        '#!/usr/bin/env python3\n'
        '"""daily_security_check.py — Automated daily security audit."""\n'
        '\n'
        'import os\n'
        'import re\n'
        'import subprocess\n'
        'import hashlib\n'
        'from datetime import datetime\n'
        'from collections import Counter\n'
        'from pathlib import Path\n'
        '\n'
        'REPORT_DIR = Path("/var/log/security_reports")\n'
        'CRITICAL_FILES = [\n'
        '    "/etc/passwd", "/etc/shadow", "/etc/ssh/sshd_config",\n'
        '    "/etc/sudoers",\n'
        ']',
        "python"
    )

    pace()

    code_block(
        'class SecurityReport:\n'
        '    def __init__(self):\n'
        '        self.timestamp = datetime.now().isoformat()\n'
        '        self.findings = []   # (severity, category, message)\n'
        '        self.stats = {}\n'
        '\n'
        '    def add_finding(self, severity, category, message):\n'
        '        self.findings.append((severity, category, message))\n'
        '\n'
        '    def check_failed_logins(self, log_path="/var/log/auth.log"):\n'
        '        """Count failed logins in the last 24 hours."""\n'
        '        pattern = re.compile(r"Failed password.+from (\\S+)")\n'
        '        ip_counts = Counter()\n'
        '        try:\n'
        '            with open(log_path) as f:\n'
        '                for line in f:\n'
        '                    m = pattern.search(line)\n'
        '                    if m:\n'
        '                        ip_counts[m.group(1)] += 1\n'
        '        except FileNotFoundError:\n'
        '            self.add_finding("WARN", "LOGS",\n'
        '                             f"Auth log not found: {log_path}")\n'
        '            return\n'
        '        self.stats["failed_logins"] = sum(ip_counts.values())\n'
        '        for ip, count in ip_counts.items():\n'
        '            if count > 20:\n'
        '                self.add_finding("CRITICAL", "AUTH",\n'
        '                    f"Brute force: {ip} had {count} failures")\n'
        '            elif count > 5:\n'
        '                self.add_finding("WARN", "AUTH",\n'
        '                    f"Elevated failures from {ip}: {count}")',
        "python"
    )

    pace()

    code_block(
        '    def check_file_integrity(self):\n'
        '        """Hash critical files and compare to known-good values."""\n'
        '        for filepath in CRITICAL_FILES:\n'
        '            if not os.path.exists(filepath):\n'
        '                self.add_finding("INFO", "INTEGRITY",\n'
        '                    f"File not found (expected on this OS?): {filepath}")\n'
        '                continue\n'
        '            h = hashlib.sha256()\n'
        '            with open(filepath, "rb") as f:\n'
        '                h.update(f.read())\n'
        '            digest = h.hexdigest()\n'
        '            self.add_finding("INFO", "INTEGRITY",\n'
        '                f"{filepath}: SHA256={digest[:16]}...")',
        "python"
    )

    pace()

    code_block(
        '    def check_open_ports(self):\n'
        '        """List listening TCP ports (requires ss or netstat)."""\n'
        '        try:\n'
        '            result = subprocess.run(\n'
        '                ["ss", "-tlnp"], capture_output=True, text=True\n'
        '            )\n'
        '            ports = re.findall(r":(\\d+)\\s", result.stdout)\n'
        '            self.stats["open_ports"] = sorted(set(ports))\n'
        '            unexpected = set(ports) - {"22", "80", "443"}\n'
        '            if unexpected:\n'
        '                self.add_finding("WARN", "NETWORK",\n'
        '                    f"Unexpected open ports: {unexpected}")\n'
        '        except FileNotFoundError:\n'
        '            self.add_finding("INFO", "NETWORK",\n'
        '                "ss command not found; skipping port check")',
        "python"
    )

    pace()

    code_block(
        '    def generate_report(self):\n'
        '        """Format findings as a text report."""\n'
        '        lines = [\n'
        '            f"=== Daily Security Report ===",\n'
        '            f"Generated: {self.timestamp}",\n'
        '            f"",\n'
        '        ]\n'
        '        for sev, cat, msg in sorted(self.findings):\n'
        '            lines.append(f"[{sev:8s}] [{cat}] {msg}")\n'
        '        lines.append(f"\\n--- Stats ---")\n'
        '        for k, v in self.stats.items():\n'
        '            lines.append(f"  {k}: {v}")\n'
        '        return "\\n".join(lines)\n'
        '\n'
        '    def run_all_checks(self):\n'
        '        self.check_failed_logins()\n'
        '        self.check_file_integrity()\n'
        '        self.check_open_ports()\n'
        '        return self.generate_report()',
        "python"
    )

    pace()

    nice_work("That was a big script! The key idea: automate checks, collect findings, generate a report.")

    press_enter()

    # --- Cron concepts ---
    sub_header("Scheduling with Cron")

    lesson_block(
        "Cron is the standard Unix scheduler. You edit the cron table with "
        "'crontab -e' and add lines in this format:"
    )

    code_block(
        "# ┌───────────── minute (0 - 59)\n"
        "# │ ┌─────────── hour (0 - 23)\n"
        "# │ │ ┌───────── day of month (1 - 31)\n"
        "# │ │ │ ┌─────── month (1 - 12)\n"
        "# │ │ │ │ ┌───── day of week (0 - 7, Sun=0 or 7)\n"
        "# │ │ │ │ │\n"
        "# * * * * * command",
        "crontab"
    )

    pace()

    code_block(
        "# Run the daily security check at 6:00 AM every day\n"
        "0 6 * * * /usr/bin/python3 /opt/security/daily_security_check.py\n"
        "\n"
        "# Run log analysis every 5 minutes\n"
        "*/5 * * * * /usr/bin/python3 /opt/security/log_monitor.py\n"
        "\n"
        "# Weekly full vulnerability scan on Sundays at midnight\n"
        "0 0 * * 0 /usr/bin/python3 /opt/security/weekly_vuln_scan.py\n"
        "\n"
        "# Monthly report on the 1st at 8:00 AM\n"
        "0 8 1 * * /usr/bin/python3 /opt/security/monthly_report.py",
        "crontab"
    )

    pace()

    lesson_block(
        "Important cron tips: (1) Use absolute paths for both the interpreter "
        "and the script. (2) Redirect output to a log file with >> so you can "
        "debug failures."
    )

    lesson_block(
        "(3) Set the PATH environment variable at the top of the crontab. "
        "(4) On modern systems, consider using systemd timers instead, which "
        "offer better logging and dependency management."
    )

    pace()

    press_enter()

    # --- Reporting ---
    sub_header("Formatting Security Reports")

    lesson_block(
        "A good security report is actionable. It should include a severity "
        "rating, a category, a clear description, and a recommended action."
    )

    pace()

    lesson_block(
        "Here is a sample output from the daily security check script:"
    )

    sample_report = (
        "=== Daily Security Report ===\n"
        "Generated: 2025-02-05T06:00:01\n"
        "\n"
        "[CRITICAL] [AUTH] Brute force: 198.51.100.23 had 45 failures\n"
        "[CRITICAL] [PERMISSIONS] 2 world-writable files in /etc\n"
        "[WARN    ] [AUTH] Elevated failures from 203.0.113.50: 8\n"
        "[WARN    ] [NETWORK] Unexpected open ports: {'8080', '3306'}\n"
        "[INFO    ] [INTEGRITY] /etc/passwd: SHA256=a1b2c3d4e5f6...\n"
        "[INFO    ] [INTEGRITY] /etc/shadow: SHA256=f6e5d4c3b2a1...\n"
        "\n"
        "--- Stats ---\n"
        "  failed_logins: 53\n"
        "  open_ports: ['22', '80', '443', '3306', '8080']"
    )
    code_block(sample_report, "report")

    pace()

    press_enter()

    # --- Incident Response ---
    sub_header("Incident Response Fundamentals")

    lesson_block(
        "When your monitoring detects a real security incident, you need a "
        "structured process to handle it. The NIST Incident Response framework "
        "(SP 800-61) defines four phases."
    )

    pace()

    lesson_block(
        "PHASE 1: PREPARATION\n"
        "Have an incident response plan BEFORE you need it. This includes: "
        "defined roles, communication templates, contact lists, and "
        "pre-authorized actions (e.g., 'the on-call engineer may block IPs "
        "without manager approval')."
    )

    pace()

    lesson_block(
        "PHASE 2: DETECTION & ANALYSIS\n"
        "This is where your monitoring and log analysis skills pay off. "
        "Confirm the incident is real (not a false positive), determine its "
        "scope, assess severity, and document everything with timestamps."
    )

    pace()

    lesson_block(
        "PHASE 3: CONTAINMENT, ERADICATION & RECOVERY\n"
        "CONTAIN: Stop the bleeding -- isolate affected systems, block attacker "
        "IPs, disable compromised accounts."
    )

    lesson_block(
        "ERADICATE: Remove the threat -- delete malware, patch the vulnerability. "
        "RECOVER: Restore normal operations from clean backups, reset credentials."
    )

    pace()

    lesson_block(
        "PHASE 4: LESSONS LEARNED (Post-Incident Review)\n"
        "Within 1-2 weeks, hold a blameless post-mortem. Document what happened, "
        "what went well, and what specific actions will prevent recurrence."
    )

    pace()

    nice_work("You now know the four IR phases. This knowledge is used in every security job!")

    press_enter()

    # --- IR automation script ---
    sub_header("Automated Incident Response Actions")

    lesson_block(
        "Some containment actions can be automated for speed. Here is an "
        "example of an auto-response script that blocks an attacker's IP "
        "at the firewall level."
    )

    pace()

    code_block(
        'import subprocess\n'
        'import logging\n'
        'from datetime import datetime\n'
        '\n'
        'IR_LOG = logging.getLogger("incident_response")\n'
        '\n'
        'def block_ip(ip_address, reason="automated block"):\n'
        '    """Add a firewall rule to block an IP address.\n\n'
        '    Uses iptables on Linux. Logs every action for audit trail.\n'
        '    """\n'
        '    IR_LOG.warning(\n'
        '        f"BLOCKING {ip_address} — reason: {reason} "\n'
        '        f"— time: {datetime.now().isoformat()}"\n'
        '    )\n'
        '    result = subprocess.run(\n'
        '        ["iptables", "-A", "INPUT", "-s", ip_address,\n'
        '         "-j", "DROP"],\n'
        '        capture_output=True, text=True\n'
        '    )\n'
        '    if result.returncode == 0:\n'
        '        IR_LOG.info(f"Successfully blocked {ip_address}")\n'
        '    else:\n'
        '        IR_LOG.error(f"Failed to block {ip_address}: "\n'
        '                     f"{result.stderr}")\n'
        '    return result.returncode == 0',
        "python"
    )

    pace()

    code_block(
        'def disable_user(username):\n'
        '    """Lock a compromised user account."""\n'
        '    IR_LOG.warning(f"DISABLING user {username}")\n'
        '    subprocess.run(["passwd", "-l", username])\n'
        '    subprocess.run(["pkill", "-u", username])  # kill sessions\n'
        '\n'
        'def snapshot_system(hostname):\n'
        '    """Create a forensic snapshot before cleanup."""\n'
        '    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")\n'
        '    archive = f"/forensics/{hostname}_{timestamp}.tar.gz"\n'
        '    IR_LOG.info(f"Creating forensic snapshot: {archive}")\n'
        '    subprocess.run([\n'
        '        "tar", "czf", archive,\n'
        '        "/var/log", "/etc", "/tmp",\n'
        '        "--exclude=/proc", "--exclude=/sys"\n'
        '    ])',
        "python"
    )

    pace()

    tip("Always log automated IR actions so you have an audit trail of what happened.")

    press_enter()

    why_it_matters(
        "Automated security checks catch configuration drift -- the gradual "
        "weakening of a system's security posture over time as ad-hoc changes "
        "accumulate. Without daily checks, you might not discover that someone "
        "opened port 3306 to the internet until an attacker exploits it."
    )

    pace()

    scenario_block(
        "The 72-Hour Incident",
        "A SaaS company detected unusual database queries at 2 AM via their "
        "automated monitoring. The IR team followed their playbook: "
        "Phase 1 (Contain) - isolated the database server within 15 minutes. "
        "Phase 2 (Analyze) - discovered a SQL injection vulnerability in an "
        "API endpoint, traced the attacker's queries. Phase 3 (Eradicate) - "
        "patched the code, rotated all database credentials. Phase 4 (Recover) "
        "- restored from a verified clean backup. Phase 5 (Lessons Learned) - "
        "added parameterized query enforcement to CI/CD pipeline, mandatory "
        "code review for all database-touching code, and new SIEM rules to "
        "detect anomalous query patterns. Total customer data exposed: zero, "
        "because the automated alert triggered before the attacker could "
        "exfiltrate."
    )

    press_enter()

    # --- Practice challenge ---
    sub_header("Practice Challenge: Write an IR Checklist")

    lesson_block(
        "Imagine your monitoring script fires this alert:\n\n"
        "  ALERT: IP 185.220.101.44 logged in as 'devuser' via SSH\n"
        "  at 22:45 (outside business hours) from a Tor exit node.\n\n"
        "Write a step-by-step incident response plan. What would you do "
        "first, second, and third?"
    )
    hint_text(
        "Think about the four IR phases: contain, analyze, eradicate, recover."
    )

    if ask_yes_no("Ready to see a model answer?"):
        success("Model IR Checklist:")
        print(f"    {G}STEP 1 (Contain, immediate):{RESET}")
        print("      - Force-disconnect the SSH session (kill the PID)")
        print("      - Lock the 'devuser' account (passwd -l devuser)")
        print("      - Block IP 185.220.101.44 at the firewall")
        print()
        print(f"    {G}STEP 2 (Analyze, within 1 hour):{RESET}")
        print("      - Review bash_history for what commands were run")
        print("      - Check if any files were modified/exfiltrated")
        print("      - Determine how the attacker got devuser's password")
        print("      - Check other servers for login from the same IP")
        print()
        print(f"    {G}STEP 3 (Eradicate & Recover):{RESET}")
        print("      - Reset devuser's password and SSH keys")
        print("      - If keys were compromised, rotate ALL keys on this server")
        print("      - Patch the entry vector (weak password? leaked creds?)")
        print()
        print(f"    {G}STEP 4 (Lessons Learned):{RESET}")
        print("      - Require MFA for SSH (or key-only auth)")
        print("      - Add off-hours login alerting permanently")
        print("      - Block all Tor exit nodes if not needed for business")
        mark_challenge_complete(progress, "module7", "ir_checklist_challenge")

    mark_lesson_complete(progress, "module7", "automating_checks")
    success("Lesson 4 complete: Automating Security Checks")
    press_enter()


# ╔═══════════════════════════════════════════════════════════════════════════╗
# ║  Quiz                                                                    ║
# ╚═══════════════════════════════════════════════════════════════════════════╝

MODULE7_QUIZ = [
    {
        "q": "Which log file on a Debian/Ubuntu Linux system records SSH login attempts?",
        "options": [
            "A) /var/log/syslog",
            "B) /var/log/auth.log",
            "C) /var/log/access.log",
            "D) /var/log/kern.log",
        ],
        "answer": "b",
        "explanation": (
            "/var/log/auth.log records authentication events including SSH "
            "logins, sudo usage, and PAM events on Debian-based systems. "
            "On RHEL/CentOS, the equivalent is /var/log/secure."
        ),
    },
    {
        "q": "What does the following regex match?\n      r\"Failed password for (\\S+) from (\\d+\\.\\d+\\.\\d+\\.\\d+)\"",
        "options": [
            "A) Successful SSH logins with username and IP",
            "B) Failed SSH logins, capturing the username and source IP",
            "C) Any password change event",
            "D) Firewall blocked connections",
        ],
        "answer": "b",
        "explanation": (
            "The regex matches 'Failed password for <user> from <IP>' lines "
            "in auth.log. The two capture groups extract the username (\\S+) "
            "and the IP address (\\d+\\.\\d+\\.\\d+\\.\\d+)."
        ),
    },
    {
        "q": "In the cron entry '*/5 * * * * /usr/bin/python3 script.py', how often does the script run?",
        "options": [
            "A) Every 5 hours",
            "B) Every 5 minutes",
            "C) At 5:00 AM daily",
            "D) On the 5th of every month",
        ],
        "answer": "b",
        "explanation": (
            "*/5 in the first field (minute) means 'every 5 minutes'. "
            "The asterisks in all other fields mean 'every hour, every day, "
            "every month, every day of week'."
        ),
    },
    {
        "q": "What is the FIRST step in incident response when you detect an active breach?",
        "options": [
            "A) Eradicate the malware",
            "B) Write a post-mortem report",
            "C) Contain the threat (isolate affected systems)",
            "D) Notify the press",
        ],
        "answer": "c",
        "explanation": (
            "Containment is the immediate priority — stop the bleeding before "
            "you investigate or clean up. Isolate affected systems, block "
            "attacker IPs, and disable compromised accounts FIRST."
        ),
    },
    {
        "q": "An IP address makes 50 HTTP 404 requests to paths like /wp-admin, /phpmyadmin, "
             "and /cgi-bin in under a minute. What is this most likely?",
        "options": [
            "A) A legitimate user browsing the website",
            "B) An automated vulnerability scanner probing for known paths",
            "C) A DDoS attack",
            "D) A DNS poisoning attempt",
        ],
        "answer": "b",
        "explanation": (
            "Rapidly hitting well-known admin paths that return 404 is the "
            "signature of an automated vulnerability scanner (like Nikto, "
            "DirBuster, or a botnet) probing for common web applications."
        ),
    },
    {
        "q": "Why should logs be shipped to a centralized, remote log collector?",
        "options": [
            "A) To save disk space on the original server",
            "B) To comply with GDPR data residency requirements",
            "C) So attackers who compromise a server cannot tamper with or delete the evidence",
            "D) Remote logs are automatically encrypted",
        ],
        "answer": "c",
        "explanation": (
            "If logs only exist on the server, an attacker with root access "
            "can delete or modify them to cover their tracks. Shipping logs "
            "to a separate, append-only system preserves the forensic evidence."
        ),
    },
    {
        "q": "What is 'alert fatigue' and why is it dangerous?",
        "options": [
            "A) When CPU usage is high due to too many monitoring scripts",
            "B) When security staff become desensitized to alerts due to excessive false positives",
            "C) When alert emails fill up the mail server storage",
            "D) When network monitoring causes latency",
        ],
        "answer": "b",
        "explanation": (
            "Alert fatigue occurs when too many low-value or false-positive "
            "alerts cause analysts to ignore or deprioritize all alerts, "
            "including genuine critical threats. Proper threshold tuning "
            "and severity-based routing are the antidote."
        ),
    },
]


# ╔═══════════════════════════════════════════════════════════════════════════╗
# ║  Main entry point                                                        ║
# ╚═══════════════════════════════════════════════════════════════════════════╝

def run(progress):
    """Main entry point called from the menu system."""
    module_key = "module7"
    while True:
        choice = show_menu("Module 7: Log Analysis & Incident Response", [
            ("log_fundamentals",  "Lesson 1: Log Fundamentals"),
            ("parsing_logs",      "Lesson 2: Parsing Logs for Suspicious Activity"),
            ("alerting_scripts",  "Lesson 3: Building Alerting Scripts"),
            ("automating_checks", "Lesson 4: Automating Security Checks"),
            ("quiz",              "Take the Quiz"),
        ])

        if choice == "back":
            return
        if choice == "quit":
            raise SystemExit

        if choice == "log_fundamentals":
            _lesson_log_fundamentals(progress)
        elif choice == "parsing_logs":
            _lesson_parsing_logs(progress)
        elif choice == "alerting_scripts":
            _lesson_alerting_scripts(progress)
        elif choice == "automating_checks":
            _lesson_automating_checks(progress)
        elif choice == "quiz":
            run_quiz(MODULE7_QUIZ, "log_analysis_quiz", module_key, progress)
