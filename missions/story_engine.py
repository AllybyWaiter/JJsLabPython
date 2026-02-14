"""
Story Engine — reusable interactive task types for story-mode missions.

Provides five task types that missions can use:
  - command_task:  user types a command (validated against accepted answers)
  - code_task:     user writes a Python snippet (validated by keywords)
  - puzzle_task:   user solves a puzzle (decode, identify, etc.)
  - choice_task:   pick an approach — different choices award different points
  - quiz_task:     quick inline knowledge check
"""

from __future__ import annotations

import os
import re
import textwrap
import time
import random

from utils.display import (
    C, G, Y, R, M, DIM, BRIGHT, RESET, TERM_WIDTH,
    narrator, terminal_prompt, sub_header, info, success,
    warning, error, hint_text, code_block, press_enter, nice_work,
    timer_header, timer_result, dossier_notification,
)


# ---------------------------------------------------------------------------
# Command task — type a real command
# ---------------------------------------------------------------------------

def command_task(
    prompt_text: str,
    accepted: list[str],
    points: int = 20,
    hints: list[str] | None = None,
    case_sensitive: bool = False,
) -> int:
    """Ask the user to type a command.  Returns points earned."""
    sub_header("COMMAND TASK")
    narrator(prompt_text)
    print()

    hints = hints or []
    hint_idx = 0
    attempts = 0
    max_attempts = 3

    while attempts < max_attempts:
        answer = input(f"  {G}{BRIGHT}root@target:~${RESET} ").strip()
        if not answer:
            continue

        match = _check_answer(answer, accepted, case_sensitive)
        if match:
            success(f"Correct!  +{points} pts")
            print()
            return points

        attempts += 1
        remaining = max_attempts - attempts
        if remaining > 0:
            error(f"Not quite. {remaining} attempt(s) remaining.")
            if hint_idx < len(hints):
                hint_text(hints[hint_idx])
                hint_idx += 1
        else:
            error("Out of attempts.")
            info(f"The expected command was:  {accepted[0]}")
            half = points // 2
            info(f"Partial credit: +{half} pts")
            print()
            return half

    return 0


# ---------------------------------------------------------------------------
# Code task — write a Python snippet
# ---------------------------------------------------------------------------

def code_task(
    prompt_text: str,
    required_keywords: list[str],
    points: int = 25,
    hints: list[str] | None = None,
    example_solution: str = "",
) -> int:
    """Ask the user to write a code snippet.  Returns points earned."""
    sub_header("CODE TASK")
    narrator(prompt_text)
    info("Type your code below (enter a blank line to submit):")
    print()

    hints = hints or []
    hint_idx = 0
    attempts = 0
    max_attempts = 3

    while attempts < max_attempts:
        lines = []
        while True:
            line = input(f"  {G}>>>{RESET} ")
            if line == "":
                break
            lines.append(line)

        code = "\n".join(lines)
        if not code.strip():
            continue

        # Check if required keywords appear in code
        found = [kw for kw in required_keywords if kw.lower() in code.lower()]
        if len(found) >= len(required_keywords):
            success(f"Great code!  +{points} pts")
            print()
            return points

        attempts += 1
        remaining = max_attempts - attempts
        missing = [kw for kw in required_keywords if kw.lower() not in code.lower()]
        if remaining > 0:
            error(f"Missing key elements: {', '.join(missing)}. {remaining} attempt(s) left.")
            if hint_idx < len(hints):
                hint_text(hints[hint_idx])
                hint_idx += 1
        else:
            error("Out of attempts.")
            if example_solution:
                info("Here's one approach:")
                code_block(example_solution, "python")
            half = points // 2
            info(f"Partial credit: +{half} pts")
            print()
            return half

    return 0


# ---------------------------------------------------------------------------
# Puzzle task — decode / identify / answer
# ---------------------------------------------------------------------------

def puzzle_task(
    prompt_text: str,
    accepted: list[str],
    points: int = 20,
    hints: list[str] | None = None,
    case_sensitive: bool = False,
) -> int:
    """Present a puzzle (decode hash, find vuln, read log). Returns points."""
    sub_header("PUZZLE TASK")
    narrator(prompt_text)
    print()

    hints = hints or []
    hint_idx = 0
    attempts = 0
    max_attempts = 3

    while attempts < max_attempts:
        answer = input(f"  {M}{BRIGHT}Answer:{RESET} ").strip()
        if not answer:
            continue

        match = _check_answer(answer, accepted, case_sensitive)
        if match:
            success(f"That's it!  +{points} pts")
            print()
            return points

        attempts += 1
        remaining = max_attempts - attempts
        if remaining > 0:
            error(f"Not quite. {remaining} attempt(s) remaining.")
            if hint_idx < len(hints):
                hint_text(hints[hint_idx])
                hint_idx += 1
        else:
            error("Out of attempts.")
            info(f"The answer was:  {accepted[0]}")
            half = points // 2
            info(f"Partial credit: +{half} pts")
            print()
            return half

    return 0


# ---------------------------------------------------------------------------
# Choice task — pick your approach
# ---------------------------------------------------------------------------

def choice_task(
    prompt_text: str,
    options: list[tuple[str, str, int]],
) -> int:
    """Present a tactical choice.  Returns points based on chosen option.

    options: list of (key_label, description, points_awarded)
    """
    sub_header("TACTICAL CHOICE")
    narrator(prompt_text)
    print()

    for i, (label, desc, _pts) in enumerate(options, 1):
        print(f"  {C}{BRIGHT}{i}.{RESET} {label}")
        wrapped = textwrap.fill(desc, width=TERM_WIDTH - 10)
        for line in wrapped.split("\n"):
            print(f"       {DIM}{line}{RESET}")
    print()

    while True:
        raw = input(f"  {C}  ▶ Your choice: {RESET}").strip()
        try:
            idx = int(raw) - 1
            if 0 <= idx < len(options):
                label, desc, pts = options[idx]
                print()
                if pts == max(o[2] for o in options):
                    success(f"Excellent choice — {label}.  +{pts} pts")
                else:
                    info(f"You chose: {label}.  +{pts} pts")
                print()
                return pts
        except ValueError:
            pass
        error("Pick a number from the list.")


# ---------------------------------------------------------------------------
# Quiz task — inline knowledge check
# ---------------------------------------------------------------------------

def quiz_task(
    question: str,
    options: list[str],
    correct_index: int,
    explanation: str = "",
    points: int = 10,
) -> int:
    """Quick inline quiz question.  Returns points earned."""
    sub_header("KNOWLEDGE CHECK")
    narrator(question)
    print()

    labels = "ABCD"
    for i, opt in enumerate(options):
        print(f"  {C}{labels[i]}.{RESET} {opt}")
    print()

    attempts = 0
    while attempts < 2:
        raw = input(f"  {C}  ▶ Your answer: {RESET}").strip().upper()
        if not raw:
            continue
        idx = labels.find(raw)
        if idx == -1:
            error("Enter A, B, C, or D.")
            continue
        if idx == correct_index:
            success(f"Correct!  +{points} pts")
            if explanation:
                info(explanation)
            print()
            return points
        attempts += 1
        if attempts < 2:
            error("Not quite — try once more.")
        else:
            error(f"The answer was {labels[correct_index]}.")
            if explanation:
                info(explanation)
            half = points // 2
            info(f"Partial credit: +{half} pts")
            print()
            return half

    return 0


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _check_answer(answer: str, accepted: list[str], case_sensitive: bool) -> bool:
    """Check if answer matches any accepted answer (supports regex patterns)."""
    for pattern in accepted:
        if case_sensitive:
            if re.fullmatch(pattern, answer):
                return True
        else:
            if re.fullmatch(pattern, answer, re.IGNORECASE):
                return True
    return False


def stage_intro(stage_num: int, title: str):
    """Print a stage header within a mission."""
    width = TERM_WIDTH
    print()
    print(f"  {Y}{BRIGHT}{'━' * (width - 4)}")
    print(f"   STAGE {stage_num}: {title}")
    print(f"  {'━' * (width - 4)}{RESET}")
    print()


# ---------------------------------------------------------------------------
# Feature 12: Timed Tasks
# ---------------------------------------------------------------------------

def timed_task(task_fn, *args, time_limit: int = 60, bonus: int = 5, **kwargs) -> int:
    """Wrap a task function with a stopwatch. Awards bonus points for speed.

    Returns base points from the task plus bonus if completed within time_limit.
    """
    timer_header(time_limit)
    start = time.time()
    base_points = task_fn(*args, **kwargs)
    elapsed = time.time() - start

    if elapsed <= time_limit:
        success(f"Speed bonus! +{bonus} pts")
        timer_result(elapsed, time_limit, bonus_earned=True)
        return base_points + bonus
    else:
        warning(f"Time's up — {elapsed:.0f}s")
        timer_result(elapsed, time_limit, bonus_earned=False)
        return base_points


# ---------------------------------------------------------------------------
# Feature 13: Random Events
# ---------------------------------------------------------------------------

# Each event: (narration, [(option_label, points), (option_label, points)])
RANDOM_EVENTS: dict[int, list[tuple[str, list[tuple[str, int]]]]] = {
    1: [
        (
            "The sysadmin just logged in to check logs! They might notice "
            "your testing activity. How do you respond?",
            [
                ("Pause and document your authorization letter", 5),
                ("Keep going and hope they don't notice", 0),
            ],
        ),
        (
            "A WAF rule just activated! Your last request was flagged as "
            "suspicious. What's your move?",
            [
                ("Adjust your payload to evade the rule and document it", 5),
                ("Blast through with more aggressive payloads", 0),
            ],
        ),
    ],
    2: [
        (
            "Strange traffic spike detected on port 443! A new burst of "
            "outbound data just started. What do you do?",
            [
                ("Capture the traffic immediately for analysis", 5),
                ("Ignore it — you're focused on the known threat", 0),
            ],
        ),
        (
            "An IDS alert fired! The Snort sensor detected a signature "
            "match on the quarantine VLAN. React?",
            [
                ("Investigate the alert and correlate with your findings", 5),
                ("Dismiss it as a false positive", 0),
            ],
        ),
    ],
    3: [
        (
            "The account lockout policy just kicked in! Your cracking "
            "attempts triggered a 15-minute lockout. What now?",
            [
                ("Switch to offline cracking while you wait", 5),
                ("Wait impatiently and try again in 15 minutes", 0),
            ],
        ),
        (
            "A password hint just leaked in an error message! The login "
            "page returned: 'Hint: favorite pet name'. Use it?",
            [
                ("Add pet names to your wordlist for a targeted attack", 5),
                ("Ignore it and stick with the generic wordlist", 0),
            ],
        ),
    ],
    4: [
        (
            "The target just changed their privacy settings! Several "
            "social media profiles went private. Quick — what do you do?",
            [
                ("Check cached versions and web archives immediately", 5),
                ("Give up on that lead", 0),
            ],
        ),
        (
            "A cached page is about to expire! The Wayback Machine's "
            "snapshot of a key page is from 30 days ago. Act fast.",
            [
                ("Save and archive the cached page before it's gone", 5),
                ("Assume it will still be there later", 0),
            ],
        ),
    ],
    5: [
        (
            "The attacker just spawned a reverse shell! A new outbound "
            "connection appeared on the quarantine VLAN. Respond!",
            [
                ("Log the connection details and block the new C2 IP", 5),
                ("Panic and unplug the server", 0),
            ],
        ),
        (
            "A journalist is calling about the breach! They claim to "
            "have insider information. What do you advise?",
            [
                ("Defer to legal — no comment until official statement", 5),
                ("Give them the technical details off the record", 0),
            ],
        ),
    ],
}


def maybe_random_event(mission_num: int, base_chance: float = 0.3) -> int:
    """Possibly trigger a random event between stages.

    Returns bonus points earned (0 if no event or poor choice).
    """
    if random.random() > base_chance:
        return 0

    events = RANDOM_EVENTS.get(mission_num, [])
    if not events:
        return 0

    event_narration, options = random.choice(events)

    width = TERM_WIDTH
    print()
    print(f"  {R}{BRIGHT}{'━' * (width - 4)}")
    print(f"   ⚡ UNEXPECTED DEVELOPMENT ⚡")
    print(f"  {'━' * (width - 4)}{RESET}")
    print()
    narrator(event_narration)
    print()

    for i, (label, _pts) in enumerate(options, 1):
        print(f"  {C}{BRIGHT}{i}.{RESET} {label}")
    print()

    while True:
        raw = input(f"  {C}  ▶ Quick — your call: {RESET}").strip()
        try:
            idx = int(raw) - 1
            if 0 <= idx < len(options):
                label, pts = options[idx]
                print()
                if pts > 0:
                    success(f"Good call — {label}.  +{pts} bonus pts")
                else:
                    info(f"You chose: {label}.  +{pts} pts")
                print()
                return pts
        except ValueError:
            pass
        error("Pick 1 or 2.")


# ---------------------------------------------------------------------------
# Feature 14: Mission Dossier Files
# ---------------------------------------------------------------------------

MISSION_DOSSIERS: dict[int, str] = {
    1: """\
╔══════════════════════════════════════════════════════════╗
║          PENETRATION TEST AUTHORIZATION LETTER          ║
╚══════════════════════════════════════════════════════════╝

TO:     [Authorized Penetration Tester]
FROM:   Sarah Chen, CISO — NovaTech Industries
DATE:   2025-02-10
RE:     Authorization for Penetration Testing — ProjectHub

This letter authorizes the bearer to conduct penetration
testing against the following systems:

  TARGET SCOPE:
  ─────────────────────────────────────────────────────────
  • Application:  ProjectHub (Internal Project Management)
  • URL:          http://projecthub.novatech.local
  • IP Address:   10.0.1.50
  • Ports:        22, 80, 443, 3306
  • Environment:  Production (after-hours testing window)

  AUTHORIZED ACTIVITIES:
  ─────────────────────────────────────────────────────────
  • Web application vulnerability scanning
  • SQL injection testing on all input fields
  • Cross-site scripting (XSS) testing
  • Authentication and session management testing
  • Authorization bypass testing
  • API endpoint enumeration

  OUT OF SCOPE:
  ─────────────────────────────────────────────────────────
  • Denial of service attacks
  • Social engineering of NovaTech employees
  • Physical security testing
  • Testing of systems outside 10.0.1.50

  EMERGENCY CONTACT:
  ─────────────────────────────────────────────────────────
  Sarah Chen (CISO):  +1-555-0142
  NOC On-Call:        +1-555-0199

Signed: Sarah Chen, CISO — NovaTech Industries
""",

    2: """\
╔══════════════════════════════════════════════════════════╗
║        MERCY GENERAL HOSPITAL — NETWORK TOPOLOGY        ║
╚══════════════════════════════════════════════════════════╝

  NETWORK DIAGRAM (Simplified):
  ─────────────────────────────────────────────────────────

       [INTERNET]
           |
      [FIREWALL] ── 203.x.x.x (Public)
           |
     ┌─────┴──────┐
     |   CORE SW   |
     └─────┬──────┘
      ┌────┼────┬────────┐
      |    |    |        |
   [VLAN10] [VLAN20] [VLAN30] [VLAN40]
   Admin   Medical   PACS    Guest
   10.10.1.x 10.10.2.x 10.10.4.x 10.10.5.x

  FIREWALL RULE EXCERPT:
  ─────────────────────────────────────────────────────────
  RULE 1: ALLOW  TCP  ANY -> 10.10.2.0/24:443  (HTTPS)
  RULE 2: ALLOW  TCP  10.10.4.0/24 -> ANY:443  (PACS Sync)
  RULE 3: DENY   TCP  10.10.5.0/24 -> 10.10.2.0/24 (Guest)
  RULE 4: ALLOW  UDP  ANY -> ANY:53             (DNS)
  ** NOTE: Rule 2 allows PACS subnet outbound on 443 **

  SUSPICIOUS TRAFFIC LOG (IDS Export):
  ─────────────────────────────────────────────────────────
  03:01:22  ALERT  10.10.4.22 -> 185.243.115.42:443
            Bytes: 214,323,712  |  Duration: 47min
            Protocol: TLS 1.2 (self-signed cert)
            Pattern: Fixed 4096-byte bursts every 30s
            Classification: POSSIBLE DATA EXFILTRATION
""",

    3: """\
╔══════════════════════════════════════════════════════════╗
║         DATAVAULT INC. — RECOVERED HASH DUMP            ║
╚══════════════════════════════════════════════════════════╝

  FILE: shadow_dump.txt
  RECOVERED: 2025-02-13 23:14:07 UTC
  SOURCE: Encrypted file server (imaged drive)

  HASH ENTRIES:
  ─────────────────────────────────────────────────────────
  server1_admin:5d41402abc4b2a76b9719d911017c592
  server2_admin:2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
  server3_admin:$2b$12$WApznUPhDubN0oeveSXHp.Rk0rMoTBMRsGJkN4Y7rx6gSecWGnDO6
  legacy_db:5f4dcc3b5aa765d61d8327deb882cf99

═══════════════════════════════════════════════════════════

  DATAVAULT PASSWORD POLICY DOCUMENT (Current):
  ─────────────────────────────────────────────────────────
  Policy ID:     POL-SEC-004 (Rev 2)
  Last Updated:  2024-06-15
  Status:        ** OUTDATED — NEEDS REVISION **

  • Minimum length:          8 characters
  • Complexity:              1 uppercase, 1 number
  • Rotation:                Every 90 days
  • Hash algorithm:          MD5 (!! CRITICAL WEAKNESS !!)
  • Salt:                    None (!! CRITICAL WEAKNESS !!)
  • Account lockout:         Disabled
  • MFA:                     Not implemented

  AUDITOR NOTES:
  This policy fails to meet NIST SP 800-63B guidelines.
  MD5 without salt is trivially crackable. Recommend
  immediate migration to bcrypt or Argon2 with per-user
  salt and cost factor >= 12.
""",

    4: """\
╔══════════════════════════════════════════════════════════╗
║         APEX DYNAMICS — OSINT INVESTIGATION BRIEF       ║
╚══════════════════════════════════════════════════════════╝

  TARGET SOCIAL MEDIA SUMMARY:
  ─────────────────────────────────────────────────────────
  Entity:        Vantage Corp (also: Vantage Holdings Group)
  LinkedIn:      23 employees listed (est. founded 2024)
  Twitter/X:     @VantageCorpIO — 142 followers, low activity
  GitHub:        github.com/vantagecorp — 2 public repos
                 (both empty README-only, created Sep 2025)

  NOTABLE EMPLOYEES (LinkedIn):
  • CEO: "David Kessler" — no prior work history listed
  • CTO: "Elena Markov" — previously at Apex Dynamics (!)
         Left Apex: August 2025
         Joined Vantage: September 2025

  DOMAIN WHOIS RECORD:
  ─────────────────────────────────────────────────────────
  Domain:        vantagecorp.io
  Registrar:     NameSilo, LLC
  Created:       2025-09-14T08:33:17Z
  Updated:       2025-11-02T14:21:05Z
  Registrant:    Vantage Holdings Group
  Country:       PA (Panama)
  Name Servers:  ns1.shadowdns.net, ns2.shadowdns.net

  RELATED DOMAINS (same registrant pattern):
  ─────────────────────────────────────────────────────────
  vantagecorp.io        2025-09-14  NameSilo  Panama
  vantageholdings.io    2025-09-14  NameSilo  Panama
  vantage-data.io       2025-09-15  NameSilo  Panama
  vntgcorp.net          2025-09-15  NameSilo  Panama

  RISK ASSESSMENT: HIGH — Infrastructure pattern matches
  known corporate espionage tradecraft.
""",

    5: """\
╔══════════════════════════════════════════════════════════╗
║       CLOUDSTREAM MEDIA — INCIDENT RESPONSE BRIEF       ║
╚══════════════════════════════════════════════════════════╝

  INCIDENT TIMELINE (Preliminary):
  ─────────────────────────────────────────────────────────
  01:58 UTC  Brute-force attack begins on /admin/login
             Source: 203.0.113.42 (VPS, Eastern Europe)
             847 attempts in 13 minutes
  02:11 UTC  Successful admin login (credentials cracked)
  02:13 UTC  First file upload: cdn_payload.js (trojanized)
  02:14 UTC  CDN config modified — serving malware to users
  02:19 UTC  Payment DB queries: /api/payments/export
  02:47 UTC  SOC Alert #IR-2024-0047 triggered
  02:48 UTC  On-call responder notified

  SOC ALERT DETAILS:
  ─────────────────────────────────────────────────────────
  Alert ID:      SOC-2024-0047
  Severity:      CRITICAL
  Triggered by:  CDN integrity check failure
  Description:   Hash mismatch on 3 CDN JavaScript bundles
                 cdn_payload.js does not match known-good hash
  Affected:      cdn-mgmt.cloudstream.io (10.0.2.15)
                 cdn-edge-01.cloudstream.io (10.0.2.21)
                 payment-db.cloudstream.io (10.0.3.8)

  INITIAL LOG EXCERPT (access.log):
  ─────────────────────────────────────────────────────────
  203.0.113.42 - - [13/Feb:01:58:01] "POST /admin/login" 401
  203.0.113.42 - - [13/Feb:01:58:02] "POST /admin/login" 401
  203.0.113.42 - - [13/Feb:01:58:02] "POST /admin/login" 401
  ... (844 more 401 responses) ...
  203.0.113.42 - - [13/Feb:02:11:14] "POST /admin/login" 200
  203.0.113.42 - - [13/Feb:02:13:01] "POST /admin/upload" 200
  203.0.113.42 - - [13/Feb:02:14:33] "POST /admin/config" 200
  203.0.113.42 - - [13/Feb:02:19:07] "GET /api/payments/export" 200
  203.0.113.42 - - [13/Feb:02:19:44] "GET /api/payments/export" 200

  RESPONSE TEAM:
  ─────────────────────────────────────────────────────────
  IR Lead:       [YOU]
  SOC Analyst:   Priya Mehta (night shift)
  CTO:           David Park
  Legal:         Pending notification
""",
}


def generate_dossier(mission_num: int) -> str:
    """Generate a mission dossier file and return its path."""
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    dossier_dir = os.path.join(project_root, "dossiers")
    os.makedirs(dossier_dir, exist_ok=True)

    filename = f"mission{mission_num}_dossier.txt"
    filepath = os.path.join(dossier_dir, filename)

    content = MISSION_DOSSIERS.get(mission_num, "")
    if content:
        with open(filepath, "w") as f:
            f.write(content)

    dossier_notification(filepath)
    narrator(
        "A classified dossier has been placed in your files. "
        "Review it at any time."
    )

    return filepath
