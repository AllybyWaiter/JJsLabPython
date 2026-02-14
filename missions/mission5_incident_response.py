"""
Mission 5: Code Red -- Incident Response

Story: It's 2:47 AM when your phone rings. CloudStream Media, a mid-size
streaming platform, has been breached. Their CDN is serving malware to users,
customer payment data may be compromised, and the attacker appears to still
be active inside the network. You are the on-call incident responder. You
need to analyze logs, identify the attack vector, contain the threat, and
preserve forensic evidence -- all while the clock is ticking and the
attacker is watching.

Stages:
  1. The Alert -- 2:47 AM        (first response, IR frameworks)
  2. Log Analysis                 (parse logs, identify attacker IP)
  3. Containment                  (firewall rules, containment strategy)
  4. Forensics & Evidence         (disk imaging, chain of custody)
  5. Recovery & Lessons Learned   (post-incident review, disclosure)
"""

from utils.display import (
    clear_screen, narrator, terminal_prompt, mission_briefing,
    mission_complete, code_block, info, sub_header, press_enter,
    C, G, Y, R, DIM, BRIGHT, RESET,
)
from utils.progress import mark_mission_complete
from missions.story_engine import (
    command_task, code_task, puzzle_task, choice_task, quiz_task, stage_intro,
)

MISSION_KEY = "mission5"
MAX_SCORE = 100


def run(progress: dict):
    """Entry point for Mission 5."""
    mission_briefing(
        mission_num=5,
        title="Code Red",
        client="CloudStream Media",
        objective="Respond to an active breach: analyze, contain, and recover",
    )

    score = 0
    score += stage_1_the_alert()
    score += stage_2_log_analysis()
    score += stage_3_containment()
    score += stage_4_forensics()
    score += stage_5_recovery()

    # Cap at max
    score = min(score, MAX_SCORE)

    mission_complete(5, "Code Red", score, MAX_SCORE)

    # Save progress
    mark_mission_complete(progress, MISSION_KEY, score, MAX_SCORE)


# ---------------------------------------------------------------------------
# Stage 1 -- The Alert: 2:47 AM
# ---------------------------------------------------------------------------

def stage_1_the_alert() -> int:
    stage_intro(1, "THE ALERT -- 2:47 AM")
    score = 0

    narrator(
        "Your phone screams you awake at 2:47 AM. The screen reads: "
        "'CRITICAL -- CloudStream SOC -- CALL IMMEDIATELY.' Your heart "
        "is already pounding before you answer. It's Priya Mehta, the "
        "night-shift SOC analyst. Her voice is shaking."
    )
    press_enter()

    narrator(
        "'We have an active breach,' Priya says. 'Our CDN nodes started "
        "serving a trojanized JavaScript payload to users about 40 minutes "
        "ago. Customer complaints are flooding in -- browsers flagging "
        "malware warnings. And there's more. We're seeing unauthorized "
        "database queries against the payments table. The attacker is "
        "still inside. We need you NOW.'"
    )
    press_enter()

    narrator(
        "You throw on clothes and open your laptop. The VPN connects. "
        "You pull up the incident response runbook. The first decision "
        "is critical: what do you do FIRST? Every second the attacker "
        "stays inside, more customer data may be exfiltrated."
    )

    score += choice_task(
        prompt_text=(
            "You've just connected to the CloudStream network. The attacker "
            "is still active. What is your FIRST action?"
        ),
        options=[
            (
                "Document the timeline and assess scope",
                "Start a formal incident log. Record what is known: when "
                "the alert fired, what systems are affected, who has been "
                "notified. Assess the scope before taking action.",
                10,
            ),
            (
                "Immediately pull the plug on all servers",
                "Shut everything down right now to stop the bleeding. "
                "Kill the CDN, kill the database, kill it all.",
                3,
            ),
            (
                "Start deleting the malware files from the CDN",
                "Manually remove the trojanized JavaScript files from "
                "each CDN node to stop the malware distribution.",
                5,
            ),
        ],
    )

    narrator(
        "A seasoned responder always documents first. Pulling the plug "
        "destroys volatile evidence -- memory contents, active connections, "
        "running processes. Deleting files without imaging them first "
        "destroys forensic evidence. The golden rule: DOCUMENT, then ACT."
    )
    press_enter()

    narrator(
        "You open a fresh incident log and start writing:\n\n"
        "  INCIDENT #IR-2024-0047\n"
        "  Time: 02:47 UTC  |  Reporter: Priya Mehta (SOC)\n"
        "  Status: ACTIVE BREACH\n"
        "  Affected: CDN (malware injection), Payment DB (unauthorized queries)\n"
        "  Attacker: STILL PRESENT\n\n"
        "Now you need to think about methodology. Every major IR framework "
        "starts with the same fundamental phases."
    )

    score += quiz_task(
        question=(
            "According to the NIST SP 800-61 Incident Response framework, "
            "what are the four phases of incident response, in order?"
        ),
        options=[
            "Preparation, Detection & Analysis, Containment/Eradication/Recovery, Post-Incident Activity",
            "Detection, Elimination, Restoration, Documentation",
            "Alert, Investigate, Remediate, Close",
            "Identify, Protect, Detect, Respond",
        ],
        correct_index=0,
        explanation=(
            "NIST SP 800-61 defines four phases: (1) Preparation, "
            "(2) Detection & Analysis, (3) Containment, Eradication & Recovery, "
            "and (4) Post-Incident Activity. You are currently in phase 2."
        ),
        points=10,
    )

    return score


# ---------------------------------------------------------------------------
# Stage 2 -- Log Analysis
# ---------------------------------------------------------------------------

def stage_2_log_analysis() -> int:
    stage_intro(2, "LOG ANALYSIS")
    score = 0

    narrator(
        "It's now 3:15 AM. You've established the initial timeline. Now you "
        "need to find the attacker. CloudStream's SIEM has collected thousands "
        "of log entries from the past two hours. Somewhere in those logs is "
        "the attacker's trail -- the IP they came from, the exploit they used, "
        "the lateral movement they performed."
    )
    press_enter()

    narrator(
        "Priya pulls up the raw web server access logs from the CDN management "
        "interface. There are over 50,000 entries in the last hour alone. You "
        "need a script to parse through them and find the suspicious activity. "
        "The log format is standard Apache combined format:\n\n"
        '  203.0.113.42 - - [13/Feb/2024:02:15:33] "POST /admin/upload HTTP/1.1" 200 4512\n'
        '  198.51.100.7 - - [13/Feb/2024:02:15:34] "GET /stream/movie123 HTTP/1.1" 200 82310\n'
        '  203.0.113.42 - - [13/Feb/2024:02:15:35] "POST /admin/config HTTP/1.1" 200 891\n'
        '  10.0.0.5 - - [13/Feb/2024:02:15:36] "GET /healthcheck HTTP/1.1" 200 15\n'
        '  203.0.113.42 - - [13/Feb/2024:02:16:01] "POST /admin/upload HTTP/1.1" 200 7823\n\n'
        "You need to write a Python script to parse a log file and flag lines "
        "that contain suspicious activity -- look for POST requests to admin "
        "endpoints, unusual status codes, or repeated access from the same IP."
    )

    score += code_task(
        prompt_text=(
            "Write a Python script that opens a log file, reads each line, "
            "checks for suspicious entries (e.g., POST to /admin, status 500, "
            "or repeated IPs), and prints the suspicious lines. Use basic "
            "file I/O and string operations."
        ),
        required_keywords=["open", "for", "if", "print"],
        points=10,
        hints=[
            "Use open('access.log') to read the file, then loop through lines with for",
            "Check each line with 'if' statements -- look for keywords like '/admin' or 'POST'",
            "Remember: open the file, loop through lines, check conditions, print matches",
        ],
        example_solution=(
            'with open("access.log") as f:\n'
            '    for line in f:\n'
            '        if "/admin" in line and "POST" in line:\n'
            '            print("[SUSPICIOUS]", line.strip())\n'
            '        if "500" in line or "401" in line:\n'
            '            print("[ERROR]", line.strip())'
        ),
    )

    narrator(
        "Your script tears through the logs. A pattern emerges immediately. "
        "One IP address stands out -- it accounts for 73% of all POST requests "
        "to the /admin endpoint in the past two hours. Here's what your "
        "script flagged:\n\n"
        "  [SUSPICIOUS] 203.0.113.42 - POST /admin/upload     -- 47 times\n"
        "  [SUSPICIOUS] 203.0.113.42 - POST /admin/config     -- 12 times\n"
        "  [SUSPICIOUS] 203.0.113.42 - POST /admin/users      --  3 times\n"
        "  [SUSPICIOUS] 203.0.113.42 - GET  /api/payments/export -- 8 times\n"
        "  [ERROR]      203.0.113.42 - POST /admin/login 401  -- 847 times (!)\n\n"
        "That last line is chilling. 847 failed login attempts followed by "
        "a successful one. The attacker brute-forced their way into the admin "
        "panel, then used the upload functionality to inject the malware "
        "payload into the CDN."
    )
    press_enter()

    narrator(
        "Look at the log summary above carefully. One IP address is responsible "
        "for almost all the malicious activity -- the brute-force attempts, the "
        "admin uploads, the payment data export."
    )

    score += puzzle_task(
        prompt_text=(
            "Based on the log analysis above, what is the attacker's IP address?"
        ),
        accepted=[
            r"203\.0\.113\.42",
        ],
        points=10,
        hints=[
            "Look at which IP appears in every [SUSPICIOUS] and [ERROR] line",
            "The IP starts with 203 and appears 47+12+3+8+847 times",
        ],
        case_sensitive=False,
    )

    narrator(
        "Confirmed: 203.0.113.42 is the attacker. A quick WHOIS lookup shows "
        "the IP belongs to a VPS provider in Eastern Europe -- likely a rented "
        "attack box. You add this to the incident log. The attack timeline "
        "is becoming clear:\n\n"
        "  01:58 UTC - Brute-force attack begins against /admin/login\n"
        "  02:11 UTC - Successful login (credentials cracked)\n"
        "  02:13 UTC - First malicious file uploaded to CDN\n"
        "  02:14 UTC - CDN config modified to serve trojanized JS\n"
        "  02:19 UTC - Payment data export queries begin\n"
        "  02:47 UTC - SOC alert triggered, you are called\n\n"
        "The attacker had 36 minutes of unrestricted access before anyone "
        "noticed. That's 36 minutes of potential data exfiltration."
    )
    press_enter()

    return score


# ---------------------------------------------------------------------------
# Stage 3 -- Containment
# ---------------------------------------------------------------------------

def stage_3_containment() -> int:
    stage_intro(3, "CONTAINMENT")
    score = 0

    narrator(
        "It's 3:42 AM. You know who the attacker is and how they got in. "
        "Now you need to STOP them. The attacker's session may still be "
        "active. Every minute you wait, more data could be leaving the "
        "building. Your hands are steady but your pulse is racing."
    )
    press_enter()

    narrator(
        "First priority: block the attacker's IP address at the network "
        "perimeter. CloudStream runs iptables on their gateway firewall. "
        "You need to add a rule to DROP all traffic from the attacker's IP "
        "address (203.0.113.42) on the INPUT chain."
    )

    score += command_task(
        prompt_text=(
            "Write the iptables command to block ALL incoming traffic from "
            "the attacker's IP address 203.0.113.42 on the INPUT chain."
        ),
        accepted=[
            r"iptables\s+-A\s+INPUT\s+-s\s+203\.0\.113\.42\s+-j\s+DROP",
            r"iptables\s+-I\s+INPUT\s+-s\s+203\.0\.113\.42\s+-j\s+DROP",
            r"iptables\s+-A\s+INPUT\s+-s\s+203\.0\.113\.42(/32)?\s+-j\s+DROP",
            r"iptables\s+-I\s+INPUT\s+1?\s*-s\s+203\.0\.113\.42\s+-j\s+DROP",
        ],
        points=10,
        hints=[
            "Use iptables -A INPUT to append a rule to the INPUT chain",
            "The -s flag specifies source IP, -j DROP drops the packets",
        ],
    )

    narrator(
        "The firewall rule is in place. The attacker's connection drops "
        "immediately. But blocking one IP isn't enough -- they could pivot "
        "to a different source. You need a broader containment strategy."
    )
    press_enter()

    narrator(
        "The CloudStream CTO, David Park, is now on the call. He's panicked. "
        "'Should we just shut everything down?' he asks. Priya wants to keep "
        "systems running to monitor the attacker. You need to make the call. "
        "This is the hardest decision in incident response -- how aggressively "
        "do you contain?"
    )

    score += choice_task(
        prompt_text=(
            "The attacker's IP is blocked, but they may have planted backdoors "
            "or have other access paths. What is your containment strategy?"
        ),
        options=[
            (
                "Isolate compromised systems but keep them running",
                "Move the affected CDN servers and the payment database server "
                "into an isolated VLAN with no internet access but keep them "
                "powered on. This preserves volatile memory evidence while "
                "stopping further data exfiltration.",
                10,
            ),
            (
                "Full network shutdown -- pull the plug on everything",
                "Shut down all CloudStream servers immediately. Total "
                "containment. Nothing gets in or out. Customers lose access "
                "to the streaming service, but the bleeding stops.",
                3,
            ),
            (
                "Keep everything running and just monitor",
                "Leave all systems online but increase monitoring. Watch "
                "what the attacker does next to gather more intelligence "
                "about their methods and objectives.",
                5,
            ),
        ],
    )

    narrator(
        "Isolating compromised systems into a quarantine VLAN is the textbook "
        "response. You preserve volatile evidence (RAM, active connections, "
        "running processes) while cutting off the attacker's ability to "
        "exfiltrate data or spread laterally. A full shutdown destroys "
        "volatile evidence. Passive monitoring risks further damage."
    )
    press_enter()

    narrator(
        "You instruct the network team to move the three compromised servers "
        "into VLAN 999 (the quarantine network). Within minutes, the CDN "
        "management server, CDN edge node, and payment database are isolated. "
        "The streaming service is temporarily offline, but the attacker is "
        "locked out and the evidence is preserved."
    )
    press_enter()

    return score


# ---------------------------------------------------------------------------
# Stage 4 -- Forensics & Evidence Preservation
# ---------------------------------------------------------------------------

def stage_4_forensics() -> int:
    stage_intro(4, "FORENSICS & EVIDENCE")
    score = 0

    narrator(
        "It's 4:30 AM. The threat is contained. Now begins the painstaking "
        "work of forensic evidence collection. If CloudStream wants to pursue "
        "legal action -- or if regulators come knocking -- you need evidence "
        "that will hold up in court. Every step must be documented. Every "
        "piece of evidence must be handled with care."
    )
    press_enter()

    narrator(
        "The first forensic task: create a bit-for-bit disk image of the "
        "compromised CDN management server's drive. This captures everything "
        "-- deleted files, slack space, unallocated clusters. The original "
        "drive is /dev/sda and you need to image it to a file called "
        "cdn_server.img. The standard tool for forensic disk imaging is dd."
    )

    score += command_task(
        prompt_text=(
            "Write the dd command to create a forensic image of /dev/sda "
            "and save it to cdn_server.img. Use a block size of 4K for "
            "efficiency."
        ),
        accepted=[
            r"dd\s+if=/dev/sda\s+of=cdn_server\.img\s+bs=4[Kk].*",
            r"dd\s+if=/dev/sda\s+of=cdn_server\.img\s+bs=4096.*",
            r"dd\s+bs=4[Kk]\s+if=/dev/sda\s+of=cdn_server\.img.*",
            r"dd\s+if=/dev/sda\s+of=cdn_server\.img\s+bs=4[Kk]",
        ],
        points=10,
        hints=[
            "dd uses if= for input file and of= for output file",
            "dd if=/dev/sda of=cdn_server.img bs=4K",
        ],
    )

    narrator(
        "The disk image is being created. While it copies, you need to "
        "generate a cryptographic hash of the image. This hash proves the "
        "image hasn't been tampered with. If the hash of the image matches "
        "when verified later, it confirms evidence integrity. You'll use "
        "SHA-256 because it's the standard for forensic evidence."
    )

    score += command_task(
        prompt_text=(
            "Generate a SHA-256 hash of the forensic image file "
            "cdn_server.img to verify its integrity."
        ),
        accepted=[
            r"sha256sum\s+cdn_server\.img",
            r"shasum\s+-a\s*256\s+cdn_server\.img",
            r"openssl\s+dgst\s+-sha256\s+cdn_server\.img",
        ],
        points=5,
        hints=[
            "The sha256sum command computes SHA-256 hashes",
            "sha256sum cdn_server.img",
        ],
    )

    narrator(
        "The hash is computed:\n\n"
        "  SHA-256: a7f3b8c1d9e2f40561...(truncated)...4e8c2a1\n"
        "  File: cdn_server.img\n\n"
        "You write this hash in the evidence log, sign it, and note the "
        "date and time. This hash is your proof that the disk image is an "
        "exact, unmodified copy of the original drive."
    )
    press_enter()

    narrator(
        "As you catalog the evidence, David Park asks about handling "
        "procedures. He wants to make sure nothing gets thrown out in court. "
        "This is where chain of custody becomes critical."
    )

    score += quiz_task(
        question=(
            "What is 'chain of custody' in digital forensics, and why "
            "does it matter?"
        ),
        options=[
            "A blockchain-based system for storing evidence securely",
            "A documented trail showing who collected, handled, transferred, "
            "and stored each piece of evidence, ensuring it was not tampered with",
            "The process of encrypting evidence so only authorized personnel can view it",
            "A legal requirement to store evidence on government servers",
        ],
        correct_index=1,
        explanation=(
            "Chain of custody is the documented, unbroken trail of accountability "
            "that ensures evidence integrity. Every person who handles evidence is "
            "logged with dates and times. Breaks in the chain can render evidence "
            "inadmissible in court."
        ),
        points=5,
    )

    narrator(
        "You complete the evidence log:\n\n"
        "  EVIDENCE LOG -- IR-2024-0047\n"
        "  -----------------------------------------------\n"
        "  Item 1: Disk image (cdn_server.img)\n"
        "    Collected by: [Your Name], 04:45 UTC\n"
        "    SHA-256: a7f3b8c1d9e2f40561...4e8c2a1\n"
        "    Storage: Evidence locker, encrypted USB drive\n\n"
        "  Item 2: RAM dump (cdn_server_mem.raw)\n"
        "    Collected by: [Your Name], 04:52 UTC\n"
        "    SHA-256: 3b9c7a2e8f1d05463...7c1e9b3\n\n"
        "  Item 3: Firewall logs (gateway_fw.log)\n"
        "    Collected by: Priya Mehta, 04:55 UTC\n"
        "    SHA-256: 8d2e1f4a6b9c03571...2a5f8d7\n\n"
        "Every piece of evidence is hashed, signed, and stored. The "
        "forensic trail is airtight."
    )
    press_enter()

    return score


# ---------------------------------------------------------------------------
# Stage 5 -- Recovery & Lessons Learned
# ---------------------------------------------------------------------------

def stage_5_recovery() -> int:
    stage_intro(5, "RECOVERY & LESSONS LEARNED")
    score = 0

    narrator(
        "It's 6:15 AM. The sun is coming up, and the worst is over. The "
        "attacker is locked out, evidence is preserved, and the compromised "
        "servers are isolated. Now comes recovery: getting CloudStream back "
        "online safely, and making sure this never happens again."
    )
    press_enter()

    narrator(
        "The team has rebuilt the CDN nodes from known-good images, rotated "
        "every credential in the environment, patched the admin panel to "
        "require multi-factor authentication, and deployed rate limiting on "
        "the login endpoint. The streaming service is back online at 7:02 AM "
        "-- four hours and fifteen minutes of total downtime."
    )
    press_enter()

    narrator(
        "David Park calls an emergency all-hands meeting for 9 AM. Before "
        "that, you need to prepare the post-incident review. The hardest "
        "question: what should CloudStream have done differently?"
    )

    score += quiz_task(
        question=(
            "The attacker brute-forced 847 login attempts before succeeding. "
            "Which control would have MOST effectively prevented this attack?"
        ),
        options=[
            "A Web Application Firewall (WAF) to block SQL injection",
            "Account lockout after a small number of failed attempts, combined with MFA",
            "Switching from HTTP to HTTPS for the admin panel",
            "Requiring longer passwords (minimum 20 characters)",
        ],
        correct_index=1,
        explanation=(
            "Account lockout policies (e.g., lock after 5 failed attempts) combined "
            "with multi-factor authentication would have stopped the brute-force "
            "attack cold. 847 attempts should never have been possible. HTTPS and "
            "WAF are important but don't address brute-force. Password length alone "
            "doesn't stop automated attacks."
        ),
        points=10,
    )

    narrator(
        "One final decision remains. CloudStream has 2.3 million users. "
        "The attacker exported data from the payments table. You don't yet "
        "know how much data was taken, but the export queries hit records "
        "containing customer names and the last four digits of credit cards. "
        "No full card numbers, but PII was accessed. David turns to you: "
        "'Do we have to tell anyone about this?'"
    )

    score += choice_task(
        prompt_text=(
            "Customer PII was accessed by the attacker. CloudStream operates "
            "in the US and EU. What do you recommend regarding disclosure?"
        ),
        options=[
            (
                "Full transparent disclosure to all affected users and regulators",
                "Immediately notify all potentially affected customers, file reports "
                "with relevant regulators (FTC, state AGs, EU DPAs under GDPR's "
                "72-hour rule), and publish a public incident report. Transparency "
                "builds trust and is legally required in most jurisdictions.",
                10,
            ),
            (
                "Wait until the full investigation is complete before disclosing",
                "Hold off on disclosure until you know exactly what data was taken. "
                "No point in alarming customers unnecessarily. Notify regulators "
                "only if required after the investigation concludes.",
                3,
            ),
            (
                "Only notify regulators, not customers",
                "File the required regulatory reports but do not notify customers "
                "directly. The data exposed was limited (names and last-four of "
                "cards), so the risk to customers is low.",
                5,
            ),
        ],
    )

    narrator(
        "Under GDPR, breaches involving personal data must be reported to "
        "the supervisory authority within 72 hours. Most US states also have "
        "mandatory breach notification laws. Delaying disclosure can result "
        "in massive fines and destroyed customer trust. The right move is "
        "always transparent, timely disclosure with clear guidance for "
        "affected users."
    )
    press_enter()

    narrator(
        "You draft the incident report and hand it to David. The key "
        "recommendations are clear:\n\n"
        "  1. Implement MFA on ALL admin interfaces immediately\n"
        "  2. Deploy account lockout and rate limiting on login endpoints\n"
        "  3. Segment the network -- CDN management should never share a\n"
        "     VLAN with the payment database\n"
        "  4. Implement real-time alerting for brute-force patterns\n"
        "  5. Conduct quarterly incident response drills\n"
        "  6. Encrypt PII at rest and in transit with proper key management\n\n"
        "David shakes your hand. 'I won't pretend this was a good night,' "
        "he says. 'But because of you, we caught it in hours instead of "
        "weeks. The evidence is preserved, the customers will be notified, "
        "and we know exactly how to make sure this doesn't happen again.'"
    )
    press_enter()

    narrator(
        "You close your laptop at 9:47 AM -- exactly seven hours after the "
        "first call. Seven hours of adrenaline, critical thinking, and "
        "methodical work. This is incident response: the unglamorous, "
        "essential discipline that separates a bad day from a catastrophe.\n\n"
        "You did well, responder. Get some sleep."
    )
    press_enter()

    return score
