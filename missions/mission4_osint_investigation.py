"""
Mission 4: Ghost Protocol — OSINT Investigation

Story: Apex Dynamics suspects a competitor, Vantage Corp, is stealing their
trade secrets. An anonymous source sent a cryptic email packed with encoded
clues. You have been hired to investigate using open-source intelligence
techniques — social media analysis, metadata extraction, domain
reconnaissance, and digital forensics — to trace the leak back to its origin
and build an evidence package that will hold up under legal scrutiny.

Stages:
  1. The Anonymous Tip      — decode the email, choose your investigation path
  2. Digital Footprint      — WHOIS / DNS lookups, OSINT ethics
  3. Domain Recon           — DNS enumeration, suspicious registration patterns
  4. Metadata Analysis      — EXIF extraction script, GPS coordinate puzzle
  5. The Reveal & Debrief   — present findings, OSINT legality review
"""

import re

from utils.display import (
    clear_screen, narrator, terminal_prompt, mission_briefing,
    mission_complete, code_block, info, success, sub_header, press_enter,
    C, G, Y, R, M, DIM, BRIGHT, RESET,
)
from utils.progress import mark_mission_complete
from missions.story_engine import (
    command_task, code_task, puzzle_task, choice_task, quiz_task, stage_intro,
    maybe_random_event, generate_dossier,
)
from missions.epilogues import show_epilogue

MISSION_KEY = "mission4"
MAX_SCORE = 100


def run(progress: dict):
    """Entry point for Mission 4."""
    mission_briefing(
        mission_num=4,
        title="Ghost Protocol",
        client="Apex Dynamics",
        objective=(
            "Investigate suspected corporate espionage using OSINT techniques"
        ),
    )

    dossier_path = generate_dossier(4)

    score = 0
    score += stage_1_anonymous_tip()
    score += maybe_random_event(4)
    score += stage_2_digital_footprint()
    score += _easter_egg_nameserver(progress)
    score += maybe_random_event(4)
    score += stage_3_domain_recon()
    score += maybe_random_event(4)
    score += stage_4_metadata_analysis()
    score += maybe_random_event(4)
    score += stage_5_reveal_and_debrief()

    mission_complete(4, "Ghost Protocol", score, MAX_SCORE)
    show_epilogue(4, score, MAX_SCORE)
    mark_mission_complete(progress, MISSION_KEY, score, MAX_SCORE)


# ---------------------------------------------------------------------------
# Stage 1 — The Anonymous Tip
# ---------------------------------------------------------------------------

def stage_1_anonymous_tip() -> int:
    stage_intro(1, "THE ANONYMOUS TIP")
    score = 0

    narrator(
        "It is 11:47 PM when the encrypted email arrives. You are sitting in "
        "your home office, the glow of three monitors casting long shadows on "
        "the wall. The sender field reads 'GHOST-7X' — no domain, no trace. "
        "The subject line is blank. The body contains a single line of text "
        "that looks like gibberish to the untrained eye."
    )
    press_enter()

    narrator(
        "You open the email and see the following encoded string:\n\n"
        f"  {C}{BRIGHT}VmFudGFnZUNvcnAtTGVha1NvdXJjZQ=={RESET}\n\n"
        "You recognize the character set immediately — A-Z, a-z, 0-9, plus, "
        "slash, and the trailing equals sign for padding. This is Base64 "
        "encoding. Whoever sent this wanted to keep the message just opaque "
        "enough to slip past automated scanners, but simple enough for an "
        "investigator to decode."
    )

    score += puzzle_task(
        prompt_text=(
            "Decode the Base64 string: VmFudGFnZUNvcnAtTGVha1NvdXJjZQ==\n"
            "What is the hidden message?"
        ),
        accepted=[
            r"VantageCorp-LeakSource",
            r"vantagecorp-leaksource",
        ],
        points=10,
        hints=[
            "Use the base64 module in Python: base64.b64decode(encoded).decode()",
            "Or on the command line: echo 'VmFudGFnZUNvcnAtTGVha1NvdXJjZQ==' | base64 -d",
        ],
        case_sensitive=False,
    )

    narrator(
        "'VantageCorp-LeakSource.' The anonymous tipster is pointing straight "
        "at Vantage Corp — Apex Dynamics' biggest competitor. The name alone "
        "is not proof, but it is a thread worth pulling. Before you dive "
        "deeper, you need to decide your initial approach. Every good OSINT "
        "investigation begins with a strategy."
    )
    press_enter()

    narrator(
        "Your client, Apex Dynamics, has given you authorization to use "
        "publicly available information only. No hacking, no social "
        "engineering, no accessing private systems. The rules of engagement "
        "are clear: open-source intelligence, nothing more."
    )

    score += choice_task(
        prompt_text=(
            "How do you begin your investigation into VantageCorp?"
        ),
        options=[
            (
                "Passive reconnaissance first",
                "Start with public records, WHOIS data, DNS lookups, and cached "
                "web pages. Leave zero digital footprint on the target.",
                5,
            ),
            (
                "Social media deep dive",
                "Search LinkedIn, Twitter/X, and GitHub for VantageCorp employees "
                "who recently joined from Apex Dynamics.",
                3,
            ),
            (
                "Direct outreach",
                "Email VantageCorp HR pretending to be a recruiter to ask about "
                "new hires from Apex Dynamics.",
                1,
            ),
        ],
    )

    narrator(
        "Smart. Passive reconnaissance is the gold standard for OSINT — you "
        "gather intelligence without the target ever knowing they are being "
        "investigated. Every WHOIS lookup, every DNS query, every cached page "
        "is public data. No laws broken, no alerts triggered."
    )
    press_enter()

    return score


# ---------------------------------------------------------------------------
# Stage 2 — Digital Footprint
# ---------------------------------------------------------------------------

def stage_2_digital_footprint() -> int:
    stage_intro(2, "DIGITAL FOOTPRINT")
    score = 0

    narrator(
        "You pull up a terminal. The first step in any domain investigation "
        "is a WHOIS lookup — the public registration record for a domain "
        "name. It can reveal the registrant's name, organization, email, "
        "registration date, and the nameservers handling the domain's DNS."
    )
    press_enter()

    narrator(
        "Your target is the domain 'vantagecorp.io'. The anonymous tip "
        "suggested this is where the stolen data is being funneled. A WHOIS "
        "query will tell you who registered it and when."
    )

    score += command_task(
        prompt_text="Run a WHOIS lookup on the domain vantagecorp.io.",
        accepted=[
            r"whois\s+vantagecorp\.io",
            r"whois\s+vantagecorp\.io\s*\|.*",
            r"whois\s+-h\s+\S+\s+vantagecorp\.io",
        ],
        points=10,
        hints=[
            "The whois command takes a domain name as an argument",
            "whois vantagecorp.io",
        ],
    )

    narrator(
        "The WHOIS results come back:\n\n"
        f"  {DIM}Domain Name: vantagecorp.io{RESET}\n"
        f"  {DIM}Registry Domain ID: D503300-LRMS{RESET}\n"
        f"  {DIM}Registrar: NameSilo, LLC{RESET}\n"
        f"  {DIM}Created Date: 2025-09-14T08:33:17Z{RESET}\n"
        f"  {DIM}Updated Date: 2025-11-02T14:21:05Z{RESET}\n"
        f"  {DIM}Registrant Organization: Vantage Holdings Group{RESET}\n"
        f"  {DIM}Registrant Country: PA (Panama){RESET}\n"
        f"  {DIM}Name Server: ns1.shadowdns.net{RESET}\n"
        f"  {DIM}Name Server: ns2.shadowdns.net{RESET}\n\n"
        "Interesting. The domain was registered just five months ago, the "
        "registrant is a shell company in Panama, and the nameservers belong "
        "to 'shadowdns.net' — a privacy-focused DNS provider often used to "
        "obscure domain ownership. Now you need to look at the DNS records "
        "themselves."
    )
    press_enter()

    narrator(
        "Next, use the 'dig' command to query the DNS records for "
        "vantagecorp.io. A simple A record query will reveal the IP address "
        "the domain points to, and a look at the MX records will show you "
        "where their email is handled."
    )

    score += command_task(
        prompt_text="Use dig to query ALL DNS record types for vantagecorp.io.",
        accepted=[
            r"dig\s+vantagecorp\.io\s+ANY",
            r"dig\s+ANY\s+vantagecorp\.io",
            r"dig\s+vantagecorp\.io\s+any",
            r"dig\s+@\S+\s+vantagecorp\.io\s+ANY",
            r"dig\s+vantagecorp\.io\s+\+noall\s+\+answer",
        ],
        points=10,
        hints=[
            "The 'ANY' query type requests all record types at once",
            "dig vantagecorp.io ANY",
        ],
    )

    narrator(
        "The DNS results reveal several records:\n\n"
        f"  {DIM}vantagecorp.io.    A      185.199.108.42{RESET}\n"
        f"  {DIM}vantagecorp.io.    MX     mail.protonmail.ch{RESET}\n"
        f"  {DIM}vantagecorp.io.    TXT    v=spf1 include:_spf.protonmail.ch ~all{RESET}\n"
        f"  {DIM}vantagecorp.io.    NS     ns1.shadowdns.net{RESET}\n"
        f"  {DIM}vantagecorp.io.    NS     ns2.shadowdns.net{RESET}\n\n"
        "ProtonMail for email — encrypted, privacy-first. The IP address "
        "185.199.108.42 belongs to a cloud VPS provider. Whoever set this up "
        "was careful about hiding their tracks."
    )
    press_enter()

    narrator(
        "Before you go further, there is an important ethical question to "
        "consider. OSINT is powerful, but it operates within boundaries. "
        "Understanding where the line is drawn separates a professional "
        "investigator from someone who is breaking the law."
    )

    score += quiz_task(
        question=(
            "Which of the following activities crosses the legal line from "
            "OSINT into unauthorized access?"
        ),
        options=[
            "Searching public court records for a company's lawsuits",
            "Using Shodan to find internet-facing devices on a target's IP range",
            "Guessing an employee's email password and logging into their account",
            "Reading a company's public SEC filings and press releases",
        ],
        correct_index=2,
        explanation=(
            "Accessing someone's account without authorization is a criminal "
            "offense under the CFAA (Computer Fraud and Abuse Act) and similar "
            "laws worldwide, regardless of how you obtained the password. "
            "OSINT is strictly limited to publicly available information."
        ),
        points=10,
    )

    return score


# ---------------------------------------------------------------------------
# Stage 3 — Domain Recon
# ---------------------------------------------------------------------------

def stage_3_domain_recon() -> int:
    stage_intro(3, "DOMAIN RECON")
    score = 0

    narrator(
        "Your WHOIS and DNS lookups painted a clear picture: vantagecorp.io "
        "is designed for anonymity. But domains rarely exist in isolation. "
        "Attackers and shell companies often register clusters of related "
        "domains. Time to enumerate and see what else is connected."
    )
    press_enter()

    narrator(
        "The 'host' command is a simple but effective DNS lookup utility. "
        "You can use it to resolve a domain to its IP address and then "
        "investigate what other domains share that same IP. This technique "
        "is called reverse DNS enumeration."
    )

    score += command_task(
        prompt_text=(
            "Use the 'host' command to resolve vantagecorp.io to its IP address."
        ),
        accepted=[
            r"host\s+vantagecorp\.io",
            r"host\s+-t\s+A\s+vantagecorp\.io",
            r"host\s+-t\s+a\s+vantagecorp\.io",
            r"host\s+vantagecorp\.io\s+\S*",
        ],
        points=5,
        hints=[
            "The host command is straightforward: host <domain>",
            "host vantagecorp.io",
        ],
    )

    narrator(
        "The host command confirms:\n\n"
        f"  {DIM}vantagecorp.io has address 185.199.108.42{RESET}\n\n"
        "Now you check what other domains are hosted on that same IP using "
        "reverse DNS. You also decide to run a subdomain brute-force scan. "
        "Tools like 'dnsrecon' can automate the process of discovering "
        "subdomains by trying thousands of common names."
    )

    score += command_task(
        prompt_text=(
            "Run dnsrecon in standard enumeration mode (-t std) against "
            "vantagecorp.io to discover subdomains and DNS records."
        ),
        accepted=[
            r"dnsrecon\s+-d\s+vantagecorp\.io.*",
            r"dnsrecon\s+.*-d\s+vantagecorp\.io.*-t\s+std.*",
            r"dnsrecon\s+-t\s+std\s+-d\s+vantagecorp\.io.*",
        ],
        points=5,
        hints=[
            "dnsrecon uses -d to specify the domain and -t for the scan type",
            "dnsrecon -d vantagecorp.io -t std",
        ],
    )

    narrator(
        "The DNS enumeration uncovers three subdomains:\n\n"
        f"  {DIM}uploads.vantagecorp.io   -> 185.199.108.42{RESET}\n"
        f"  {DIM}dev.vantagecorp.io       -> 185.199.108.42{RESET}\n"
        f"  {DIM}staging.vantagecorp.io   -> 185.199.108.43{RESET}\n\n"
        "An 'uploads' subdomain is particularly suspicious — it suggests a "
        "file transfer mechanism. The 'dev' and 'staging' subdomains indicate "
        "an active development environment. But there is something else in "
        "the WHOIS records that caught your eye."
    )
    press_enter()

    narrator(
        "You run WHOIS on several related domains and notice a pattern:\n\n"
        f"  {DIM}vantagecorp.io     — Registered 2025-09-14 — NameSilo — Panama{RESET}\n"
        f"  {DIM}vantageholdings.io — Registered 2025-09-14 — NameSilo — Panama{RESET}\n"
        f"  {DIM}vantage-data.io    — Registered 2025-09-15 — NameSilo — Panama{RESET}\n"
        f"  {DIM}vntgcorp.net       — Registered 2025-09-15 — NameSilo — Panama{RESET}\n\n"
        "Four domains, all registered within 24 hours of each other, all "
        "through the same registrar, all using a Panama shell company. This "
        "is a domain cluster — a common pattern in corporate espionage "
        "infrastructure."
    )

    score += puzzle_task(
        prompt_text=(
            "Based on the WHOIS records above, what specific pattern connects "
            "all four domains? Identify the three key attributes they share.\n"
            "(Format your answer as: same registrar, same date, same country — "
            "or describe the pattern in your own words.)"
        ),
        accepted=[
            r".*same\s+(registrar|date|country).*same\s+(registrar|date|country).*same\s+(registrar|date|country).*",
            r".*namesilo.*panama.*2025.*",
            r".*panama.*namesilo.*2025.*",
            r".*registrar.*date.*country.*",
            r".*registrar.*country.*date.*",
            r".*same registrar.*same date.*same country.*",
            r".*registered.*same\s+(day|time|date).*same\s+(registrar|provider).*same\s+(country|location).*",
            r".*domain\s+cluster.*",
        ],
        points=10,
        hints=[
            "Look at the registrar, the dates, and the registrant country across all four",
            "They share the same registrar (NameSilo), same registration timeframe, and same country (Panama)",
        ],
        case_sensitive=False,
    )

    narrator(
        "Exactly. All four domains share the same registrar, the same "
        "registration window, and the same shell-company country. In OSINT, "
        "we call this 'infrastructure fingerprinting.' The adversary reused "
        "the same operational setup for all their domains, creating a pattern "
        "that links them together. This is a critical finding for the "
        "investigation."
    )
    press_enter()

    return score


# ---------------------------------------------------------------------------
# Stage 4 — Metadata Analysis
# ---------------------------------------------------------------------------

def stage_4_metadata_analysis() -> int:
    stage_intro(4, "METADATA ANALYSIS")
    score = 0

    narrator(
        "While examining the uploads.vantagecorp.io subdomain through cached "
        "pages on the Wayback Machine, you find something interesting: a "
        "directory listing containing several image files. These appear to be "
        "photos of proprietary circuit board designs — the exact trade secrets "
        "Apex Dynamics reported stolen."
    )
    press_enter()

    narrator(
        "Digital images carry hidden data called EXIF metadata — Exchangeable "
        "Image File Format. When a photo is taken with a smartphone or digital "
        "camera, the device embeds information into the file: camera model, "
        "timestamp, GPS coordinates, software used, and sometimes even the "
        "device owner's name. Most people never strip this metadata before "
        "uploading files. If the leaker took photos of the circuit boards, "
        "their device metadata could reveal exactly who they are and where "
        "they were standing."
    )
    press_enter()

    narrator(
        "Write a Python script that uses the Pillow library to extract EXIF "
        "metadata from an image file. Your script should open the image, "
        "read its EXIF data, and print out the tag names and their values. "
        "This is one of the most practical OSINT skills you can have."
    )

    score += code_task(
        prompt_text=(
            "Write a Python script to extract EXIF metadata from an image.\n"
            "Your code should:\n"
            "  1. Import the PIL/Pillow library\n"
            "  2. Open an image file\n"
            "  3. Extract EXIF data using _getexif() or getexif()\n"
            "  4. Use ExifTags.TAGS to convert numeric tag IDs to readable names\n"
            "  5. Print or iterate over the tag name-value pairs"
        ),
        required_keywords=[
            "PIL", "Image", "open", "exif", "TAGS",
        ],
        points=15,
        hints=[
            "from PIL import Image; from PIL.ExifTags import TAGS",
            "Use img.getexif() or img._getexif() to get the raw EXIF dictionary",
            "Loop with: for tag_id, value in exif_data.items()",
        ],
        example_solution=(
            "from PIL import Image\n"
            "from PIL.ExifTags import TAGS\n"
            "\n"
            "img = Image.open('circuit_board_01.jpg')\n"
            "exif_data = img.getexif()\n"
            "\n"
            "for tag_id, value in exif_data.items():\n"
            "    tag_name = TAGS.get(tag_id, tag_id)\n"
            "    print(f'{tag_name}: {value}')"
        ),
    )

    narrator(
        "Excellent. You run your script against the leaked images and the "
        "EXIF data is a goldmine:\n\n"
        f"  {DIM}Make: Apple{RESET}\n"
        f"  {DIM}Model: iPhone 15 Pro{RESET}\n"
        f"  {DIM}DateTime: 2025:10:03 22:14:37{RESET}\n"
        f"  {DIM}Software: 17.0.3{RESET}\n"
        f"  {DIM}GPSLatitude: (37, 23, 48.12){RESET}\n"
        f"  {DIM}GPSLatitudeRef: N{RESET}\n"
        f"  {DIM}GPSLongitude: (122, 5, 12.44){RESET}\n"
        f"  {DIM}GPSLongitudeRef: W{RESET}\n\n"
        "The photos were taken with an iPhone 15 Pro on October 3, 2025, at "
        "10:14 PM. And there are GPS coordinates embedded in the image. The "
        "leaker forgot to disable location services."
    )
    press_enter()

    narrator(
        "The GPS coordinates in EXIF are stored in degrees, minutes, and "
        "seconds (DMS) format. To locate the position on a map, you need "
        "to convert them to decimal degrees.\n\n"
        "  Latitude:  37 degrees, 23 minutes, 48.12 seconds N\n"
        "  Longitude: 122 degrees, 5 minutes, 12.44 seconds W\n\n"
        "The formula is:  decimal = degrees + (minutes / 60) + (seconds / 3600)\n"
        "For West longitude, the result is negative.\n\n"
        "Calculate the decimal coordinates and identify where this photo was "
        "taken. Round each coordinate to two decimal places."
    )

    score += puzzle_task(
        prompt_text=(
            "Convert the GPS coordinates to decimal degrees.\n"
            "  Lat: 37 deg 23 min 48.12 sec N\n"
            "  Lon: 122 deg 5 min 12.44 sec W\n\n"
            "What are the decimal coordinates? (Format: lat, lon — e.g., 37.40, -122.09)"
        ),
        accepted=[
            r"37\.40,?\s*-122\.09",
            r"37\.40\s*,?\s*-\s*122\.09",
            r"37\.397.*,?\s*-122\.087.*",
        ],
        points=10,
        hints=[
            "Latitude: 37 + (23/60) + (48.12/3600) = 37 + 0.3833 + 0.01337 = 37.3967 -> 37.40",
            "Longitude: -(122 + (5/60) + (12.44/3600)) = -(122 + 0.0833 + 0.003456) = -122.0868 -> -122.09",
        ],
        case_sensitive=False,
    )

    narrator(
        "37.40, -122.09 — that is Mountain View, California. Right in the "
        "heart of Silicon Valley. And here is the critical detail: Apex "
        "Dynamics' R&D lab is located at 455 Innovation Drive, Mountain View. "
        "The GPS coordinates from the leaked photos place the photographer "
        "inside the building. Someone with physical access to the R&D lab "
        "took these photos with their personal iPhone and uploaded them to "
        "VantageCorp's infrastructure."
    )
    press_enter()

    return score


# ---------------------------------------------------------------------------
# Stage 5 — The Reveal & Debrief
# ---------------------------------------------------------------------------

def stage_5_reveal_and_debrief() -> int:
    stage_intro(5, "THE REVEAL & DEBRIEF")
    score = 0

    narrator(
        "You compile your findings into a timeline:\n\n"
        "  1. Sep 14, 2025 — Four domains registered through NameSilo using\n"
        "     a Panama shell company (Vantage Holdings Group)\n"
        "  2. Oct 3, 2025 — Photos of proprietary circuit boards taken inside\n"
        "     Apex Dynamics' R&D lab (Mountain View, CA) with an iPhone 15 Pro\n"
        "  3. Oct-Nov 2025 — Images uploaded to uploads.vantagecorp.io\n"
        "  4. Nov 2, 2025 — Domain records updated, possibly to hide tracks\n\n"
        "The evidence chain is clear: someone inside Apex Dynamics is "
        "exfiltrating trade secrets to a domain cluster operated by a "
        "competitor-linked shell company. Now you need to present your "
        "findings to the client."
    )
    press_enter()

    narrator(
        "You sit in the Apex Dynamics boardroom. CEO Diana Reeves, General "
        "Counsel Marcus Webb, and CISO Elena Park are waiting. The way you "
        "present this evidence matters — it could end up in court."
    )

    score += choice_task(
        prompt_text=(
            "How do you present your OSINT findings to the Apex Dynamics team?"
        ),
        options=[
            (
                "Structured evidence report",
                "Present a formal report with a timeline, evidence chain, "
                "methodology documentation, and screenshots with hashes to "
                "prove integrity. Recommend they involve law enforcement.",
                5,
            ),
            (
                "Live technical demo",
                "Walk the executives through each tool and command live on "
                "your laptop, showing them exactly how you found each clue.",
                3,
            ),
            (
                "Executive summary only",
                "Give a one-page summary with the conclusion and skip the "
                "technical details. Executives do not need to see the commands.",
                1,
            ),
        ],
    )

    narrator(
        "Marcus Webb, the General Counsel, nods approvingly. 'A structured "
        "evidence report with integrity hashes is exactly what we need if "
        "this goes to litigation. Document your methodology so our legal "
        "team can verify the chain of evidence. And you are right — we "
        "should contact the FBI's Cyber Division.'\n\n"
        "Elena Park, the CISO, adds: 'I want to cross-reference the EXIF "
        "timestamp with our badge access logs. If we can match an employee "
        "who was in the R&D lab on October 3rd at 10:14 PM to an iPhone 15 "
        "Pro on our MDM system, we have our insider.'"
    )
    press_enter()

    narrator(
        "Before wrapping up the engagement, there is one more critical topic "
        "to cover: the legal boundaries of OSINT. As a professional "
        "investigator, you must always be able to explain why your methods "
        "were lawful."
    )

    score += quiz_task(
        question=(
            "Which of the following statements about OSINT legality is TRUE?"
        ),
        options=[
            "OSINT has no legal restrictions because all data is public",
            "Collecting publicly available data is legal, but using it for "
            "harassment or stalking can be criminal",
            "OSINT is illegal in the European Union due to GDPR",
            "Only law enforcement agencies are legally permitted to conduct OSINT",
        ],
        correct_index=1,
        explanation=(
            "OSINT itself involves collecting publicly available data, which is "
            "legal. However, how you USE that data matters enormously. Stalking, "
            "harassment, doxxing, or using OSINT findings to access private "
            "systems are all criminal acts. GDPR adds restrictions on processing "
            "personal data in the EU, but does not ban OSINT outright. Always "
            "operate within your legal authority and scope of engagement."
        ),
        points=5,
    )

    narrator(
        "Diana Reeves stands and shakes your hand. 'You have given us "
        "exactly what we need — a clear evidence trail built entirely on "
        "public data, no gray areas, no legal exposure. Our lawyers will "
        "take it from here.'\n\n"
        "As you pack up your laptop, Elena catches you at the door. 'We are "
        "already locking down the R&D lab access list and deploying DLP "
        "sensors on our network. This will not happen again. Thank you.'"
    )
    press_enter()

    narrator(
        "Walking to your car, you reflect on the investigation. Not a single "
        "password was cracked. Not a single system was compromised. Every "
        "piece of evidence came from publicly available sources — WHOIS "
        "records, DNS queries, cached web pages, and image metadata. That "
        "is the power of OSINT: the truth is often hiding in plain sight, "
        "waiting for someone with the right skills to find it."
    )
    press_enter()

    return score


# ---------------------------------------------------------------------------
# Easter Egg — Investigate the nameserver
# ---------------------------------------------------------------------------

def _easter_egg_nameserver(progress: dict) -> int:
    """Hidden bonus: investigate the suspicious shadowdns.net nameservers."""
    narrator(
        "Something nags at you. The WHOIS results showed the nameservers "
        "as ns1.shadowdns.net and ns2.shadowdns.net — a privacy-focused "
        "DNS provider. But who runs shadowdns.net itself? That might be "
        "worth a quick look..."
    )
    print()
    bonus_input = input(f"  {G}{BRIGHT}root@target:~${RESET} ").strip()
    if bonus_input and re.search(r"whois\s+shadowdns\.net", bonus_input, re.IGNORECASE):
        print()
        success("HIDDEN BONUS: You investigated the nameserver! +10 pts")
        narrator(
            "The WHOIS for shadowdns.net reveals it was registered through "
            "the same Panama registrar — NameSilo — on the same day as the "
            "VantageCorp domains. The adversary didn't just use a privacy DNS "
            "service; they CREATED one. This is a significant finding that "
            "strengthens the infrastructure fingerprint."
        )
        eggs = progress.setdefault("easter_eggs_found", [])
        if "mission4" not in eggs:
            eggs.append("mission4")
        return 10
    return 0
