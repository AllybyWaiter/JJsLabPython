"""
Mission 2: Shadow on the Wire — Network Intrusion Investigation

Story: You're called in to investigate strange network activity at Mercy
General Hospital. Their monitoring system flagged unusual outbound traffic
at 3 AM. You discover a backdoor that's been exfiltrating patient data.

Stages:
  1. Network Analysis — capture and inspect suspicious traffic
  2. Packet Investigation — write a packet analyzer, identify protocols
  3. Backdoor Discovery — decode C2 communications, decide how to respond
  4. Containment & Debrief — lock down the network and report findings
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

MISSION_KEY = "mission2"
MAX_SCORE = 100


def run(progress: dict):
    """Entry point for Mission 2."""
    mission_briefing(
        mission_num=2,
        title="Shadow on the Wire",
        client="Mercy General Hospital",
        objective="Investigate anomalous network traffic and neutralize a data exfiltration threat",
    )

    score = 0
    score += stage_1_network_analysis()
    score += stage_2_packet_investigation()
    score += stage_3_backdoor_discovery()
    score += stage_4_containment()

    # Cap at max
    score = min(score, MAX_SCORE)

    mission_complete(2, "Shadow on the Wire", score, MAX_SCORE)

    # Save progress
    mark_mission_complete(progress, MISSION_KEY, score, MAX_SCORE)


# ---------------------------------------------------------------------------
# Stage 1 — Network Analysis
# ---------------------------------------------------------------------------

def stage_1_network_analysis() -> int:
    stage_intro(1, "NETWORK ANALYSIS")
    score = 0

    narrator(
        "Your phone buzzes at 4:17 AM. It's a call from Dr. Anita Rao, "
        "the CTO of Mercy General Hospital. 'We need you here now,' she "
        "says, her voice tight with urgency. 'Our IDS flagged a burst of "
        "outbound traffic at 3 AM — over 200 megabytes sent to an unknown "
        "external IP. This hospital handles 40,000 patient records. If "
        "someone is pulling data out, we have a HIPAA nightmare on our "
        "hands.'"
    )
    press_enter()

    narrator(
        "You arrive at the hospital's server room twenty minutes later. "
        "The hum of rack-mounted servers fills the cold air. A wall of "
        "blinking LEDs tells you these machines are busy — maybe too busy "
        "for 4 AM. Dr. Rao hands you credentials to the network monitoring "
        "station. 'The traffic came from somewhere on the 10.10.0.0/16 "
        "internal subnet,' she says. 'Find it.'"
    )
    press_enter()

    narrator(
        "You sit down at the monitoring workstation and open a terminal. "
        "The first step is to capture live traffic on the hospital's core "
        "network interface, eth0. You need to grab packets and write them "
        "to a file for deeper analysis. Time to fire up tcpdump."
    )

    score += command_task(
        prompt_text=(
            "Capture network traffic on interface eth0 and write it to a "
            "pcap file called 'hospital_capture.pcap'. Use tcpdump."
        ),
        accepted=[
            r"tcpdump\s+-i\s+eth0\s+-w\s+hospital_capture\.pcap.*",
            r"tcpdump\s+.*-i\s+eth0.*-w\s+hospital_capture\.pcap.*",
            r"tcpdump\s+.*-w\s+hospital_capture\.pcap.*-i\s+eth0.*",
            r"sudo\s+tcpdump\s+-i\s+eth0\s+-w\s+hospital_capture\.pcap.*",
        ],
        points=10,
        hints=[
            "tcpdump uses -i to specify the interface and -w to write to a file",
            "tcpdump -i eth0 -w hospital_capture.pcap",
        ],
    )

    narrator(
        "Packets start flowing. After a 60-second capture, you stop tcpdump "
        "and examine the results. The file is 14 MB — there's definitely "
        "active traffic at this hour. Now you need to filter the capture "
        "to find connections to external IP addresses.\n\n"
        "The IDS alert log shows the suspicious traffic was directed at "
        "port 443 — but the volume and timing don't match normal HTTPS "
        "behavior. The destination was logged as 185.243.115.42. That IP "
        "is registered to a VPS provider in Eastern Europe."
    )
    press_enter()

    narrator(
        "You run a quick filter on the capture file. The results are "
        "alarming:\n\n"
        "  10.10.4.22:49832 -> 185.243.115.42:443   [SYN]\n"
        "  10.10.4.22:49832 -> 185.243.115.42:443   [PSH, ACK] len=4096\n"
        "  10.10.4.22:49832 -> 185.243.115.42:443   [PSH, ACK] len=4096\n"
        "  10.10.4.22:49832 -> 185.243.115.42:443   [PSH, ACK] len=4096\n"
        "  (... 847 more packets ...)\n\n"
        "A single internal machine — 10.10.4.22 — has been sending large, "
        "steady data streams to the external IP. The packet sizes are "
        "uniform at 4096 bytes, which is unusual for legitimate HTTPS "
        "traffic. This looks like automated data exfiltration."
    )

    score += puzzle_task(
        prompt_text=(
            "Based on the traffic analysis above, what is the internal IP "
            "address of the compromised machine?"
        ),
        accepted=[
            r"10\.10\.4\.22",
        ],
        points=5,
        hints=[
            "Look at the source IP in the packet log — the left side of the arrow",
            "The IP starts with 10.10.4.",
        ],
    )

    narrator(
        "Confirmed. The machine at 10.10.4.22 is your prime suspect. "
        "Dr. Rao checks the asset registry — it's a workstation in the "
        "radiology department, used by staff to access the PACS (Picture "
        "Archiving and Communication System) which stores medical images "
        "and patient metadata. If that workstation is compromised, the "
        "attacker may have access to thousands of patient records."
    )
    press_enter()

    return score


# ---------------------------------------------------------------------------
# Stage 2 — Packet Investigation
# ---------------------------------------------------------------------------

def stage_2_packet_investigation() -> int:
    stage_intro(2, "PACKET INVESTIGATION")
    score = 0

    narrator(
        "You need to dig deeper into the captured packets. The raw pcap "
        "file contains thousands of frames, and scrolling through hex dumps "
        "isn't efficient. You decide to write a Python script using the "
        "scapy library to parse the capture file, filter for traffic "
        "involving the suspicious IP, and extract the payload data."
    )
    press_enter()

    narrator(
        "Your script needs to:\n"
        "  1. Import scapy and read the pcap file\n"
        "  2. Filter packets where the destination is 185.243.115.42\n"
        "  3. Extract the raw payload from each matching packet\n"
        "  4. Write the extracted data to a file for analysis\n\n"
        "Write the core of this packet analyzer."
    )

    score += code_task(
        prompt_text=(
            "Write a Python script using scapy to read 'hospital_capture.pcap', "
            "filter packets going to 185.243.115.42, and extract the raw payload "
            "data. Use rdpcap to read, check IP layer destination, and access "
            "the Raw layer."
        ),
        required_keywords=["scapy", "rdpcap", "185.243.115.42", "Raw", "IP"],
        points=15,
        hints=[
            "Start with: from scapy.all import rdpcap, IP, Raw",
            "Use rdpcap('file.pcap') to load packets, then loop and check pkt[IP].dst",
            "Access payload with pkt[Raw].load",
        ],
        example_solution=(
            "from scapy.all import rdpcap, IP, Raw\n"
            "\n"
            "packets = rdpcap('hospital_capture.pcap')\n"
            "target_ip = '185.243.115.42'\n"
            "\n"
            "with open('extracted_data.bin', 'wb') as out:\n"
            "    for pkt in packets:\n"
            "        if pkt.haslayer(IP) and pkt[IP].dst == target_ip:\n"
            "            if pkt.haslayer(Raw):\n"
            "                out.write(pkt[Raw].load)\n"
            "\n"
            "print('Payload extraction complete.')"
        ),
    )

    narrator(
        "Your script runs and extracts 198 MB of raw payload data. "
        "Examining the first few hundred bytes, you see something "
        "unexpected. The traffic is wrapped in TLS, but the certificate "
        "is self-signed and the cipher suite is weak. This isn't legitimate "
        "HTTPS — it's a custom encrypted tunnel designed to look like "
        "normal web traffic."
    )
    press_enter()

    narrator(
        "Before you continue the technical deep-dive, let's make sure "
        "you understand the networking fundamentals at play here. The "
        "attacker chose port 443 deliberately — it's the standard port "
        "for HTTPS traffic, which most firewalls allow outbound without "
        "inspection."
    )

    score += quiz_task(
        question=(
            "Why would an attacker choose to exfiltrate data over port "
            "443 instead of using a random high port?"
        ),
        options=[
            "Port 443 is faster than other ports",
            "Port 443 (HTTPS) is typically allowed through firewalls and blends with normal traffic",
            "Port 443 automatically encrypts data without any configuration",
            "Port 443 is unmonitored by all intrusion detection systems",
        ],
        correct_index=1,
        explanation=(
            "Attackers use port 443 because outbound HTTPS traffic is almost always "
            "allowed by firewalls and appears normal in traffic logs. It provides "
            "natural camouflage for malicious communications. This technique is "
            "known as 'living off the land' at the network layer."
        ),
        points=10,
    )

    narrator(
        "You also notice something in the packet timing. The data bursts "
        "happen in precise 30-second intervals — a clear sign of automated "
        "beaconing, not human-driven browsing. A real user would generate "
        "irregular traffic patterns. This machine is running on a timer."
    )
    press_enter()

    return score


# ---------------------------------------------------------------------------
# Stage 3 — Backdoor Discovery
# ---------------------------------------------------------------------------

def stage_3_backdoor_discovery() -> int:
    stage_intro(3, "BACKDOOR DISCOVERY")
    score = 0

    narrator(
        "You gain access to the compromised workstation at 10.10.4.22. "
        "A quick process listing reveals a suspicious service running "
        "as SYSTEM: 'svchost_update.exe' — a name designed to blend in "
        "with legitimate Windows services, but it's not in any standard "
        "Windows directory. It's running from C:\\ProgramData\\Microsoft\\"
        "Updates\\, a folder that doesn't exist on clean installs."
    )
    press_enter()

    narrator(
        "You examine the malware's configuration file, hidden in the same "
        "directory. It's a JSON file with Base64-encoded values. One field "
        "catches your eye:\n\n"
        "  {\n"
        "    \"beacon_interval\": 30,\n"
        "    \"c2_server\": \"aHR0cHM6Ly8xODUuMjQzLjExNS40Mi9hcGkvY2hlY2tpbg==\",\n"
        "    \"exfil_path\": \"L3BhY3MvZGljb20vZXhwb3J0\",\n"
        "    \"encryption\": \"xor_rolling\"\n"
        "  }\n\n"
        "The c2_server value is Base64-encoded. Decode it to find the "
        "command-and-control URL the malware reports to."
    )

    score += puzzle_task(
        prompt_text=(
            "Decode the Base64 string: aHR0cHM6Ly8xODUuMjQzLjExNS40Mi9hcGkvY2hlY2tpbg==\n"
            "What is the C2 (command-and-control) URL?"
        ),
        accepted=[
            r"https?://185\.243\.115\.42/api/checkin",
        ],
        points=15,
        hints=[
            "Use a Base64 decoder: echo 'aHR0cHM6Ly8...' | base64 -d",
            "The decoded string starts with 'https://'",
        ],
    )

    narrator(
        "The C2 URL is https://185.243.115.42/api/checkin — every 30 "
        "seconds the backdoor phones home, receives instructions, and "
        "exfiltrates data from the PACS DICOM export directory. The "
        "attacker has been quietly siphoning patient imaging data — X-rays, "
        "MRIs, CT scans — along with the embedded patient metadata: names, "
        "dates of birth, medical record numbers."
    )
    press_enter()

    narrator(
        "This is a serious incident. You now face a critical decision. "
        "The backdoor is active and still exfiltrating data. You could "
        "kill the process immediately, but that might alert the attacker "
        "and cause them to destroy evidence on their C2 server. "
        "Alternatively, you could monitor the connection to gather "
        "intelligence about the attacker before shutting it down."
    )

    score += choice_task(
        prompt_text=(
            "The backdoor is actively exfiltrating patient data. How do "
            "you proceed?"
        ),
        options=[
            (
                "Isolate and monitor",
                "Move the workstation to a quarantine VLAN, sinkhole the C2 "
                "traffic to your own server, and observe the attacker's "
                "behavior to gather forensic evidence before killing the process.",
                15,
            ),
            (
                "Kill it immediately",
                "Terminate the malicious process, delete the binary, and block "
                "the C2 IP at the firewall right now. Stop the bleeding first.",
                8,
            ),
            (
                "Unplug the network cable",
                "Physically disconnect the workstation from the network to "
                "stop all traffic instantly.",
                5,
            ),
        ],
    )

    narrator(
        "Dr. Rao nods as you explain your approach. 'The forensics team "
        "from our cyber insurance provider is en route,' she says. 'They'll "
        "want as much evidence as possible. Every minute we can safely "
        "observe the attacker's tactics gives us a better chance of "
        "understanding the full scope of the breach.'\n\n"
        "You set up a sinkhole on the quarantine VLAN — the backdoor "
        "thinks it's still talking to its C2 server, but every packet is "
        "being logged. After 45 minutes of observation, you've captured "
        "the full command protocol and identified two additional compromised "
        "machines on the network."
    )
    press_enter()

    return score


# ---------------------------------------------------------------------------
# Stage 4 — Containment & Debrief
# ---------------------------------------------------------------------------

def stage_4_containment() -> int:
    stage_intro(4, "CONTAINMENT & DEBRIEF")
    score = 0

    narrator(
        "With the forensic evidence secured, it's time to lock down the "
        "network. The attacker's C2 server at 185.243.115.42 needs to be "
        "blocked at the perimeter firewall immediately. You also need to "
        "block all outbound traffic from the three compromised workstations "
        "until they can be reimaged. You sit down at the hospital's Linux-"
        "based firewall appliance."
    )
    press_enter()

    narrator(
        "First, block all outbound traffic to the attacker's C2 server. "
        "Use iptables to drop any packets destined for 185.243.115.42."
    )

    score += command_task(
        prompt_text=(
            "Write an iptables rule to DROP all outbound traffic to the "
            "attacker's C2 IP address 185.243.115.42."
        ),
        accepted=[
            r"iptables\s+-A\s+OUTPUT\s+-d\s+185\.243\.115\.42\s+-j\s+DROP",
            r"iptables\s+-A\s+FORWARD\s+-d\s+185\.243\.115\.42\s+-j\s+DROP",
            r"iptables\s+-I\s+OUTPUT\s+-d\s+185\.243\.115\.42\s+-j\s+DROP",
            r"iptables\s+-I\s+FORWARD\s+-d\s+185\.243\.115\.42\s+-j\s+DROP",
            r"iptables\s+.*-d\s+185\.243\.115\.42\s+-j\s+DROP",
            r"sudo\s+iptables\s+.*-d\s+185\.243\.115\.42\s+-j\s+DROP",
        ],
        points=10,
        hints=[
            "Use iptables -A to append a rule, -d for destination, -j for action",
            "iptables -A OUTPUT -d 185.243.115.42 -j DROP",
        ],
    )

    narrator(
        "Good. The C2 channel is severed. You verify the rule is active:\n\n"
        "  Chain OUTPUT (policy ACCEPT)\n"
        "  target  prot  source       destination\n"
        "  DROP    all   anywhere     185.243.115.42\n\n"
        "No more data is leaving this network for that IP. You also add "
        "rules to block the three compromised workstations from reaching "
        "the internet entirely while the forensics team works on them."
    )
    press_enter()

    narrator(
        "Now it's time for the debrief. You sit down with Dr. Rao, the "
        "hospital's legal counsel, and the CISO to present your findings. "
        "Under HIPAA regulations, this breach triggers mandatory "
        "notification requirements. Understanding incident response "
        "procedure is critical."
    )

    score += quiz_task(
        question=(
            "In a HIPAA-covered healthcare environment, what is the FIRST "
            "step in the incident response process after a confirmed data "
            "breach involving patient records?"
        ),
        options=[
            "Notify the media to warn affected patients",
            "Contain the breach and preserve evidence for forensic analysis",
            "File a police report with local law enforcement",
            "Shut down all hospital IT systems to prevent further exposure",
        ],
        correct_index=1,
        explanation=(
            "The first priority in incident response is containment and evidence "
            "preservation. HIPAA's Breach Notification Rule requires notification "
            "within 60 days, but you must first stop the bleeding and secure "
            "forensic evidence. Premature actions like shutting down all systems "
            "could disrupt patient care, and media notification happens only "
            "after the scope of the breach is determined."
        ),
        points=10,
    )

    narrator(
        "You compile your incident report. The timeline is clear:\n\n"
        "  02:47 AM — Backdoor initiates exfiltration cycle\n"
        "  03:01 AM — IDS flags anomalous outbound volume\n"
        "  03:14 AM — Automated alert sent to on-call staff\n"
        "  04:17 AM — You receive the call\n"
        "  04:38 AM — Live packet capture begins\n"
        "  05:22 AM — Compromised workstation identified\n"
        "  05:55 AM — Backdoor binary and C2 config recovered\n"
        "  06:10 AM — Workstation moved to quarantine VLAN\n"
        "  07:02 AM — Two additional compromised hosts found\n"
        "  07:30 AM — All C2 traffic blocked at perimeter firewall\n"
        "  08:00 AM — Debrief with hospital leadership\n"
    )
    press_enter()

    narrator(
        "Your investigation reveals that the initial compromise occurred "
        "twelve days ago via a phishing email sent to a radiology "
        "technician. The email contained a malicious Word document that "
        "exploited a macro to download and install the backdoor. Since "
        "then, the attacker has exfiltrated approximately 2.4 GB of "
        "patient imaging data and metadata."
    )

    score += quiz_task(
        question=(
            "Based on this investigation, which security control would "
            "have been MOST effective at preventing the initial compromise?"
        ),
        options=[
            "Stronger Wi-Fi passwords on the hospital network",
            "Email filtering with attachment sandboxing and macro blocking",
            "Full-disk encryption on all workstations",
            "More frequent password rotation for user accounts",
        ],
        correct_index=1,
        explanation=(
            "The attack started with a phishing email containing a malicious "
            "macro-enabled document. Email filtering that sandboxes attachments "
            "and blocks macros by default would have stopped the payload from "
            "ever reaching the user. Defense in depth starts at the most common "
            "entry point: email."
        ),
        points=10,
    )

    narrator(
        "Dr. Rao shakes your hand firmly. 'You found it before they got "
        "everything,' she says. 'We'll begin patient notification this "
        "week. The board is approving budget for a complete security "
        "overhaul — email filtering, endpoint detection, network "
        "segmentation, the works.'\n\n"
        "As you walk out of Mercy General, the morning sun hits your "
        "face. Somewhere out there, an attacker just lost access to their "
        "cash cow. The shadow on the wire has been cut. But you know it's "
        "only a matter of time before the next one shows up. You make a "
        "mental note: check your own email filters when you get home."
    )
    press_enter()

    return score
