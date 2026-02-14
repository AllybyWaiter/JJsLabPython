"""
Mission Epilogues — score-based narrative endings for each mission.

After completing a mission, players see a "SIX MONTHS LATER..." epilogue
that reflects how well they performed. Three tiers per mission:
  - HIGH  (>=90%): best possible outcome
  - MID   (50-89%): mixed results
  - LOW   (<50%): consequences of a weak performance
"""

import time

from utils.display import (
    sub_header, narrator, press_enter,
)


EPILOGUES = {
    1: {
        "high": (
            "ProjectHub passes a rigorous third-party security audit with zero "
            "critical findings. Sarah Chen presents your penetration test report "
            "at the annual DevSecOps conference as a case study in proactive "
            "security. NovaTech's client launch goes off without a hitch, and "
            "two Fortune 500 companies sign on within the first quarter. Sarah "
            "sends you a handwritten note: 'You didn't just find the bugs — "
            "you changed how we think about security.'"
        ),
        "mid": (
            "The SQL injection and XSS vulnerabilities are patched within a "
            "week. But a follow-up audit by a different firm finds two medium-"
            "severity issues you missed — a session fixation flaw and an IDOR "
            "on the API. The client launch is delayed by three weeks while the "
            "dev team scrambles to fix them. Sarah Chen is grateful for your "
            "work, but quietly hires a second firm for future engagements. "
            "'Good work,' she says. 'But we needed great.'"
        ),
        "low": (
            "NovaTech launches ProjectHub to clients with a false sense of "
            "security. Six weeks later, an attacker exploits the same SQL "
            "injection vulnerability you failed to fully document. Customer "
            "data is exposed — names, emails, project details for 12,000 "
            "users. The breach makes industry news. NovaTech faces a class-"
            "action lawsuit and their stock drops 8%. Sarah Chen leaves the "
            "company. Your report is cited in the post-mortem as 'incomplete.'"
        ),
    },
    2: {
        "high": (
            "Your forensic evidence package is airtight. The FBI Cyber Division "
            "traces the C2 server to a ransomware group operating out of Eastern "
            "Europe. Three arrests follow. Mercy General's swift response earns "
            "praise from HIPAA regulators — no fines are levied because the "
            "hospital demonstrated exemplary incident handling. Dr. Rao publishes "
            "a case study in the Journal of Healthcare Information Security, "
            "crediting your investigation as the reason they caught the breach "
            "in hours instead of months."
        ),
        "mid": (
            "The network is hardened and the backdoor is removed, but the "
            "attacker is never identified. Without complete forensic evidence, "
            "the FBI investigation stalls. HIPAA regulators issue a moderate "
            "fine of $380,000 for gaps in the hospital's security controls. "
            "Dr. Rao implements your recommendations but can't shake the "
            "feeling that the attacker is still out there, watching. The "
            "hospital's cyber insurance premium doubles."
        ),
        "low": (
            "The incomplete investigation leaves critical gaps. Three months "
            "later, a second breach occurs — the attacker had planted a "
            "secondary backdoor you never found. This time, 40,000 patient "
            "records are fully exfiltrated and posted on a dark web forum. "
            "A class-action lawsuit follows. HIPAA levies the maximum fine "
            "of $1.5 million. Dr. Rao steps down as CTO. The hospital's "
            "reputation takes years to recover."
        ),
    },
    3: {
        "high": (
            "DataVault migrates their entire infrastructure to Argon2 with "
            "mandatory MFA on every account. Your evidence package — the "
            "cracked hashes, the weak policy documentation, the timeline of "
            "Marcus Webb's sabotage — becomes central to the criminal case "
            "against him. Marcus faces charges for unauthorized access and "
            "intentional damage to computer systems. He takes a plea deal "
            "and is sentenced to 18 months. Rachel Torres calls you on the "
            "anniversary: 'We haven't had a single password incident since.'"
        ),
        "mid": (
            "DataVault upgrades to bcrypt, but the MFA rollout stalls due to "
            "budget constraints. Only admin accounts are protected. The case "
            "against Marcus Webb drags on — his lawyer argues the weak hashes "
            "prove the company's negligence, not his malice. The suit settles "
            "out of court. Two legacy systems are quietly forgotten and still "
            "run MD5. Rachel knows it, but the board won't fund a full migration."
        ),
        "low": (
            "Without a thorough investigation, DataVault patches the immediate "
            "problem but fails to address the root cause. The legacy MD5 systems "
            "remain in production. Eight months later, a different contractor "
            "discovers the same weak hashes and exploits them — this time "
            "exfiltrating 50,000 customer records. The data is gone for good. "
            "Marcus Webb's case is dismissed due to insufficient evidence. "
            "DataVault loses three major clients and nearly folds."
        ),
    },
    4: {
        "high": (
            "Your structured evidence report is handed to the FBI's Cyber "
            "Division. Cross-referencing your OSINT findings with badge access "
            "logs and MDM records, they identify Elena Markov — the former Apex "
            "engineer who joined Vantage Corp. She is indicted on charges of "
            "trade secret theft under the Economic Espionage Act. Apex Dynamics "
            "recovers $4.2 million in damages through civil litigation. The CEO "
            "sends you a bottle of Scotch with a note: 'The ghost has a name now.'"
        ),
        "mid": (
            "Your investigation produces strong circumstantial evidence, but "
            "gaps in the OSINT chain give the defense room to maneuver. Apex "
            "files a civil suit against Vantage Corp, but the case settles out "
            "of court for an undisclosed amount — far less than the actual "
            "damages. Elena Markov quietly resigns from Vantage and moves to "
            "another company. The stolen designs appear in a competitor's "
            "product six months later. Everyone knows, but nobody can prove it."
        ),
        "low": (
            "The investigation produces too little actionable evidence. Without "
            "clear documentation linking the domains, the metadata, and the "
            "insider, the case collapses before it reaches a courtroom. Apex "
            "Dynamics' trade secrets continue to leak. The ghost remains free. "
            "A year later, Vantage Corp launches a suspiciously similar product "
            "line. Apex's market share drops 15%. The CEO fires the CISO and "
            "hires a new investigation firm. This time, they find what you missed."
        ),
    },
    5: {
        "high": (
            "CloudStream's incident response becomes an industry model. Your "
            "forensic evidence leads to the arrest of the attacker — a 24-year-"
            "old hacker operating from a rented apartment in Bucharest. David "
            "Park presents the post-mortem at RSA Conference to a standing "
            "ovation. CloudStream's transparent disclosure earns customer trust "
            "instead of destroying it. Subscriptions actually increase by 12% "
            "in the following quarter. David sends you a message: 'You turned "
            "our worst night into our finest hour.'"
        ),
        "mid": (
            "CloudStream recovers, but the scars remain. The regulatory fines "
            "are manageable — $200,000 from the FTC, a warning from EU DPAs. "
            "But without complete forensic evidence, the attacker is never "
            "identified. Prosecution is impossible. David Park implements every "
            "security recommendation but can't sleep through the night for "
            "months. The attacker is still out there, and they know CloudStream's "
            "infrastructure intimately. The security team lives in a state of "
            "permanent vigilance."
        ),
        "low": (
            "The incomplete response leaves CloudStream exposed. Regulators "
            "levy maximum fines — $2.1 million combined. The delayed disclosure "
            "destroys customer trust; 340,000 users cancel within 60 days. A "
            "private equity firm acquires CloudStream at a steep discount. David "
            "Park is replaced as CTO. The new owners gut the engineering team "
            "and offshore the security operations. The attacker's identity is "
            "never discovered. Your name appears in the post-mortem under "
            "'areas for improvement.'"
        ),
    },
}


def show_epilogue(mission_num: int, score: int, max_score: int):
    """Display a score-based epilogue after mission completion."""
    mission_epilogues = EPILOGUES.get(mission_num)
    if not mission_epilogues:
        return

    pct = (score / max_score * 100) if max_score else 0

    if pct >= 90:
        tier = "high"
    elif pct >= 50:
        tier = "mid"
    else:
        tier = "low"

    text = mission_epilogues[tier]

    print()
    sub_header("SIX MONTHS LATER...")
    time.sleep(1)
    narrator(text)
    press_enter()
