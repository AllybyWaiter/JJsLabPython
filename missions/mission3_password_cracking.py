"""
Mission 3: The Vault — Password Cracking

Story: DataVault Inc. discovers that their former sysadmin, Marcus Webb,
left behind encrypted files and password hashes before being terminated.
You're hired to crack the hashes and recover the data before it's too late.

Stages:
  1. Hash Identification     — recognize hash types by format
  2. Dictionary Attack       — write and run a dictionary attack
  3. Advanced Cracking       — crack a real hash, recommend policy
  4. Debrief                 — password storage best practices
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

MISSION_KEY = "mission3"
MAX_SCORE = 100


def run(progress: dict):
    """Entry point for Mission 3."""
    difficulty = progress.get("difficulty", "beginner")

    mission_briefing(
        mission_num=3,
        title="The Vault",
        client="DataVault Inc.",
        objective="Crack recovered password hashes before the data is lost",
    )

    dossier_path = generate_dossier(3)

    score = 0
    score += stage_1_hash_identification(difficulty)
    score += _easter_egg_legacy_hash(progress)
    score += maybe_random_event(3)
    score += stage_2_dictionary_attack(difficulty)
    score += maybe_random_event(3)
    score += stage_3_advanced_cracking(difficulty)
    score += maybe_random_event(3)
    score += stage_4_debrief(difficulty)

    mission_complete(3, "The Vault", score, MAX_SCORE)
    show_epilogue(3, score, MAX_SCORE)
    mark_mission_complete(progress, MISSION_KEY, score, MAX_SCORE)


# ---------------------------------------------------------------------------
# Stage 1 — Hash Identification
# ---------------------------------------------------------------------------

def stage_1_hash_identification(difficulty: str = "beginner") -> int:
    stage_intro(1, "HASH IDENTIFICATION")
    score = 0

    narrator(
        "You get the call at 11 PM on a Thursday. Rachel Torres, CTO of "
        "DataVault Inc., sounds shaken. 'We terminated our sysadmin, Marcus "
        "Webb, this morning. Routine exit audit found something disturbing — "
        "he changed the master passwords on three encrypted file servers "
        "right before he walked out. We're locked out of our own data.'"
    )
    press_enter()

    narrator(
        "You arrive at DataVault's server room within the hour. Their "
        "forensics team has already imaged the drives and extracted a "
        "file: shadow_dump.txt. Inside are four password hashes that "
        "Marcus set. Crack them, and you unlock the vaults."
    )
    press_enter()

    narrator(
        "You open the file and see the first hash:\n\n"
        "  Hash 1:  5d41402abc4b2a76b9719d911017c592\n\n"
        "Before you try to crack anything, you need to identify what type "
        "of hash you're dealing with. This one is 32 hex characters long."
    )

    score += puzzle_task(
        prompt_text=(
            "What type of hash is this? (32 hexadecimal characters)\n"
            "  5d41402abc4b2a76b9719d911017c592"
        ),
        accepted=[
            r"md5",
            r"md-?5",
        ],
        points=10,
        hints=[
            "Count the characters -- 32 hex digits is a signature length for a very common hash",
            "It's one of the most widely known (and weakest) hash algorithms",
        ],
        difficulty=difficulty,
    )

    narrator(
        "Good eye. MD5 produces a 128-bit (32 hex character) digest. "
        "It's fast to compute, which makes it fast to crack.\n\n"
        "Now look at the second hash:\n\n"
        "  Hash 2:  2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824\n\n"
        "This one is 64 hex characters long — twice the length of MD5."
    )

    score += puzzle_task(
        prompt_text=(
            "What type of hash is this? (64 hexadecimal characters)\n"
            "  2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        ),
        accepted=[
            r"sha-?256",
            r"sha256",
        ],
        points=10,
        hints=[
            "It's in the SHA-2 family -- 256 bits = 64 hex characters",
            "SHA-___  (fill in the number of bits)",
        ],
        difficulty=difficulty,
    )

    narrator(
        "Correct. SHA-256 produces a 256-bit (64 hex character) digest. "
        "Stronger than MD5, but still not designed for password storage.\n\n"
        "The third hash looks different entirely:\n\n"
        "  Hash 3:  $2b$12$WApznUPhDubN0oeveSXHp.Rk0rMoTBMRsGJkN4Y7rx6gSecWGnDO6\n\n"
        "Notice the $2b$12$ prefix and the unusual character set."
    )

    score += puzzle_task(
        prompt_text=(
            "What type of hash is this?\n"
            "  $2b$12$WApznUPhDubN0oeveSXHp.Rk0rMoTBMRsGJkN4Y7rx6gSecWGnDO6"
        ),
        accepted=[
            r"bcrypt",
            r"b-?crypt",
        ],
        points=10,
        hints=[
            "The $2b$ prefix is a dead giveaway for this adaptive hash function",
            "It starts with $2b$ — a password hashing function named after a fish cipher",
        ],
        difficulty=difficulty,
    )

    narrator(
        "That's bcrypt — an adaptive hashing function designed for passwords. "
        "The '12' after $2b$ is the cost factor (2^12 = 4,096 rounds). "
        "It's intentionally slow, making brute-force attacks expensive. "
        "Marcus knew what he was doing with that one."
    )
    press_enter()

    narrator(
        "Rachel leans over your shoulder. 'Can you crack all three?' "
        "You nod. 'The MD5 and SHA-256 should fall quickly. The bcrypt "
        "one will take more work. Let me explain why...'"
    )

    score += quiz_task(
        question=(
            "Why is bcrypt more resistant to cracking than MD5 or SHA-256?"
        ),
        options=[
            "Bcrypt produces a longer hash output",
            "Bcrypt is intentionally slow and includes a built-in salt",
            "Bcrypt uses symmetric encryption instead of hashing",
            "Bcrypt hashes cannot be compared for equality",
        ],
        correct_index=1,
        explanation=(
            "Bcrypt is designed for password hashing. Its configurable cost "
            "factor makes it intentionally slow, and each hash includes a "
            "unique salt, so identical passwords produce different hashes. "
            "This makes precomputed attacks (rainbow tables) useless."
        ),
        points=10,
        difficulty=difficulty,
    )

    return score


# ---------------------------------------------------------------------------
# Stage 2 — Dictionary Attack
# ---------------------------------------------------------------------------

def stage_2_dictionary_attack(difficulty: str = "beginner") -> int:
    stage_intro(2, "DICTIONARY ATTACK")
    score = 0

    narrator(
        "Time to get cracking. You start with the MD5 hash. The fastest "
        "approach for common passwords is a dictionary attack — hashing "
        "every word in a wordlist and comparing it to the target hash."
    )
    press_enter()

    narrator(
        "You have a wordlist file called rockyou.txt (a famous leaked "
        "password list with millions of entries). Your first step is to "
        "write a quick Python script that reads the wordlist, hashes each "
        "word with MD5, and checks for a match against the target hash.\n\n"
        "Target MD5 hash:  5d41402abc4b2a76b9719d911017c592"
    )

    score += code_task(
        prompt_text=(
            "Write a Python script that performs a dictionary attack.\n"
            "It should:\n"
            "  - import hashlib\n"
            "  - open and read a wordlist file\n"
            "  - hash each word with md5\n"
            "  - compare to the target hash using hexdigest()"
        ),
        required_keywords=[
            "hashlib",
            "md5",
            "hexdigest",
            "open",
        ],
        points=10,
        hints=[
            "Start with: import hashlib",
            "Use hashlib.md5(word.encode()).hexdigest() to hash each word",
            "Open the wordlist with: open('rockyou.txt', 'r')",
        ],
        example_solution=(
            "import hashlib\n"
            "\n"
            "target = '5d41402abc4b2a76b9719d911017c592'\n"
            "\n"
            "with open('rockyou.txt', 'r', errors='ignore') as f:\n"
            "    for line in f:\n"
            "        word = line.strip()\n"
            "        hashed = hashlib.md5(word.encode()).hexdigest()\n"
            "        if hashed == target:\n"
            "            print(f'Cracked: {word}')\n"
            "            break"
        ),
        difficulty=difficulty,
    )

    narrator(
        "Your script runs through the wordlist. Within seconds, it finds "
        "a match:\n\n"
        "  [+] Cracked!  5d41402abc4b2a76b9719d911017c592  =>  hello\n\n"
        "Marcus used 'hello' as one of his passwords. Not exactly the "
        "work of a security-conscious sysadmin. One vault down, two to go."
    )
    press_enter()

    narrator(
        "For the SHA-256 hash, you could modify your script, but "
        "professionals use dedicated tools. John the Ripper is a classic "
        "password cracker that supports hundreds of hash formats and can "
        "run dictionary, rule-based, and brute-force attacks."
    )

    score += command_task(
        prompt_text=(
            "Use John the Ripper to run a dictionary attack against a file "
            "called hashes.txt using the rockyou.txt wordlist."
        ),
        accepted=[
            r"john\s+.*--wordlist[= ]rockyou\.txt.*hashes\.txt",
            r"john\s+.*--wordlist[= ]/usr/share/wordlists/rockyou\.txt.*hashes\.txt",
            r"john\s+.*hashes\.txt.*--wordlist[= ]rockyou\.txt",
            r"john\s+.*hashes\.txt.*--wordlist[= ]/usr/share/wordlists/rockyou\.txt",
        ],
        points=10,
        hints=[
            "The syntax is: john --wordlist=<path_to_wordlist> <hash_file>",
            "john --wordlist=rockyou.txt hashes.txt",
        ],
        difficulty=difficulty,
    )

    narrator(
        "John the Ripper crunches through the wordlist:\n\n"
        "  Loaded 1 password hash (Raw-SHA256)\n"
        "  Press 'q' or Ctrl-C to abort\n"
        "  sunshine         (user2)\n"
        "  1g 0:00:00:03 DONE (Dictionary) 0.3125g/s 1024Kp/s\n\n"
        "Two down. The SHA-256 password was 'sunshine'. Marcus apparently "
        "didn't practice what he preached about password complexity."
    )
    press_enter()

    return score


# ---------------------------------------------------------------------------
# Stage 3 — Advanced Cracking
# ---------------------------------------------------------------------------

def stage_3_advanced_cracking(difficulty: str = "beginner") -> int:
    stage_intro(3, "ADVANCED CRACKING")
    score = 0

    narrator(
        "The bcrypt hash is going to be much harder to crack with brute "
        "force — that's the whole point of bcrypt. But you have one more "
        "trick: sometimes, even with strong hashing, people choose terrible "
        "passwords.\n\n"
        "Before tackling the bcrypt hash, Rachel brings you another "
        "finding. The forensics team recovered a MySQL database dump from "
        "Marcus's workstation. It contains an old user table where passwords "
        "were stored as plain MD5 — no salt, no iterations."
    )
    press_enter()

    narrator(
        "One hash from the database stands out:\n\n"
        "  admin:5f4dcc3b5aa765d61d8327deb882cf99\n\n"
        "This is one of the most commonly seen MD5 hashes in the world. "
        "Any experienced security analyst would recognize it instantly. "
        "What is the plaintext password?"
    )

    score += puzzle_task(
        prompt_text=(
            "Crack this famous MD5 hash. What is the plaintext?\n"
            "  5f4dcc3b5aa765d61d8327deb882cf99"
        ),
        accepted=[
            r"password",
        ],
        points=10,
        hints=[
            "This is literally the most common password in every leaked database",
            "It's the word people use when they can't think of a password",
        ],
        case_sensitive=True,
        difficulty=difficulty,
    )

    narrator(
        "'password'. Of course. Marcus stored the admin credentials with "
        "the literal word 'password' as the password. You check — this same "
        "password unlocks the third vault. All three file servers are now "
        "accessible."
    )
    press_enter()

    narrator(
        "Rachel exhales with relief. 'We're back in. But I never want this "
        "to happen again. What should our password policy look like going "
        "forward?' This is your chance to make a lasting recommendation."
    )

    score += choice_task(
        prompt_text=(
            "What password policy do you recommend DataVault implement?"
        ),
        options=[
            (
                "Require 20+ character passphrases with bcrypt storage",
                "Enforce long passphrases, use bcrypt with high cost factor, "
                "add MFA, and conduct regular hash audits",
                10,
            ),
            (
                "Require 8+ chars with uppercase, lowercase, number, symbol",
                "Classic complexity rules with SHA-256 hashing and quarterly "
                "password rotation",
                3,
            ),
            (
                "Implement passwordless authentication only",
                "Remove passwords entirely and use hardware keys or biometrics",
                7,
            ),
        ],
    )

    narrator(
        "You present your full recommendation:\n\n"
        "  1. Store all passwords with bcrypt (cost 12+) or Argon2\n"
        "  2. Enforce minimum 16-character passphrases\n"
        "  3. Require multi-factor authentication for all admin accounts\n"
        "  4. Conduct quarterly password hash audits\n"
        "  5. Implement account lockout after failed attempts\n\n"
        "Rachel takes notes carefully. 'This is exactly what we needed.'"
    )
    press_enter()

    return score


# ---------------------------------------------------------------------------
# Stage 4 — Debrief
# ---------------------------------------------------------------------------

def stage_4_debrief(difficulty: str = "beginner") -> int:
    stage_intro(4, "MISSION DEBRIEF")
    score = 0

    narrator(
        "A week later, you sit down with the DataVault board of directors "
        "to present your findings. The room is tense — they want to "
        "understand how this happened and how to prevent it."
    )
    press_enter()

    narrator(
        "You walk them through the timeline: Marcus changed three server "
        "passwords to weak values, counting on the team not being able to "
        "recover them. But weak hashes and weak passwords are a fatal "
        "combination.\n\n"
        "'The real lesson,' you explain, 'is about how passwords are stored. "
        "The hashing algorithm matters just as much as the password itself.'"
    )

    score += quiz_task(
        question=(
            "Which of the following is the BEST practice for storing "
            "user passwords in a database?"
        ),
        options=[
            "Store passwords in plaintext for easy recovery",
            "Use MD5 with a global salt shared across all accounts",
            "Use bcrypt or Argon2 with a unique per-user salt and high cost factor",
            "Encrypt passwords with AES so they can be decrypted if needed",
        ],
        correct_index=2,
        explanation=(
            "Bcrypt and Argon2 are purpose-built for password hashing. They "
            "are intentionally slow, use unique salts per password, and have "
            "adjustable cost factors. Encryption is reversible and therefore "
            "not suitable — if the key is compromised, all passwords are exposed."
        ),
        points=10,
        difficulty=difficulty,
    )

    narrator(
        "A board member asks, 'What about those rainbow table attacks we "
        "keep hearing about? How do salts actually help?'"
    )

    score += quiz_task(
        question=(
            "What is the primary purpose of a salt in password hashing?"
        ),
        options=[
            "To make the hash output longer and harder to read",
            "To encrypt the password before hashing it",
            "To ensure identical passwords produce different hashes, defeating precomputed tables",
            "To slow down the hashing algorithm",
        ],
        correct_index=2,
        explanation=(
            "A salt is random data added to each password before hashing. "
            "Even if two users have the same password, their salts differ, "
            "so their hashes differ. This makes precomputed attacks like "
            "rainbow tables impractical — the attacker would need a separate "
            "table for every possible salt value."
        ),
        points=10,
        difficulty=difficulty,
    )

    narrator(
        "The board nods along. You conclude your presentation with a "
        "final thought on the future of authentication."
    )

    narrator(
        "'Passwords are the oldest and weakest link in authentication. "
        "Even with perfect hashing, people choose bad passwords. The "
        "industry is moving toward passkeys, hardware tokens, and "
        "biometric authentication. My recommendation: start planning "
        "your transition now.'\n\n"
        "Rachel stands and shakes your hand. 'You saved our data and "
        "probably our company. We'll implement every recommendation.'"
    )
    press_enter()

    narrator(
        "As you pack your laptop, you reflect on the case. Three vaults, "
        "three weak passwords, three lessons learned:\n\n"
        "  - MD5 is dead for password storage. Don't use it.\n"
        "  - SHA-256 is better, but not designed for passwords.\n"
        "  - Bcrypt and Argon2 exist for a reason. Use them.\n\n"
        "Marcus Webb's sabotage failed because he underestimated how "
        "quickly weak hashes fall. The vault is open. Mission complete."
    )
    press_enter()

    return score


# ---------------------------------------------------------------------------
# Easter Egg — Recognize the legacy hash
# ---------------------------------------------------------------------------

def _easter_egg_legacy_hash(progress: dict) -> int:
    """Hidden bonus: recognize the 'password' hash from the dossier."""
    narrator(
        "You glance at the dossier one more time. There's a fourth hash "
        "Rachel didn't mention — the legacy_db entry: "
        "5f4dcc3b5aa765d61d8327deb882cf99. It's not part of the vault "
        "servers, but something about it looks familiar..."
    )
    print()
    bonus_input = input(f"  {M}{BRIGHT}Recognize it? (Enter to skip):{RESET} ").strip()
    if bonus_input and re.search(r"^password$", bonus_input, re.IGNORECASE):
        print()
        success("HIDDEN BONUS: You recognized the world's worst password! +10 pts")
        narrator(
            "5f4dcc3b5aa765d61d8327deb882cf99 is the MD5 hash of 'password' "
            "— the single most commonly cracked hash in every leaked database. "
            "If you can spot it on sight, you've seen enough breaches to know "
            "what you're doing."
        )
        eggs = progress.setdefault("easter_eggs_found", [])
        if "mission3" not in eggs:
            eggs.append("mission3")
        return 10
    return 0
