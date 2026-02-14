"""
Module 4 — Password Security
Covers hashing algorithms, password cracking concepts, building a strength
checker, and password policy best practices. Includes working code that the
user can run directly for hands-on learning.

All cracking exercises operate ONLY on test hashes the user generates
themselves — never against real credentials.
"""

import hashlib
import os
import time
import re
import math
import string

from utils.display import (
    section_header, sub_header, lesson_block, code_block, scenario_block,
    why_it_matters, info, success, warning, press_enter, show_menu,
    disclaimer, hint_text, ask_yes_no, pace, learning_goal, nice_work, tip,
    C, G, Y, R, RESET, BRIGHT, DIM
)
from utils.progress import mark_lesson_complete, mark_challenge_complete
from utils.quiz import run_quiz


# ─────────────────────────────────────────────────────────────────────────────
# Module entry point
# ─────────────────────────────────────────────────────────────────────────────

def run(progress):
    """Main entry point called from the menu system."""
    module_key = "module4"
    while True:
        choice = show_menu("Module 4: Password Security", [
            ("hashing",           "Lesson 1: Hashing Algorithms"),
            ("cracking",          "Lesson 2: Password Cracking Concepts"),
            ("strength_checker",  "Lesson 3: Building a Password Strength Checker"),
            ("policy",            "Lesson 4: Password Policy Best Practices"),
            ("quiz",              "Take the Quiz"),
        ])
        if choice == "back":
            return
        if choice == "quit":
            raise SystemExit

        if choice == "hashing":
            lesson_hashing(progress, module_key)
        elif choice == "cracking":
            lesson_cracking(progress, module_key)
        elif choice == "strength_checker":
            lesson_strength_checker(progress, module_key)
        elif choice == "policy":
            lesson_policy(progress, module_key)
        elif choice == "quiz":
            _run_quiz(progress, module_key)


# ─────────────────────────────────────────────────────────────────────────────
# Lesson 1 — Hashing Algorithms
# ─────────────────────────────────────────────────────────────────────────────

def lesson_hashing(progress, module_key):
    section_header("Lesson 1: Hashing Algorithms")
    learning_goal([
        "Understand what hash functions are and their key properties",
        "Learn why MD5 and SHA-1 are not safe for passwords",
        "Know why bcrypt and Argon2 are the recommended choices",
        "See hashing in action with live demos",
    ])
    disclaimer()

    lesson_block(
        "A hash function takes any input and produces a fixed-size output (the "
        "hash or digest). Cryptographic hash functions have three key properties:"
    )
    pace()

    lesson_block(
        "(1) Deterministic -- the same input always gives the same output. "
        "(2) One-way -- you cannot reverse the hash back to the input. "
        "(3) Collision-resistant -- it is very hard to find two different inputs "
        "that produce the same hash."
    )

    why_it_matters(
        "Passwords should NEVER be stored in plaintext. If a database is breached, "
        "properly hashed passwords buy time for users to change credentials. "
        "Fast algorithms like MD5 can be cracked at billions of attempts per "
        "second, while slow algorithms like bcrypt are designed to resist this."
    )

    pace()
    press_enter()

    # ── MD5 ──
    sub_header("MD5 -- Fast and Broken")
    lesson_block(
        "MD5 produces a 128-bit hash displayed as a 32-character hex string. "
        "It was designed for speed and is used in checksums. However, MD5 is "
        "CRYPTOGRAPHICALLY BROKEN -- collision attacks have been practical since "
        "2004. NEVER use MD5 for password hashing."
    )
    pace()

    # ── SHA-1 ──
    sub_header("SHA-1 -- Deprecated")
    lesson_block(
        "SHA-1 produces a 160-bit hash. While stronger than MD5, collision "
        "attacks were demonstrated by Google's SHAttered project in 2017. Like "
        "MD5, it is far too fast for password hashing."
    )
    pace()

    # ── SHA-256 ──
    sub_header("SHA-256 -- Secure for Integrity, Not for Passwords")
    lesson_block(
        "SHA-256 produces a 256-bit hash and is secure against collision attacks. "
        "It is used in TLS certificates and digital signatures."
    )
    lesson_block(
        "However, SHA-256 is still a fast hash -- billions of hashes per second "
        "on a GPU. For passwords, you need an intentionally SLOW algorithm."
    )
    tip("Speed is great for file verification but terrible for password storage.")
    pace()

    press_enter()

    # ── bcrypt ──
    sub_header("bcrypt -- Purpose-Built for Passwords")
    lesson_block(
        "bcrypt is a password hashing function designed to be slow on purpose. "
        "It has a configurable 'work factor' that controls how expensive it is "
        "to compute. As hardware gets faster, you increase the work factor."
    )
    lesson_block(
        "bcrypt also automatically generates and includes a random salt, "
        "preventing rainbow table attacks."
    )
    pace()

    code_block(
        "# bcrypt hash structure:\n"
        "# $2b$12$LJ3m4ys3Lf.Zy2W3YKhxqOJz1jD6vHvyd5QzE8Wm9sBhY2jNGXDC\n"
        "#  |  |  |                    |                                |\n"
        "#  |  |  |                    +-- 22-char salt (base64)       |\n"
        "#  |  |  +-- cost factor (2^12 = 4096 iterations)             |\n"
        "#  |  +-- algorithm version                                    |\n"
        "#  +-- prefix ($2b$ = bcrypt)                                  |",
        "text"
    )
    pace()

    nice_work("bcrypt is a great choice -- now let's see the newest option.")

    # ── Argon2 ──
    sub_header("Argon2 -- The Modern Gold Standard")
    lesson_block(
        "Argon2 won the 2015 Password Hashing Competition and is the recommended "
        "algorithm for new projects. It is memory-hard, meaning it needs a lot "
        "of RAM to compute, making it resistant to GPU and ASIC-based cracking."
    )
    lesson_block(
        "Argon2 has three variants: Argon2d (resists GPU attacks), Argon2i "
        "(resists side-channel attacks), and Argon2id (hybrid -- recommended "
        "for password hashing)."
    )
    pace()

    press_enter()

    # ── Salting explained ──
    sub_header("What Is a Salt and Why It Matters")
    lesson_block(
        "A salt is a random value combined with the password before hashing. "
        "Each user gets a unique salt, so even if two users have the same "
        "password, their hashes will be different."
    )
    lesson_block(
        "Salting defeats rainbow tables (massive lookup tables of hash-to-password "
        "mappings). The salt does not need to be secret -- it is stored alongside "
        "the hash. Its purpose is to ensure uniqueness."
    )
    pace()

    code_block(
        '# Without salt — identical passwords produce identical hashes:\n'
        '#   hash("password123") -> 482c811da5d5b4bc6d497ffa...\n'
        '#   hash("password123") -> 482c811da5d5b4bc6d497ffa...  (same!)\n'
        '#\n'
        '# With unique salts — identical passwords produce different hashes:\n'
        '#   hash("password123" + "a1b2c3") -> 9f4e2c1d8a7b3e5f...\n'
        '#   hash("password123" + "x7y8z9") -> 3d7a8b2e1c9f4d6a...  (different!)',
        "text"
    )
    tip("bcrypt and Argon2 handle salting automatically -- you do not need to manage salts yourself.")
    pace()

    press_enter()

    # ── Live demo ──
    sub_header("Live Demo: Hashing in Action")
    info("Let's see each algorithm hash the same input in real time.\n")
    pace()

    demo_password = "JJsLab2025!"
    info(f"Test password: {Y}{demo_password}{RESET}\n")

    # MD5
    md5_start = time.perf_counter()
    md5_hash = hashlib.md5(demo_password.encode()).hexdigest()
    md5_time = time.perf_counter() - md5_start
    print(f"  {R}MD5{RESET}     {md5_hash}")
    print(f"          Time: {md5_time*1_000_000:.1f} microseconds")
    print(f"          Length: {len(md5_hash)} chars (128 bits)")
    print(f"          Status: {R}BROKEN — never use for passwords{RESET}\n")

    # SHA-1
    sha1_start = time.perf_counter()
    sha1_hash = hashlib.sha1(demo_password.encode()).hexdigest()
    sha1_time = time.perf_counter() - sha1_start
    print(f"  {Y}SHA-1{RESET}   {sha1_hash}")
    print(f"          Time: {sha1_time*1_000_000:.1f} microseconds")
    print(f"          Length: {len(sha1_hash)} chars (160 bits)")
    print(f"          Status: {Y}DEPRECATED — collision attacks exist{RESET}\n")

    # SHA-256
    sha256_start = time.perf_counter()
    sha256_hash = hashlib.sha256(demo_password.encode()).hexdigest()
    sha256_time = time.perf_counter() - sha256_start
    print(f"  {C}SHA-256{RESET} {sha256_hash}")
    print(f"          Time: {sha256_time*1_000_000:.1f} microseconds")
    print(f"          Length: {len(sha256_hash)} chars (256 bits)")
    print(f"          Status: {C}Secure for integrity, too fast for passwords{RESET}\n")

    # SHA-256 with salt
    salt = os.urandom(16).hex()
    sha256s_start = time.perf_counter()
    sha256_salted = hashlib.sha256((salt + demo_password).encode()).hexdigest()
    sha256s_time = time.perf_counter() - sha256s_start
    print(f"  {C}SHA-256{RESET} {sha256_salted}")
    print(f"  {C}+salt{RESET}   Salt: {salt}")
    print(f"          Time: {sha256s_time*1_000_000:.1f} microseconds")
    print(f"          Status: {C}Better, but still too fast for passwords{RESET}\n")

    pace()

    # bcrypt (if available)
    try:
        import bcrypt as bcrypt_lib
        bcrypt_start = time.perf_counter()
        bcrypt_hash = bcrypt_lib.hashpw(demo_password.encode(), bcrypt_lib.gensalt(rounds=12))
        bcrypt_time = time.perf_counter() - bcrypt_start
        print(f"  {G}bcrypt{RESET}  {bcrypt_hash.decode()}")
        print(f"          Time: {bcrypt_time*1000:.1f} milliseconds (cost=12)")
        print(f"          Status: {G}RECOMMENDED — intentionally slow{RESET}\n")
    except ImportError:
        print(f"  {Y}bcrypt{RESET}  [Not installed — run: pip install bcrypt]")
        print(f"          Status: {G}RECOMMENDED — intentionally slow{RESET}\n")

    # argon2 (if available)
    try:
        from argon2 import PasswordHasher
        ph = PasswordHasher()
        argon2_start = time.perf_counter()
        argon2_hash = ph.hash(demo_password)
        argon2_time = time.perf_counter() - argon2_start
        print(f"  {G}Argon2{RESET}  {argon2_hash[:70]}...")
        print(f"          Time: {argon2_time*1000:.1f} milliseconds")
        print(f"          Status: {G}GOLD STANDARD — memory-hard, GPU-resistant{RESET}\n")
    except ImportError:
        print(f"  {Y}Argon2{RESET}  [Not installed — run: pip install argon2-cffi]")
        print(f"          Status: {G}GOLD STANDARD — memory-hard, GPU-resistant{RESET}\n")

    nice_work("See the speed difference? That slowness is what protects passwords!")
    pace()
    press_enter()

    # ── Interactive hashing ──
    sub_header("Try It Yourself")
    info("Enter a string to hash with multiple algorithms.")
    print()
    user_input = input(f"  {C}Enter a string to hash (or press Enter to skip): {RESET}").strip()
    if user_input:
        print()
        print(f"  Input:   {Y}{user_input}{RESET}")
        print(f"  MD5:     {hashlib.md5(user_input.encode()).hexdigest()}")
        print(f"  SHA-1:   {hashlib.sha1(user_input.encode()).hexdigest()}")
        print(f"  SHA-256: {hashlib.sha256(user_input.encode()).hexdigest()}")

        # Show how a single character change completely changes the hash
        altered = user_input + "!"
        print(f"\n  Now with one extra character ('{altered}'):")
        print(f"  SHA-256: {hashlib.sha256(altered.encode()).hexdigest()}")
        info("Notice the hash is completely different — this is the 'avalanche effect'.")
    print()

    press_enter()

    pace()

    # ── Comparison table ──
    sub_header("Algorithm Comparison Summary")
    print(f"  {'Algorithm':<12} {'Output':<10} {'Speed':<14} {'Password Use':<16} {'Status'}")
    print(f"  {'─'*12} {'─'*10} {'─'*14} {'─'*16} {'─'*20}")
    print(f"  {'MD5':<12} {'128 bit':<10} {'Very fast':<14} {R}{'NEVER':<16}{RESET} {'Broken'}")
    print(f"  {'SHA-1':<12} {'160 bit':<10} {'Very fast':<14} {R}{'NEVER':<16}{RESET} {'Deprecated'}")
    print(f"  {'SHA-256':<12} {'256 bit':<10} {'Fast':<14} {Y}{'Not ideal':<16}{RESET} {'Secure (integrity)'}")
    print(f"  {'bcrypt':<12} {'184 bit':<10} {'Slow (tunable)':<14} {G}{'RECOMMENDED':<16}{RESET} {'Proven'}")
    print(f"  {'Argon2id':<12} {'Variable':<10} {'Slow (tunable)':<14} {G}{'BEST':<16}{RESET} {'Gold standard'}")
    print()
    pace()

    # ── Code example for proper storage ──
    sub_header("Proper Password Storage Code")
    lesson_block("Here is how to hash and verify passwords with bcrypt in Python:")
    code_block(
        'import bcrypt\n'
        '\n'
        'def hash_password(plain_password: str) -> str:\n'
        '    """Hash a password using bcrypt with automatic salting."""\n'
        '    salt = bcrypt.gensalt(rounds=12)  # 2^12 iterations\n'
        '    hashed = bcrypt.hashpw(plain_password.encode("utf-8"), salt)\n'
        '    return hashed.decode("utf-8")\n'
        '\n'
        'def verify_password(plain_password: str, hashed_password: str) -> bool:\n'
        '    """Verify a password against a stored bcrypt hash."""\n'
        '    return bcrypt.checkpw(\n'
        '        plain_password.encode("utf-8"),\n'
        '        hashed_password.encode("utf-8")\n'
        '    )',
        "python"
    )
    pace()

    code_block(
        '# Usage:\n'
        'stored_hash = hash_password("my_secure_password")\n'
        'print(f"Stored: {stored_hash}")\n'
        '\n'
        'print(verify_password("my_secure_password", stored_hash))   # True\n'
        'print(verify_password("wrong_password", stored_hash))        # False',
        "python"
    )
    tip("This pattern works for any web app -- just store the hash and verify on login.")
    pace()

    press_enter()

    # ── Scenario ──
    scenario_block(
        "LinkedIn Breach (2012 / 2016)",
        "In 2012, 6.5 million LinkedIn password hashes were leaked online. "
        "LinkedIn had stored passwords using unsalted SHA-1, making them trivial "
        "to crack with rainbow tables. In 2016, it was revealed that the breach "
        "actually affected 117 million accounts. Over 90% of the hashes were "
        "cracked within 72 hours. Had LinkedIn used bcrypt with proper salting, "
        "cracking would have taken years instead of hours."
    )
    pace()

    # ── Practice challenge ──
    sub_header("Practice Challenge: Hash and Compare")
    info("1. Hash the string 'JJsLab' with MD5, SHA-256, and bcrypt.")
    info("2. Change one character and observe the avalanche effect.")
    info("3. Measure the time difference between SHA-256 and bcrypt.")
    info("4. Explain in your own words why bcrypt is preferred for passwords.")
    print()
    hint_text("Use the time module to measure: start = time.time(); ...; elapsed = time.time() - start")
    hint_text("bcrypt should be thousands of times slower than SHA-256.")

    if ask_yes_no("Did you complete the hashing comparison exercise?"):
        success("You now understand why algorithm choice matters for password storage.")
        mark_lesson_complete(progress, module_key, "hashing")
        mark_challenge_complete(progress, module_key, "hashing_comparison")
    else:
        info("Come back after trying the exercise. It only takes a few minutes.")

    press_enter()


# ─────────────────────────────────────────────────────────────────────────────
# Lesson 2 — Password Cracking Concepts
# ─────────────────────────────────────────────────────────────────────────────

def lesson_cracking(progress, module_key):
    section_header("Lesson 2: Password Cracking Concepts")
    learning_goal([
        "Understand brute-force, dictionary, and rainbow table attacks",
        "See the math behind password cracking speed",
        "Build and run a simple password cracker",
    ])
    disclaimer()

    warning("IMPORTANT: Only crack hashes you generated yourself for learning.")
    warning("Cracking passwords from stolen databases is illegal and unethical.")
    print()

    lesson_block(
        "Password cracking is the process of recovering plaintext passwords from "
        "their hashes. Security professionals study cracking to understand how "
        "attackers work and to test password policies."
    )
    pace()

    lesson_block(
        "There are three primary approaches: brute-force, dictionary attacks, "
        "and rainbow tables."
    )

    why_it_matters(
        "Understanding how passwords are cracked helps you design better "
        "policies, choose good hashing algorithms, and assess risk when a "
        "database of hashes is leaked."
    )

    pace()
    press_enter()

    # ── Brute-force ──
    sub_header("Brute-Force Attacks")
    lesson_block(
        "A brute-force attack tries every possible combination of characters "
        "until the correct password is found. For lowercase letters only, a "
        "6-character password has 26^6 = 308 million combinations."
    )
    lesson_block(
        "Adding uppercase, digits, and symbols expands the character set to 95+, "
        "making longer passwords exponentially harder to crack."
    )
    pace()

    # ── Brute-force math ──
    sub_header("The Math of Brute-Force")
    charsets = [
        ("Digits only (0-9)", 10),
        ("Lowercase (a-z)", 26),
        ("Lower + Upper (a-zA-Z)", 52),
        ("Alphanumeric (a-zA-Z0-9)", 62),
        ("All printable ASCII", 95),
    ]
    print(f"  {'Character Set':<30} {'6-char':<16} {'8-char':<16} {'12-char':<20}")
    print(f"  {'─'*30} {'─'*16} {'─'*16} {'─'*20}")
    for name, size in charsets:
        c6 = size ** 6
        c8 = size ** 8
        c12 = size ** 12
        print(f"  {name:<30} {c6:<16,} {c8:<16,} {c12:<20,}")
    print()
    pace()

    info("At 10 billion hashes/sec (modern GPU with MD5):")
    for name, size in charsets:
        c8 = size ** 8
        seconds = c8 / 10_000_000_000
        if seconds < 1:
            time_str = f"{seconds*1000:.1f} milliseconds"
        elif seconds < 60:
            time_str = f"{seconds:.1f} seconds"
        elif seconds < 3600:
            time_str = f"{seconds/60:.1f} minutes"
        elif seconds < 86400:
            time_str = f"{seconds/3600:.1f} hours"
        elif seconds < 31536000:
            time_str = f"{seconds/86400:.1f} days"
        else:
            time_str = f"{seconds/31536000:.1f} years"
        print(f"    8-char {name:<30} -> {time_str}")
    print()
    tip("Notice how adding character types makes a huge difference in cracking time.")
    pace()

    press_enter()

    # ── Dictionary attacks ──
    sub_header("Dictionary Attacks")
    lesson_block(
        "A dictionary attack uses a pre-compiled list of likely passwords -- "
        "common words, leaked passwords, and variations. This is much faster "
        "than brute-force because humans use predictable passwords."
    )
    lesson_block(
        "Popular wordlists include RockYou (14 million passwords), SecLists, and "
        "CrackStation's dictionary. Attackers also apply rules like appending "
        "numbers and l33tspeak substitutions."
    )
    pace()

    code_block(
        '# Common password variations that dictionary attacks try:\n'
        '# Base word: "password"\n'
        '# Variations:\n'
        '#   password, Password, PASSWORD\n'
        '#   password1, password123, password!\n'
        '#   p@ssword, p@55w0rd, p@$$w0rd\n'
        '#   password2024, password2025\n'
        '#   drowssap (reversed)',
        "text"
    )

    nice_work("You can see why common passwords fall so quickly!")
    pace()
    press_enter()

    # ── Rainbow tables ──
    sub_header("Rainbow Tables")
    lesson_block(
        "A rainbow table is a precomputed lookup table that maps hashes back to "
        "their plaintext inputs. Instead of hashing each guess at crack-time, "
        "the attacker just looks up the target hash. This allows near-instant "
        "password recovery."
    )
    lesson_block(
        "The key defense against rainbow tables is SALTING -- a salt makes each "
        "hash unique, so the attacker would need a separate table for every "
        "possible salt value, which is infeasible."
    )
    pace()

    code_block(
        '# Rainbow table concept:\n'
        '# Precomputed table (unsalted MD5):\n'
        '#   "password"    -> 5f4dcc3b5aa765d61d8327deb882cf99\n'
        '#   "123456"      -> e10adc3949ba59abbe56e057f20f883e\n'
        '#   "letmein"     -> 0d107d09f5bbe40cade3de5c71e9e9b7\n'
        '#   ... millions more entries ...\n'
        '#\n'
        '# Lookup: given hash e10adc3949ba59abbe56e057f20f883e\n'
        '#   -> instant match: "123456"\n'
        '#\n'
        '# With salt: hash = MD5(salt + password)\n'
        '#   Different salt = different hash = rainbow table is useless',
        "text"
    )
    pace()

    press_enter()

    # ── Build a simple cracker ──
    sub_header("Hands-On: Build a Simple Password Cracker")
    warning("This cracker works ONLY against test hashes you generate yourself.")
    print()

    lesson_block(
        "Let's build a simple cracker that shows both dictionary and brute-force "
        "approaches. First, the dictionary attack:"
    )

    code_block(
        'import hashlib\n'
        'import itertools\n'
        'import string\n'
        'import time\n'
        '\n'
        '# ─── Generate a test hash to crack ───\n'
        'test_password = "cat42"\n'
        'target_hash = hashlib.sha256(test_password.encode()).hexdigest()\n'
        'print(f"Target hash (SHA-256 of a secret word): {target_hash}")\n'
        '\n'
        '# ─── Dictionary attack ───\n'
        'def dictionary_attack(target_hash, wordlist):\n'
        '    """Try each word in the wordlist."""\n'
        '    for word in wordlist:\n'
        '        if hashlib.sha256(word.encode()).hexdigest() == target_hash:\n'
        '            return word\n'
        '    return None',
        "python"
    )
    pace()

    code_block(
        'mini_wordlist = [\n'
        '    "password", "123456", "admin", "letmein", "welcome",\n'
        '    "monkey", "dragon", "master", "cat42", "abc123",\n'
        '    "iloveyou", "trustno1", "sunshine", "princess",\n'
        ']\n'
        '\n'
        'start = time.time()\n'
        'result = dictionary_attack(target_hash, mini_wordlist)\n'
        'elapsed = time.time() - start\n'
        'if result:\n'
        '    print(f"[+] Dictionary attack found: {result} in {elapsed:.4f}s")\n'
        'else:\n'
        '    print(f"[-] Not found in dictionary ({elapsed:.4f}s)")',
        "python"
    )
    pace()

    lesson_block("Now the brute-force approach, which tries every combination:")
    code_block(
        '# ─── Brute-force attack (short passwords only) ───\n'
        'def brute_force_attack(target_hash, charset, max_length=4):\n'
        '    """Try all combinations up to max_length."""\n'
        '    attempts = 0\n'
        '    for length in range(1, max_length + 1):\n'
        '        for combo in itertools.product(charset, repeat=length):\n'
        '            attempts += 1\n'
        '            candidate = "".join(combo)\n'
        '            if hashlib.sha256(candidate.encode()).hexdigest() == target_hash:\n'
        '                return candidate, attempts\n'
        '    return None, attempts',
        "python"
    )
    pace()

    code_block(
        '# Try brute-forcing a short password\n'
        'short_pw = "zap"\n'
        'short_hash = hashlib.sha256(short_pw.encode()).hexdigest()\n'
        'start = time.time()\n'
        'found, attempts = brute_force_attack(short_hash, string.ascii_lowercase, 3)\n'
        'elapsed = time.time() - start\n'
        'if found:\n'
        '    print(f"[+] Brute-force found: {found} in {attempts:,} attempts ({elapsed:.2f}s)")\n'
        'else:\n'
        '    print(f"[-] Not found in {attempts:,} attempts ({elapsed:.2f}s)")',
        "python"
    )
    pace()

    press_enter()

    # ── Live mini-cracker demo ──
    sub_header("Live Demo: Mini Dictionary Cracker")
    info("We will hash a test password and try to crack it with a small wordlist.\n")
    pace()

    # Generate a test hash
    test_passwords = ["sunshine", "dragon", "master", "hello", "shadow"]
    import random
    secret = random.choice(test_passwords)
    target = hashlib.sha256(secret.encode()).hexdigest()

    print(f"  Target hash: {Y}{target}{RESET}")
    print(f"  Algorithm:   SHA-256")
    print(f"  Attempting dictionary attack...\n")

    wordlist = [
        "password", "123456", "qwerty", "admin", "letmein", "welcome",
        "monkey", "dragon", "master", "abc123", "iloveyou", "trustno1",
        "sunshine", "princess", "football", "charlie", "shadow", "michael",
        "hello", "ranger", "batman", "access", "thunder", "whatever",
    ]

    attempts = 0
    start = time.perf_counter()
    cracked = None
    for word in wordlist:
        attempts += 1
        candidate_hash = hashlib.sha256(word.encode()).hexdigest()
        if candidate_hash == target:
            cracked = word
            break

    elapsed = time.perf_counter() - start

    if cracked:
        success(f"Cracked! Password: '{cracked}' (attempt #{attempts}, {elapsed*1000:.2f} ms)")
    else:
        warning(f"Not found in {attempts} attempts ({elapsed*1000:.2f} ms)")

    print()
    info(f"Hash rate: ~{int(attempts / elapsed):,} hashes/second (single-threaded Python)")
    info("A GPU-based tool like Hashcat achieves billions of hashes/second on MD5.")
    pace()

    lesson_block(
        "This shows why password complexity matters -- a common dictionary word "
        "is cracked instantly. With massive wordlists and GPU acceleration, "
        "simple passwords do not survive a breach."
    )

    nice_work("You just saw a dictionary attack in action!")
    pace()
    press_enter()

    # ── Live brute-force demo ──
    sub_header("Live Demo: Mini Brute-Force Cracker")
    info("Now let's brute-force a short password to show how time scales.\n")
    pace()

    import itertools
    bf_password = "hi"
    bf_target = hashlib.sha256(bf_password.encode()).hexdigest()
    print(f"  Target hash: {Y}{bf_target}{RESET}")
    print(f"  Charset:     lowercase a-z")
    print(f"  Max length:  3 characters")
    print(f"  Brute-forcing...\n")

    bf_attempts = 0
    bf_start = time.perf_counter()
    bf_cracked = None
    for length in range(1, 4):
        for combo in itertools.product(string.ascii_lowercase, repeat=length):
            bf_attempts += 1
            candidate = "".join(combo)
            if hashlib.sha256(candidate.encode()).hexdigest() == bf_target:
                bf_cracked = candidate
                break
        if bf_cracked:
            break

    bf_elapsed = time.perf_counter() - bf_start

    if bf_cracked:
        success(f"Cracked! Password: '{bf_cracked}' (attempt #{bf_attempts:,}, {bf_elapsed*1000:.1f} ms)")
    else:
        warning(f"Not found in {bf_attempts:,} attempts ({bf_elapsed*1000:.1f} ms)")

    total_combos = sum(26**i for i in range(1, 4))
    print(f"\n  Total combinations tried: {bf_attempts:,} / {total_combos:,}")
    info("With full printable ASCII and longer passwords, the search space explodes.")
    tip("Even adding just a few more characters makes brute-force take exponentially longer.")
    pace()

    press_enter()

    # ── Scenario ──
    scenario_block(
        "RockYou Breach (2009)",
        "RockYou, a social app developer, stored 32 million user passwords in "
        "PLAINTEXT. When the database was stolen, no cracking was even needed. "
        "The leaked list revealed that the most common password was '123456' "
        "(used by nearly 300,000 users), followed by '12345', '123456789', "
        "'password', and 'iloveyou'. This wordlist is now the most widely used "
        "dictionary for password cracking research."
    )
    pace()

    # ── Practice challenge ──
    sub_header("Practice Challenge: Crack Your Own Test Hashes")
    info("1. Generate SHA-256 hashes of 5 passwords of varying strength:")
    info("   - A 4-letter lowercase word (e.g., 'test')")
    info("   - A common dictionary word (e.g., 'monkey')")
    info("   - A word with a number appended (e.g., 'monkey1')")
    info("   - A 12-character random passphrase (e.g., 'correct-horse')")
    info("   - A 16-character random string (e.g., 'kX9$mP2!qR7&vL4@')")
    info("2. Try cracking each hash using the code above.")
    info("3. Record which ones you can crack and how long each takes.")
    print()
    hint_text("Shorter and simpler passwords fall to brute-force or dictionary attacks.")
    hint_text("Random, long passwords should be effectively uncrackable with these tools.")

    if ask_yes_no("Did you complete the cracking exercise with your own test hashes?"):
        success("Excellent! You now have hands-on insight into password cracking.")
        mark_lesson_complete(progress, module_key, "cracking")
        mark_challenge_complete(progress, module_key, "cracking_exercise")
    else:
        info("Take your time — this exercise builds important intuition.")

    press_enter()


# ─────────────────────────────────────────────────────────────────────────────
# Lesson 3 — Building a Password Strength Checker
# ─────────────────────────────────────────────────────────────────────────────

def lesson_strength_checker(progress, module_key):
    section_header("Lesson 3: Building a Password Strength Checker")
    learning_goal([
        "Understand password entropy and what makes a password strong",
        "Build a strength checker with scoring and feedback",
        "Try the live checker with your own passwords",
    ])
    disclaimer()

    lesson_block(
        "A password strength checker evaluates how resistant a password is to "
        "cracking. Good checkers go beyond simple rules and consider entropy, "
        "dictionary words, and common patterns."
    )
    pace()

    lesson_block(
        "In this lesson, we will build a comprehensive strength checker from "
        "scratch."
    )

    why_it_matters(
        "Users choose weak passwords unless guided by feedback. A real-time "
        "strength meter nudges them toward stronger passwords. Tools like zxcvbn "
        "(by Dropbox) have shown that pattern-based analysis is far more accurate "
        "than rigid complexity rules."
    )

    pace()
    press_enter()

    # ── Entropy ──
    sub_header("Entropy: Measuring Password Randomness")
    lesson_block(
        "Entropy measures the number of possible combinations, expressed in bits. "
        "A password with N bits of entropy has 2^N possible values. The formula: "
        "entropy = length * log2(charset_size)."
    )
    tip("Example: 10 lowercase letters = 10 * log2(26) = about 47 bits of entropy.")
    pace()

    code_block(
        'import math\n'
        'import string\n'
        '\n'
        'def calculate_entropy(password: str) -> float:\n'
        '    """Calculate the entropy of a password based on its character classes."""\n'
        '    charset_size = 0\n'
        '    if any(c in string.ascii_lowercase for c in password):\n'
        '        charset_size += 26\n'
        '    if any(c in string.ascii_uppercase for c in password):\n'
        '        charset_size += 26\n'
        '    if any(c in string.digits for c in password):\n'
        '        charset_size += 10\n'
        '    if any(c in string.punctuation for c in password):\n'
        '        charset_size += 32\n'
        '    if any(c == " " for c in password):\n'
        '        charset_size += 1',
        "python"
    )
    pace()

    code_block(
        '    if charset_size == 0:\n'
        '        return 0.0\n'
        '\n'
        '    entropy = len(password) * math.log2(charset_size)\n'
        '    return round(entropy, 1)\n'
        '\n'
        '# Examples:\n'
        'print(calculate_entropy("password"))      # ~37.6 bits (weak)\n'
        'print(calculate_entropy("P@ssw0rd!"))     # ~59.4 bits (moderate)\n'
        'print(calculate_entropy("correct horse battery staple"))  # ~148 bits (strong)',
        "python"
    )
    pace()

    press_enter()

    # ── Common password check ──
    sub_header("Checking Against Common Passwords")
    lesson_block(
        "Even a password with high theoretical entropy is weak if it appears "
        "in a list of commonly used passwords. A good strength checker compares "
        "the candidate against such a list."
    )
    pace()

    code_block(
        '# A small sample of the most common passwords\n'
        'COMMON_PASSWORDS = {\n'
        '    "123456", "password", "123456789", "12345678", "12345",\n'
        '    "1234567", "1234567890", "qwerty", "abc123", "111111",\n'
        '    "password1", "iloveyou", "1q2w3e4r", "000000", "qwerty123",\n'
        '    "zaq12wsx", "dragon", "sunshine", "princess", "letmein",\n'
        '    "654321", "monkey", "27653", "1qaz2wsx", "123321",\n'
        '    "qwertyuiop", "superman", "asdfghjkl", "welcome", "admin",\n'
        '    "football", "shadow", "master", "michael", "trustno1",\n'
        '    "batman", "access", "hello", "charlie", "thunder",\n'
        '    "Summer2024", "P@ssw0rd", "Baseball1", "Football1",\n'
        '}',
        "python"
    )
    pace()

    code_block(
        'def is_common_password(password: str) -> bool:\n'
        '    """Check if the password is in the common passwords list."""\n'
        '    return password.lower() in {p.lower() for p in COMMON_PASSWORDS}',
        "python"
    )

    nice_work("Two key building blocks done -- entropy and common password check!")
    pace()
    press_enter()

    # ── Pattern detection ──
    sub_header("Pattern and Complexity Detection")
    lesson_block("Now let's detect common weak patterns like keyboard sequences and repeated characters:")

    code_block(
        'import re\n'
        '\n'
        'def detect_patterns(password: str) -> list[str]:\n'
        '    """Detect common weak patterns in a password."""\n'
        '    issues = []\n'
        '\n'
        '    # Length check\n'
        '    if len(password) < 8:\n'
        '        issues.append("Too short (minimum 8 characters recommended)")\n'
        '    if len(password) < 12:\n'
        '        issues.append("Consider 12+ characters for strong security")\n'
        '\n'
        '    # Character class checks\n'
        '    if not re.search(r"[a-z]", password):\n'
        '        issues.append("No lowercase letters")\n'
        '    if not re.search(r"[A-Z]", password):\n'
        '        issues.append("No uppercase letters")\n'
        '    if not re.search(r"[0-9]", password):\n'
        '        issues.append("No digits")\n'
        '    if not re.search(r"[!@#$%^&*()_+\\-=\\[\\]{}|;:,.<>?/~`]", password):\n'
        '        issues.append("No special characters")',
        "python"
    )
    pace()

    code_block(
        '    # Repeated characters\n'
        '    if re.search(r"(.)\\1{2,}", password):\n'
        '        issues.append("Contains repeated characters (e.g., aaa)")\n'
        '\n'
        '    # Sequential characters\n'
        '    sequences = ["abcdef", "123456", "qwerty", "asdf", "zxcv"]\n'
        '    for seq in sequences:\n'
        '        if seq in password.lower():\n'
        '            issues.append(f"Contains keyboard sequence: {seq}")\n'
        '\n'
        '    # Common substitutions (l33tspeak)\n'
        '    desubbed = password.lower()\n'
        '    for old, new in [("@", "a"), ("0", "o"), ("1", "i"), ("3", "e"),\n'
        '                     ("$", "s"), ("!", "i"), ("5", "s")]:\n'
        '        desubbed = desubbed.replace(old, new)\n'
        '    if desubbed != password.lower() and desubbed in COMMON_PASSWORDS_LOWER:\n'
        '        issues.append("Common password with character substitutions")\n'
        '\n'
        '    return issues',
        "python"
    )
    pace()

    press_enter()

    # ── Full scoring system ──
    sub_header("Complete Scoring System")
    lesson_block(
        "Let's combine entropy, common password checks, and pattern detection "
        "into a unified scoring system (0 to 100)."
    )
    pace()

    code_block(
        'def score_password(password: str) -> dict:\n'
        '    """Score a password from 0 to 100 with detailed feedback."""\n'
        '    score = 0\n'
        '    feedback = []\n'
        '\n'
        '    # --- Entropy-based scoring (up to 40 points) ---\n'
        '    entropy = calculate_entropy(password)\n'
        '    entropy_score = min(40, int(entropy * 40 / 80))  # 80 bits = full marks\n'
        '    score += entropy_score\n'
        '    feedback.append(f"Entropy: {entropy:.1f} bits ({entropy_score}/40 points)")\n'
        '\n'
        '    # --- Length scoring (up to 25 points) ---\n'
        '    length_score = min(25, len(password) * 25 // 20)  # 20+ chars = full marks\n'
        '    score += length_score\n'
        '    feedback.append(f"Length: {len(password)} chars ({length_score}/25 points)")',
        "python"
    )
    pace()

    code_block(
        '    # --- Character variety (up to 20 points) ---\n'
        '    variety = 0\n'
        '    if re.search(r"[a-z]", password): variety += 1\n'
        '    if re.search(r"[A-Z]", password): variety += 1\n'
        '    if re.search(r"[0-9]", password): variety += 1\n'
        '    if re.search(r"[^a-zA-Z0-9]", password): variety += 1\n'
        '    variety_score = variety * 5\n'
        '    score += variety_score\n'
        '    feedback.append(f"Character variety: {variety}/4 types ({variety_score}/20 points)")\n'
        '\n'
        '    # --- Penalties (up to -30 points) ---\n'
        '    penalties = 0\n'
        '    if is_common_password(password):\n'
        '        penalties += 30\n'
        '        feedback.append("PENALTY: Common password (-30)")\n'
        '    issues = detect_patterns(password)\n'
        '    penalties += min(15, len(issues) * 3)\n'
        '    for issue in issues:\n'
        '        feedback.append(f"Issue: {issue}")',
        "python"
    )
    pace()

    code_block(
        '    # --- No bonus points beyond 15 (prevents gaming) ---\n'
        '    bonus = 0\n'
        '    if len(password) >= 16 and variety >= 3:\n'
        '        bonus = 15\n'
        '        feedback.append(f"BONUS: Long + varied ({bonus} points)")\n'
        '\n'
        '    final_score = max(0, min(100, score - penalties + bonus))\n'
        '\n'
        '    # Rating\n'
        '    if final_score >= 80:\n'
        '        rating = "STRONG"\n'
        '    elif final_score >= 60:\n'
        '        rating = "MODERATE"\n'
        '    elif final_score >= 40:\n'
        '        rating = "WEAK"\n'
        '    else:\n'
        '        rating = "VERY WEAK"\n'
        '\n'
        '    return {\n'
        '        "score": final_score,\n'
        '        "rating": rating,\n'
        '        "entropy": entropy,\n'
        '        "feedback": feedback,\n'
        '    }',
        "python"
    )

    nice_work("You have built a complete password scoring system!")
    pace()
    press_enter()

    # ── Live strength checker ──
    sub_header("Live Password Strength Checker")
    info("Try the built-in strength checker right now.\n")

    # Demonstrate with sample passwords first
    samples = [
        "123456",
        "password",
        "Monkey42!",
        "correct horse battery staple",
        "kX9$mP2!qR7&vL4@Zy",
    ]

    print(f"  {'Password':<35} {'Score':<8} {'Entropy':<12} {'Rating'}")
    print(f"  {'─'*35} {'─'*8} {'─'*12} {'─'*15}")
    for pw in samples:
        result = _score_password(pw)
        color = G if result["rating"] == "STRONG" else (Y if result["rating"] == "MODERATE" else R)
        display_pw = pw if len(pw) <= 30 else pw[:27] + "..."
        print(f"  {display_pw:<35} {color}{result['score']:<8}{RESET} "
              f"{result['entropy']:<12.1f} {color}{result['rating']}{RESET}")
    print()

    press_enter()

    # Interactive checker
    sub_header("Try Your Own Passwords")
    while True:
        user_pw = input(f"  {C}Enter a password to check (or 'done' to continue): {RESET}").strip()
        if user_pw.lower() == "done" or not user_pw:
            break

        result = _score_password(user_pw)
        color = G if result["rating"] == "STRONG" else (Y if result["rating"] == "MODERATE" else R)

        print(f"\n  Score: {color}{BRIGHT}{result['score']}/100 — {result['rating']}{RESET}")
        print(f"  Entropy: {result['entropy']:.1f} bits")
        print(f"  Feedback:")
        for fb in result["feedback"]:
            print(f"    - {fb}")
        print()

    press_enter()

    # ── Scenario ──
    scenario_block(
        "Dropbox's zxcvbn (2012)",
        "Dropbox created zxcvbn, an open-source password strength estimator that "
        "analyzes passwords using pattern matching instead of rigid rules. It "
        "detects dictionary words, common names, keyboard patterns, dates, "
        "l33tspeak substitutions, and spatial sequences. zxcvbn estimates the "
        "number of guesses an attacker would need, providing far more accurate "
        "strength measurement than traditional 'must contain uppercase + digit + "
        "symbol' rules. It has been adopted by many major services."
    )

    # ── Practice challenge ──
    sub_header("Practice Challenge: Extend the Strength Checker")
    info("1. Add keyboard walk detection (e.g., 'qweasdzxc', '1qaz2wsx').")
    info("2. Add date detection (e.g., '19901225', '01/01/2000').")
    info("3. Add a check for the user's own name or email in the password.")
    info("4. Add estimated crack time based on entropy and assumed hash rate.")
    info("5. BONUS: Load a larger common password list from a file.")
    print()
    hint_text("Keyboard walks can be detected by checking adjacent key positions.")
    hint_text("Crack time estimate: 2^entropy / hashes_per_second = seconds to crack.")

    if ask_yes_no("Did you extend the strength checker with at least two improvements?"):
        success("Impressive! Building security tools deepens your understanding.")
        mark_lesson_complete(progress, module_key, "strength_checker")
        mark_challenge_complete(progress, module_key, "strength_checker_extended")
    else:
        info("Give it a try when you have time. It is a great coding exercise.")

    press_enter()


# ─────────────────────────────────────────────────────────────────────────────
# Lesson 4 — Password Policy Best Practices
# ─────────────────────────────────────────────────────────────────────────────

def lesson_policy(progress, module_key):
    section_header("Lesson 4: Password Policy Best Practices")
    disclaimer()

    lesson_block(
        "Password policies define the rules that govern how passwords are created, "
        "stored, and managed within an organization. Modern best practices have "
        "shifted dramatically from the traditional approach — the latest NIST "
        "guidelines (SP 800-63B) recommend longer passphrases over complex short "
        "passwords, and discourage forced periodic rotation."
    )

    why_it_matters(
        "Poor password policies lead to users writing passwords on sticky notes, "
        "reusing passwords across services, or creating predictable patterns "
        "(Spring2025!, Summer2025!). A well-designed policy, combined with "
        "multi-factor authentication and a password manager, dramatically reduces "
        "credential-based attacks."
    )

    press_enter()

    # ── NIST Guidelines ──
    sub_header("NIST SP 800-63B Guidelines (Updated)")
    lesson_block(
        "The National Institute of Standards and Technology (NIST) publishes the "
        "most widely referenced guidelines for digital identity and authentication. "
        "Their current recommendations represent a major shift from older policies:"
    )

    print(f"  {G}DO:{RESET}")
    info("  Require a minimum of 8 characters (15+ for privileged accounts).")
    info("  Allow up to at least 64 characters to support passphrases.")
    info("  Accept all printable ASCII characters, Unicode, and spaces.")
    info("  Screen passwords against breach databases and common password lists.")
    info("  Provide real-time strength feedback during creation.")
    info("  Use MFA (multi-factor authentication) wherever possible.")
    info("  Hash passwords with bcrypt, scrypt, PBKDF2, or Argon2.")
    print()

    print(f"  {R}DO NOT:{RESET}")
    info("  Do NOT require composition rules (uppercase + digit + symbol).")
    info("  Do NOT force periodic password changes (e.g., every 90 days).")
    info("  Do NOT use password hints or knowledge-based questions.")
    info("  Do NOT truncate or limit the character set.")
    info("  Do NOT store passwords in plaintext or use reversible encryption.")
    print()

    lesson_block(
        "The rationale: forced complexity rules and periodic rotation lead to "
        "predictable behavior. Users create passwords like 'P@ssw0rd1!' and "
        "increment the number each cycle. Longer, memorable passphrases like "
        "'correct horse battery staple' are both stronger and easier to remember."
    )

    press_enter()

    # ── MFA ──
    sub_header("Multi-Factor Authentication (MFA)")
    lesson_block(
        "MFA requires users to present two or more independent authentication "
        "factors: something you know (password), something you have (phone, "
        "hardware key), and something you are (biometric). Even if an attacker "
        "steals a password, they cannot log in without the second factor."
    )

    info(f"{BRIGHT}Types of MFA (ranked by security):{RESET}")
    print(f"\n  {G}1. Hardware security keys (FIDO2 / WebAuthn){RESET}")
    print(f"     YubiKey, Google Titan — phishing-resistant, strongest option")
    print(f"  {G}2. Authenticator apps (TOTP){RESET}")
    print(f"     Google Authenticator, Authy — time-based one-time passwords")
    print(f"  {Y}3. Push notifications{RESET}")
    print(f"     Duo, Microsoft Authenticator — convenient but vulnerable to fatigue attacks")
    print(f"  {R}4. SMS codes{RESET}")
    print(f"     Better than nothing, but vulnerable to SIM swapping and interception")
    print()

    code_block(
        '# Implementing TOTP (Time-Based One-Time Password) in Python\n'
        'import pyotp\n'
        'import qrcode\n'
        '\n'
        '# Generate a secret for the user (store securely)\n'
        'secret = pyotp.random_base32()\n'
        'print(f"Secret: {secret}")\n'
        '\n'
        '# Generate a QR code for the authenticator app\n'
        'totp = pyotp.TOTP(secret)\n'
        'uri = totp.provisioning_uri(\n'
        '    name="user@company.com",\n'
        '    issuer_name="JJs LAB"\n'
        ')\n'
        'qrcode.make(uri).save("mfa_qr.png")\n'
        '\n'
        '# Verify a code submitted by the user\n'
        'user_code = input("Enter your 6-digit code: ")\n'
        'if totp.verify(user_code):\n'
        '    print("MFA verification successful!")\n'
        'else:\n'
        '    print("Invalid code.")',
        "python"
    )

    press_enter()

    # ── Password Managers ──
    sub_header("Password Managers")
    lesson_block(
        "A password manager generates, stores, and auto-fills unique, strong "
        "passwords for every account. The user only needs to remember one master "
        "password (which should be a strong passphrase). Password managers "
        "solve the fundamental problem of humans needing to remember dozens of "
        "complex passwords — they cannot, so they reuse passwords, which is the "
        "number one credential-based attack vector."
    )

    info(f"{BRIGHT}Benefits of password managers:{RESET}")
    info("  - Generate truly random passwords (e.g., 'kX9$mP2!qR7&vL4@')")
    info("  - Unique password per site — one breach does not compromise others")
    info("  - Phishing protection — auto-fill only works on the correct domain")
    info("  - Encrypted vault protects all credentials with a master password")
    info("  - Team features allow secure credential sharing in organizations")
    print()

    info(f"{BRIGHT}Recommended password managers:{RESET}")
    info("  - 1Password — strong team features, Watchtower breach monitoring")
    info("  - Bitwarden — open-source, free tier available, self-hostable")
    info("  - KeePassXC — fully offline, open-source, no cloud dependency")
    print()

    code_block(
        '# Generating a strong random password programmatically\n'
        'import secrets\n'
        'import string\n'
        '\n'
        'def generate_password(length: int = 20) -> str:\n'
        '    """Generate a cryptographically secure random password."""\n'
        '    charset = string.ascii_letters + string.digits + string.punctuation\n'
        '    # Ensure at least one of each character type\n'
        '    while True:\n'
        '        password = "".join(secrets.choice(charset) for _ in range(length))\n'
        '        if (any(c in string.ascii_lowercase for c in password)\n'
        '                and any(c in string.ascii_uppercase for c in password)\n'
        '                and any(c in string.digits for c in password)\n'
        '                and any(c in string.punctuation for c in password)):\n'
        '            return password\n'
        '\n'
        'def generate_passphrase(word_count: int = 5) -> str:\n'
        '    """Generate a random passphrase from a word list."""\n'
        '    # In production, use a proper word list (e.g., EFF diceware)\n'
        '    words = [\n'
        '        "correct", "horse", "battery", "staple", "wizard",\n'
        '        "thunder", "garden", "rocket", "planet", "ocean",\n'
        '        "bridge", "castle", "forest", "silver", "marble",\n'
        '        "velvet", "copper", "ancient", "frozen", "summit",\n'
        '        "harbor", "crystal", "meadow", "beacon", "shield",\n'
        '    ]\n'
        '    return "-".join(secrets.choice(words) for _ in range(word_count))\n'
        '\n'
        'print(f"Random password: {generate_password()}")\n'
        'print(f"Random passphrase: {generate_passphrase()}")',
        "python"
    )

    press_enter()

    # ── Organizational Policies ──
    sub_header("Organizational Password Policies")
    lesson_block(
        "Beyond individual password strength, organizations need policies that "
        "cover the entire credential lifecycle:"
    )

    info(f"{BRIGHT}1. Account provisioning:{RESET}")
    info("   - Temporary passwords must be changed on first login.")
    info("   - Use unique initial passwords, never shared defaults.")
    print()
    info(f"{BRIGHT}2. Storage and transmission:{RESET}")
    info("   - Hash all passwords with bcrypt/Argon2 (cost factor >= 12).")
    info("   - Transmit passwords only over TLS (HTTPS).")
    info("   - Never log passwords, even in debug mode.")
    print()
    info(f"{BRIGHT}3. Recovery and reset:{RESET}")
    info("   - Use secure, time-limited reset tokens (not security questions).")
    info("   - Send reset links, not new passwords, via email.")
    info("   - Rate-limit reset requests to prevent abuse.")
    print()
    info(f"{BRIGHT}4. Monitoring:{RESET}")
    info("   - Monitor for credential stuffing attacks (high volume login failures).")
    info("   - Alert on logins from unusual locations or devices.")
    info("   - Check employee passwords against breach databases regularly.")
    print()
    info(f"{BRIGHT}5. Service and API accounts:{RESET}")
    info("   - Use API keys or certificates instead of passwords where possible.")
    info("   - Rotate service account credentials regularly.")
    info("   - Store secrets in a vault (HashiCorp Vault, AWS Secrets Manager).")
    print()

    press_enter()

    # ── Live demo: generate passwords ──
    sub_header("Live Demo: Secure Password Generator")
    info("Generating example passwords with varying approaches:\n")

    import secrets

    # Random password
    charset = string.ascii_letters + string.digits + string.punctuation
    for i in range(3):
        pw = "".join(secrets.choice(charset) for _ in range(20))
        entropy = _calculate_entropy(pw)
        print(f"  Random (20 chars): {G}{pw}{RESET}  ({entropy:.1f} bits)")

    print()

    # Passphrase
    wordlist = [
        "correct", "horse", "battery", "staple", "wizard",
        "thunder", "garden", "rocket", "planet", "ocean",
        "bridge", "castle", "forest", "silver", "marble",
        "velvet", "copper", "ancient", "frozen", "summit",
        "harbor", "crystal", "meadow", "beacon", "shield",
        "compass", "lantern", "glacier", "canyon", "ember",
    ]
    for i in range(3):
        phrase = "-".join(secrets.choice(wordlist) for _ in range(5))
        entropy = _calculate_entropy(phrase)
        print(f"  Passphrase:        {G}{phrase}{RESET}  ({entropy:.1f} bits)")

    print()
    info("Both approaches are strong. Passphrases are easier to type on mobile.")

    press_enter()

    # ── Scenario ──
    scenario_block(
        "Colonial Pipeline Ransomware Attack (2021)",
        "The Colonial Pipeline attack — which disrupted fuel supply across the "
        "US East Coast — was traced to a single compromised password on an "
        "inactive VPN account. The password was found in a dark web dump, "
        "suggesting it was reused from a previous breach. The account did not "
        "have multi-factor authentication enabled. This incident demonstrates "
        "that a single weak credential can have enormous real-world consequences "
        "when MFA and proper account management are absent."
    )

    # ── Practice challenge ──
    sub_header("Practice Challenge: Draft a Password Policy")
    info("Write a one-page password policy for a fictional company that includes:")
    info("1. Minimum password requirements (following NIST guidelines).")
    info("2. MFA requirements for different roles/access levels.")
    info("3. Password manager deployment plan.")
    info("4. Service account credential management procedures.")
    info("5. Breach response procedures for compromised credentials.")
    print()
    hint_text("Reference NIST SP 800-63B for your requirements.")
    hint_text("Consider different tiers: general users, admins, service accounts.")

    if ask_yes_no("Did you draft a password policy document?"):
        success("Well done! Writing policies is a key skill for security professionals.")
        mark_lesson_complete(progress, module_key, "policy")
        mark_challenge_complete(progress, module_key, "password_policy_draft")
    else:
        info("This is a valuable exercise — revisit it when you have 30 minutes.")

    press_enter()


# ─────────────────────────────────────────────────────────────────────────────
# Internal helper functions (used by the live demos)
# ─────────────────────────────────────────────────────────────────────────────

# Common passwords list used by the strength checker
_COMMON_PASSWORDS = {
    "123456", "password", "123456789", "12345678", "12345",
    "1234567", "1234567890", "qwerty", "abc123", "111111",
    "password1", "iloveyou", "1q2w3e4r", "000000", "qwerty123",
    "zaq12wsx", "dragon", "sunshine", "princess", "letmein",
    "654321", "monkey", "27653", "1qaz2wsx", "123321",
    "qwertyuiop", "superman", "asdfghjkl", "welcome", "admin",
    "football", "shadow", "master", "michael", "trustno1",
    "batman", "access", "hello", "charlie", "thunder",
    "summer2024", "p@ssw0rd", "baseball1", "football1",
    "passw0rd", "test", "love", "secret", "god", "sex",
}

# Lower-cased version for comparison
_COMMON_PASSWORDS_LOWER = {p.lower() for p in _COMMON_PASSWORDS}


def _calculate_entropy(password: str) -> float:
    """Calculate the entropy of a password based on its character classes."""
    charset_size = 0
    if any(c in string.ascii_lowercase for c in password):
        charset_size += 26
    if any(c in string.ascii_uppercase for c in password):
        charset_size += 26
    if any(c in string.digits for c in password):
        charset_size += 10
    if any(c in string.punctuation for c in password):
        charset_size += 32
    if any(c == " " for c in password):
        charset_size += 1
    if charset_size == 0:
        return 0.0
    return round(len(password) * math.log2(charset_size), 1)


def _is_common_password(password: str) -> bool:
    """Check if the password is in the common passwords list."""
    return password.lower() in _COMMON_PASSWORDS_LOWER


def _detect_patterns(password: str) -> list:
    """Detect common weak patterns in a password."""
    issues = []

    if len(password) < 8:
        issues.append("Too short (minimum 8 characters recommended)")
    elif len(password) < 12:
        issues.append("Consider 12+ characters for strong security")

    if not re.search(r"[a-z]", password):
        issues.append("No lowercase letters")
    if not re.search(r"[A-Z]", password):
        issues.append("No uppercase letters")
    if not re.search(r"[0-9]", password):
        issues.append("No digits")
    if not re.search(r"[!@#$%^&*()_+\-=\[\]{}|;:,.<>?/~`]", password):
        issues.append("No special characters")

    if re.search(r"(.)\1{2,}", password):
        issues.append("Contains repeated characters (e.g., aaa)")

    sequences = ["abcdef", "123456", "qwerty", "asdfgh", "zxcvbn"]
    for seq in sequences:
        if seq in password.lower():
            issues.append(f"Contains keyboard sequence: {seq}")

    # Check for common substitutions (l33tspeak)
    desubbed = password.lower()
    for old, new in [("@", "a"), ("0", "o"), ("1", "i"), ("3", "e"),
                     ("$", "s"), ("!", "i"), ("5", "s")]:
        desubbed = desubbed.replace(old, new)
    if desubbed != password.lower() and desubbed in _COMMON_PASSWORDS_LOWER:
        issues.append("Common password with character substitutions")

    return issues


def _score_password(password: str) -> dict:
    """Score a password from 0 to 100 with detailed feedback."""
    score = 0
    feedback = []

    # Entropy-based scoring (up to 40 points)
    entropy = _calculate_entropy(password)
    entropy_score = min(40, int(entropy * 40 / 80))
    score += entropy_score
    feedback.append(f"Entropy: {entropy:.1f} bits ({entropy_score}/40 points)")

    # Length scoring (up to 25 points)
    length_score = min(25, len(password) * 25 // 20)
    score += length_score
    feedback.append(f"Length: {len(password)} chars ({length_score}/25 points)")

    # Character variety (up to 20 points)
    variety = 0
    if re.search(r"[a-z]", password):
        variety += 1
    if re.search(r"[A-Z]", password):
        variety += 1
    if re.search(r"[0-9]", password):
        variety += 1
    if re.search(r"[^a-zA-Z0-9]", password):
        variety += 1
    variety_score = variety * 5
    score += variety_score
    feedback.append(f"Character variety: {variety}/4 types ({variety_score}/20 points)")

    # Penalties
    penalties = 0
    if _is_common_password(password):
        penalties += 30
        feedback.append("PENALTY: Common password (-30)")
    issues = _detect_patterns(password)
    penalties += min(15, len(issues) * 3)
    for issue in issues:
        feedback.append(f"Issue: {issue}")

    # Bonus for long + varied
    bonus = 0
    if len(password) >= 16 and variety >= 3:
        bonus = 15
        feedback.append(f"BONUS: Long + varied ({bonus} points)")

    final_score = max(0, min(100, score - penalties + bonus))

    if final_score >= 80:
        rating = "STRONG"
    elif final_score >= 60:
        rating = "MODERATE"
    elif final_score >= 40:
        rating = "WEAK"
    else:
        rating = "VERY WEAK"

    return {
        "score": final_score,
        "rating": rating,
        "entropy": entropy,
        "feedback": feedback,
    }


# ─────────────────────────────────────────────────────────────────────────────
# Quiz
# ─────────────────────────────────────────────────────────────────────────────

def _run_quiz(progress, module_key):
    questions = [
        {
            "q": "Why is MD5 unsuitable for password hashing?",
            "options": [
                "A) It produces hashes that are too short",
                "B) It is too fast, allowing billions of attempts per second",
                "C) It requires too much memory to compute",
                "D) It does not support Unicode input",
            ],
            "answer": "b",
            "explanation": (
                "MD5 is designed for speed, which is a disadvantage for password "
                "hashing. Attackers can compute billions of MD5 hashes per second "
                "on a modern GPU, making brute-force attacks trivial. It also has "
                "known collision vulnerabilities."
            ),
        },
        {
            "q": "What is the primary purpose of a salt in password hashing?",
            "options": [
                "A) To make the hash longer and harder to store",
                "B) To encrypt the password before hashing",
                "C) To ensure identical passwords produce different hashes, "
                   "defeating rainbow tables",
                "D) To slow down the hashing process",
            ],
            "answer": "c",
            "explanation": (
                "A salt is a random value added to each password before hashing, "
                "ensuring that even identical passwords produce unique hashes. This "
                "makes precomputed rainbow tables useless because each salt would "
                "require its own table."
            ),
        },
        {
            "q": "Which algorithm won the Password Hashing Competition and is "
                 "considered the gold standard for new projects?",
            "options": [
                "A) bcrypt",
                "B) SHA-3",
                "C) Argon2",
                "D) PBKDF2",
            ],
            "answer": "c",
            "explanation": (
                "Argon2 won the 2015 Password Hashing Competition. Its memory-hard "
                "design makes it resistant to GPU and ASIC-based cracking, and "
                "Argon2id (the hybrid variant) is recommended for password hashing."
            ),
        },
        {
            "q": "According to NIST SP 800-63B, which practice should be AVOIDED?",
            "options": [
                "A) Screening passwords against breach databases",
                "B) Allowing passphrases up to 64 characters",
                "C) Requiring periodic password changes (e.g., every 90 days)",
                "D) Using multi-factor authentication",
            ],
            "answer": "c",
            "explanation": (
                "NIST recommends AGAINST forced periodic password changes because "
                "they lead to predictable patterns (Password1!, Password2!, ...). "
                "Passwords should only be changed when there is evidence of compromise."
            ),
        },
        {
            "q": "What type of MFA is most resistant to phishing attacks?",
            "options": [
                "A) SMS codes",
                "B) Email verification codes",
                "C) Push notifications",
                "D) Hardware security keys (FIDO2 / WebAuthn)",
            ],
            "answer": "d",
            "explanation": (
                "Hardware security keys using FIDO2/WebAuthn are phishing-resistant "
                "because they cryptographically verify the origin of the request. "
                "An attacker on a fake site cannot intercept or replay the challenge."
            ),
        },
        {
            "q": "A password has 60 bits of entropy. Approximately how many "
                 "guesses are needed to exhaust the entire search space?",
            "options": [
                "A) 60 million",
                "B) About 1 billion (10^9)",
                "C) About 1 quintillion (10^18)",
                "D) About 1 trillion (10^12)",
            ],
            "answer": "c",
            "explanation": (
                "60 bits of entropy means 2^60 possible values, which is "
                "approximately 1.15 * 10^18 (about 1 quintillion). At 10 billion "
                "guesses per second, this would take about 3.6 years to exhaust."
            ),
        },
    ]
    run_quiz(questions, "password_security_quiz", module_key, progress)
