"""
CTF challenge engine for JJ's LAB.
Handles flag validation, scoring, timing, and challenge execution.
"""

import re
import time
import urllib.request

from utils.display import (
    section_header, sub_header, info, success, warning,
    error as error_msg, hint_text, press_enter, ask_yes_no,
    C, G, Y, R, RESET, BRIGHT, DIM
)


class CTFTimer:
    """Simple timer for CTF challenges."""

    def __init__(self):
        self._start = None
        self._end = None

    def start(self):
        self._start = time.time()
        self._end = None

    def stop(self):
        self._end = time.time()

    def elapsed(self):
        if self._start is None:
            return 0.0
        end = self._end if self._end else time.time()
        return end - self._start

    def format_time(self):
        total = int(self.elapsed())
        minutes = total // 60
        seconds = total % 60
        return f"{minutes:02d}:{seconds:02d}"


def validate_flag(user_input, correct_flag, validation="exact"):
    """Validate a flag submission.

    Args:
        user_input: What the user typed
        correct_flag: The correct flag
        validation: "exact" for exact match, "regex" for regex match

    Returns True if valid.
    """
    user_clean = user_input.strip()
    if validation == "regex":
        return bool(re.match(correct_flag, user_clean, re.IGNORECASE))
    # exact
    return user_clean.upper() == correct_flag.upper()


def calculate_score(base_points, hints_used, hint_penalty, elapsed_seconds):
    """Calculate score with hint penalties and time bonuses.

    Returns int score (floor at 0).
    """
    score = base_points - (hints_used * hint_penalty)
    # Time bonus
    if elapsed_seconds < 120:
        score += 10
    elif elapsed_seconds < 300:
        score += 5
    return max(0, score)


def _check_vuln_app():
    """Check if the vulnerable app is running on localhost:5050."""
    try:
        urllib.request.urlopen("http://127.0.0.1:5050", timeout=2)
        return True
    except Exception:
        return False


def run_ctf_challenge(challenge, progress):
    """Run a single CTF challenge interactively.

    Args:
        challenge: Challenge dict from ctf_challenges.py
        progress: User progress dict

    Returns dict with: completed, score, time, hints_used
    """
    section_header(f"CTF: {challenge['title']}")
    print(f"  {C}Category:{RESET}   {challenge['category']}")
    print(f"  {C}Difficulty:{RESET} {challenge['difficulty']}")
    print(f"  {C}Points:{RESET}     {challenge['points']}")
    print(f"  {C}Hint cost:{RESET}  {challenge['hint_penalty']} pts per hint")
    print()

    # Show challenge description
    print(f"  {challenge['description']}")
    print()

    # Check if vuln app is needed
    if challenge.get("requires_vuln_app"):
        if not _check_vuln_app():
            warning("This challenge requires the vulnerable app to be running!")
            info("Start it from the main menu: 'Start Vulnerable Practice App'")
            press_enter()
            return {"completed": False, "score": 0, "time": 0, "hints_used": 0}

    if not ask_yes_no("Ready to start?"):
        return {"completed": False, "score": 0, "time": 0, "hints_used": 0}

    timer = CTFTimer()
    timer.start()
    hints_used = 0
    max_submissions = 5

    for attempt in range(1, max_submissions + 1):
        remaining = max_submissions - attempt + 1
        print(f"\n  {DIM}[Attempt {attempt}/{max_submissions} | Time: {timer.format_time()}]{RESET}")

        try:
            flag_input = input(f"  {C}Enter flag: {RESET}").strip()
        except (KeyboardInterrupt, EOFError):
            print()
            return {"completed": False, "score": 0, "time": timer.elapsed(), "hints_used": hints_used}

        if not flag_input:
            continue

        validation = challenge.get("validation", "exact")
        if validate_flag(flag_input, challenge["flag"], validation):
            timer.stop()
            elapsed = timer.elapsed()
            score = calculate_score(
                challenge["points"], hints_used,
                challenge["hint_penalty"], elapsed
            )

            print()
            success(f"FLAG CAPTURED!")
            print(f"  {G}{BRIGHT}Score: {score} pts  |  Time: {timer.format_time()}{RESET}")
            if hints_used:
                print(f"  {DIM}Hint penalty: -{hints_used * challenge['hint_penalty']} pts{RESET}")
            if elapsed < 120:
                print(f"  {G}Speed bonus: +10 pts{RESET}")
            elif elapsed < 300:
                print(f"  {G}Speed bonus: +5 pts{RESET}")
            print()

            return {"completed": True, "score": score, "time": elapsed, "hints_used": hints_used}
        else:
            error_msg(f"Incorrect flag. {remaining - 1} attempt(s) remaining.")

            # Offer hint after wrong answer
            if hints_used < len(challenge["hints"]):
                penalty = challenge["hint_penalty"]
                if ask_yes_no(f"Want a hint? (-{penalty} pts)"):
                    hint_text(challenge["hints"][hints_used])
                    hints_used += 1

    timer.stop()
    warning("No attempts remaining. Better luck next time!")
    return {"completed": False, "score": 0, "time": timer.elapsed(), "hints_used": hints_used}
