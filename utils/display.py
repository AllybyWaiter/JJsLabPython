"""
Terminal display utilities for JJ's LAB.
Provides colored output, banners, formatted text blocks, and UI helpers.
"""

import os
import sys
import time
import textwrap
from colorama import Fore, Back, Style, init

init(autoreset=True)

# -- Color shortcuts --
R = Fore.RED
G = Fore.GREEN
Y = Fore.YELLOW
B = Fore.BLUE
C = Fore.CYAN
M = Fore.MAGENTA
W = Fore.WHITE
DIM = Style.DIM
BRIGHT = Style.BRIGHT
RESET = Style.RESET_ALL

try:
    TERM_WIDTH = min(os.get_terminal_size().columns, 90)
except OSError:
    TERM_WIDTH = 80

# -- Hacker alias (set via set_agent_alias) --
_current_alias = ""


def set_agent_alias(alias: str):
    """Set the current agent alias for display in mission screens."""
    global _current_alias
    _current_alias = alias


# -- ASCII art per mission --
MISSION_ART = {
    1: [
        r"   ┌───────┐  ",
        r"   │ ░░░░░ │  ",
        r"   │ ░ X ░ │  ",
        r"   │ ░░░░░ │  ",
        r"   └──┤├───┘  ",
        r"     /  \     ",
        r"    BROKEN    ",
    ],
    2: [
        r"  [PC]──────[SW]──────[PC]",
        r"    \        |        /   ",
        r"     \       |       /    ",
        r"      ──[FIREWALL]──     ",
        r"             |            ",
        r"         [SERVER]         ",
    ],
    3: [
        r"   ╔══════════════╗ ",
        r"   ║  THE  VAULT  ║ ",
        r"   ║   ┌──(O)──┐  ║ ",
        r"   ║   │ ░░░░░ │  ║ ",
        r"   ║   │ ░░░░░ │  ║ ",
        r"   ║   └───────┘  ║ ",
        r"   ╚══════════════╝ ",
    ],
    4: [
        r"       .-''--.      ",
        r"      /  ◉  ◉ \     ",
        r"     |    __    |    ",
        r"      \  ‾‾‾  /     ",
        r"       '-..-'       ",
        r"     G H O S T      ",
    ],
    5: [
        r"      ╱╲   ╱╲       ",
        r"     ╱  ╲ ╱  ╲      ",
        r"    ╱ ╱╲ ╳ ╱╲ ╲     ",
        r"   ╱ ╱  ╳╳╳  ╲ ╲   ",
        r"   ‾‾  FIRE!  ‾‾   ",
        r"   !! CODE RED !!   ",
    ],
}


def clear_screen():
    os.system("cls" if os.name == "nt" else "clear")


def banner():
    """Print the main application banner."""
    J = [" ####", "   ##", "   ##", "#  ##", " ### "]
    L = ["#    ", "#    ", "#    ", "#    ", "#####"]
    A = [" ### ", "#   #", "#####", "#   #", "#   #"]
    B = ["#### ", "#   #", "#### ", "#   #", "#### "]

    print(f"\n{C}{BRIGHT}")
    for i in range(5):
        print(f"      {J[i]}  {J[i]}        {L[i]}  {A[i]}  {B[i]}")
    print()
    print(f"        {W}JJ's LAB -- Ethical Hacking & Security{C}")
    print(f"        {DIM}{W}For authorized internal use only{C}{BRIGHT}")
    print(f"{RESET}")


def section_header(title: str):
    """Print a prominent section header."""
    width = TERM_WIDTH
    print()
    print(f"{C}{BRIGHT}{'═' * width}")
    print(f"  {title}")
    print(f"{'═' * width}{RESET}")
    print()


def sub_header(title: str):
    print(f"\n{Y}{BRIGHT}── {title} {'─' * max(0, TERM_WIDTH - len(title) - 4)}{RESET}\n")


def info(text: str):
    print(f"{C}[i]{RESET} {text}")


def success(text: str):
    print(f"{G}[✓]{RESET} {text}")


def warning(text: str):
    print(f"{Y}[!]{RESET} {text}")


def error(text: str):
    print(f"{R}[✗]{RESET} {text}")


def disclaimer():
    """Print the ethical-use disclaimer."""
    box_width = TERM_WIDTH - 4
    print(f"\n{R}{BRIGHT}┌{'─' * box_width}┐")
    lines = [
        "DISCLAIMER — AUTHORIZED USE ONLY",
        "",
        "This application is designed for EDUCATIONAL purposes and",
        "for testing systems you OWN or have WRITTEN AUTHORIZATION",
        "to test. Unauthorized access to computer systems is illegal.",
        "",
        "All exercises run against localhost only.",
        "Never use these techniques against systems without permission.",
    ]
    for line in lines:
        padding = box_width - len(line) - 2
        print(f"│ {line}{' ' * max(0, padding)} │")
    print(f"└{'─' * box_width}┘{RESET}\n")


def lesson_block(text: str):
    """Print a wrapped block of lesson text."""
    wrapped = textwrap.fill(text, width=TERM_WIDTH - 4)
    for line in wrapped.split("\n"):
        print(f"  {line}")
    print()


def code_block(code: str, language: str = "python"):
    """Print a syntax-highlighted-style code block."""
    print(f"\n{DIM}  ┌─ {language} {'─' * max(0, TERM_WIDTH - len(language) - 8)}┐{RESET}")
    for line in code.strip().split("\n"):
        print(f"  {G}│{RESET} {line}")
    print(f"{DIM}  └{'─' * (TERM_WIDTH - 4)}┘{RESET}\n")


def scenario_block(title: str, text: str):
    """Print a real-world scenario box."""
    print(f"\n{M}{BRIGHT}  ┌─ Real-World Scenario: {title} {'─' * max(0, TERM_WIDTH - len(title) - 30)}┐{RESET}")
    wrapped = textwrap.fill(text, width=TERM_WIDTH - 8)
    for line in wrapped.split("\n"):
        print(f"{M}  │{RESET}  {line}")
    print(f"{M}  └{'─' * (TERM_WIDTH - 4)}┘{RESET}\n")


def why_it_matters(text: str):
    """Print a 'why this matters' callout."""
    print(f"\n{Y}{BRIGHT}  ★ Why This Matters for Your Company{RESET}")
    wrapped = textwrap.fill(text, width=TERM_WIDTH - 6)
    for line in wrapped.split("\n"):
        print(f"    {line}")
    print()


def hint_text(text: str):
    """Print hint text (dimmed)."""
    print(f"{DIM}  Hint: {text}{RESET}")


def tip(text: str):
    """Print a beginner-friendly tip."""
    print(f"\n{C}{BRIGHT}  TIP:{RESET} {text}\n")


def nice_work(msg: str = "Nice work! You're making great progress."):
    """Print an encouraging message."""
    print(f"\n{G}{BRIGHT}  >> {msg}{RESET}\n")


def learning_goal(goals: list[str]):
    """Show what the learner will pick up in this section."""
    print(f"\n{C}{BRIGHT}  In this lesson you will learn:{RESET}")
    for g in goals:
        print(f"  {C}-{RESET} {g}")
    print()


def pace():
    """Short pause between concepts -- keeps output from overwhelming."""
    input(f"{DIM}  (press Enter when you're ready to keep going){RESET}")


def show_menu(title: str, options: list[tuple[str, str]], back: bool = True) -> str:
    """Display a numbered menu and return the user's choice key.

    options: list of (key, label) tuples.
    Returns the key string of the chosen option, or 'back'/'quit'.
    """
    section_header(title)
    for i, (key, label) in enumerate(options, 1):
        print(f"  {C}{BRIGHT}{i}.{RESET} {label}")
    if back:
        print(f"\n  {DIM}0. Back{RESET}")
    print(f"  {DIM}q. Quit{RESET}")
    print()

    while True:
        choice = input(f"{C}  ▶ Choose an option: {RESET}").strip().lower()
        if choice == "q":
            return "quit"
        if choice == "0" and back:
            return "back"
        try:
            idx = int(choice) - 1
            if 0 <= idx < len(options):
                return options[idx][0]
        except ValueError:
            pass
        error("Invalid choice. Try again.")


def press_enter():
    """Pause until the user presses Enter."""
    input(f"\n{DIM}  Press Enter to continue...{RESET}")


def ask_yes_no(prompt: str) -> bool:
    while True:
        answer = input(f"{C}  {prompt} (y/n): {RESET}").strip().lower()
        if answer in ("y", "yes"):
            return True
        if answer in ("n", "no"):
            return False


def progress_bar(current: int, total: int, label: str = ""):
    """Print a simple progress bar."""
    pct = current / total if total else 0
    filled = int(pct * 30)
    bar = f"{'█' * filled}{'░' * (30 - filled)}"
    print(f"  {label} [{G}{bar}{RESET}] {current}/{total} ({pct:.0%})")


# ---------------------------------------------------------------------------
# Story Mode display helpers
# ---------------------------------------------------------------------------

def mission_briefing(mission_num: int, title: str, client: str, objective: str):
    """Display a dramatic mission briefing screen."""
    clear_screen()
    width = TERM_WIDTH
    print(f"\n{R}{BRIGHT}")
    print(f"  {'▄' * (width - 4)}")
    print(f"  █{' ' * (width - 6)}█")
    label = f"MISSION {mission_num}"
    pad = width - 6 - len(label)
    print(f"  █  {label}{' ' * max(0, pad)}█")
    pad2 = width - 6 - len(title)
    print(f"  █  {title.upper()}{' ' * max(0, pad2)}█")
    print(f"  █{' ' * (width - 6)}█")
    print(f"  {'▀' * (width - 4)}")
    print(f"{RESET}")

    # ASCII art for this mission
    art_lines = MISSION_ART.get(mission_num, [])
    if art_lines:
        print(f"{C}{DIM}")
        for art_line in art_lines:
            print(f"    {art_line}")
        print(f"{RESET}")

    time.sleep(0.5)
    print(f"  {C}{BRIGHT}CLIENT:{RESET}    {client}")
    print(f"  {C}{BRIGHT}OBJECTIVE:{RESET} {objective}")
    if _current_alias:
        print(f"  {C}{BRIGHT}AGENT:{RESET}     {_current_alias}")
    print()
    print(f"  {DIM}{'─' * (width - 4)}{RESET}")
    press_enter()


def narrator(text: str):
    """Print green story narration text with typing animation."""
    wrapped = textwrap.fill(text, width=TERM_WIDTH - 6)
    for line in wrapped.split("\n"):
        sys.stdout.write(f"  {G}")
        for ch in line:
            sys.stdout.write(ch)
            sys.stdout.flush()
            if ch in ".!?":
                time.sleep(0.04)
            elif ch in ",;:":
                time.sleep(0.02)
            else:
                time.sleep(0.012)
        sys.stdout.write(f"{RESET}\n")
    print()


def terminal_prompt(text: str):
    """Print a simulated terminal prompt line."""
    print(f"  {G}{BRIGHT}root@target:~${RESET} {text}")


def mission_complete(mission_num: int, title: str, score: int, max_score: int):
    """Display the victory screen with score and rating."""
    clear_screen()
    pct = (score / max_score * 100) if max_score else 0

    if pct >= 90:
        rating = "ELITE HACKER"
        rating_color = R
    elif pct >= 70:
        rating = "SKILLED OPERATIVE"
        rating_color = Y
    elif pct >= 50:
        rating = "JUNIOR ANALYST"
        rating_color = C
    else:
        rating = "SCRIPT KIDDIE"
        rating_color = DIM

    width = TERM_WIDTH
    print(f"\n{G}{BRIGHT}")
    print(f"  {'═' * (width - 4)}")
    print(f"  MISSION {mission_num} COMPLETE")
    print(f"  {title}")
    print(f"  {'═' * (width - 4)}")
    print(f"{RESET}")
    print(f"  {C}SCORE:{RESET}  {score} / {max_score}  ({pct:.0f}%)")
    filled = min(int(pct / 100 * 30), 30)
    bar = f"{'█' * filled}{'░' * (30 - filled)}"
    print(f"  [{G}{bar}{RESET}]")
    print()
    print(f"  {rating_color}{BRIGHT}RATING: {rating}{RESET}")
    if _current_alias:
        print(f"\n  {G}Well done, Agent {_current_alias}.{RESET}")
    print()
    print(f"  {DIM}{'─' * (width - 4)}{RESET}")
    press_enter()


# ---------------------------------------------------------------------------
# Timer display helpers (Feature 12)
# ---------------------------------------------------------------------------

def timer_header(time_limit: int):
    """Print a timed-task banner before the task starts."""
    width = TERM_WIDTH
    print()
    print(f"  {Y}{BRIGHT}{'━' * (width - 4)}")
    print(f"   ⏱  TIMED — you have {time_limit} seconds")
    print(f"  {'━' * (width - 4)}{RESET}")
    print()


def timer_result(elapsed: float, time_limit: int, bonus_earned: bool):
    """Print the elapsed time vs limit with color coding."""
    if bonus_earned:
        print(f"  {G}{BRIGHT}⏱  {elapsed:.1f}s / {time_limit}s — Speed bonus earned!{RESET}")
    else:
        print(f"  {Y}⏱  {elapsed:.1f}s / {time_limit}s — Time exceeded{RESET}")
    print()


# ---------------------------------------------------------------------------
# Dossier display helpers (Feature 14)
# ---------------------------------------------------------------------------

def show_dossier(filepath: str):
    """Print file contents in a styled evidence box."""
    try:
        with open(filepath, "r") as f:
            content = f.read()
    except FileNotFoundError:
        error(f"Dossier not found: {filepath}")
        return

    width = TERM_WIDTH
    print(f"\n{DIM}{C}  ┌─ CLASSIFIED DOSSIER {'─' * max(0, width - 27)}┐{RESET}")
    for line in content.split("\n"):
        truncated = line[:width - 8]
        print(f"  {DIM}{C}│{RESET} {truncated}")
    print(f"{DIM}{C}  └{'─' * (width - 4)}┘{RESET}\n")


def dossier_notification(filepath: str):
    """Print a dossier availability notification."""
    import os
    filename = os.path.basename(filepath)
    print(f"\n  {C}{BRIGHT}📁 DOSSIER:{RESET} {filename} saved to {filepath}")
    print()
