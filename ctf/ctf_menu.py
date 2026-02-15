"""
CTF menu and progress tracking for JJ's LAB.
"""

from utils.display import (
    section_header, sub_header, info, success, warning,
    error as error_msg, press_enter, show_menu, ask_yes_no,
    progress_bar, C, G, Y, R, RESET, BRIGHT, DIM
)
from utils.progress import save_progress
from ctf.ctf_challenges import CTF_CHALLENGES
from ctf.ctf_engine import run_ctf_challenge


def init_ctf_progress(progress):
    """Ensure CTF progress structure exists."""
    if "ctf" not in progress:
        progress["ctf"] = {
            "challenges": {},
            "total_flags": 0,
            "total_score": 0,
        }


def mark_ctf_complete(progress, challenge_id, result):
    """Record a CTF challenge completion. Keeps best score."""
    init_ctf_progress(progress)
    ctf = progress["ctf"]
    existing = ctf["challenges"].get(challenge_id, {})

    if not existing.get("completed") or result["score"] > existing.get("score", 0):
        was_new = not existing.get("completed")
        ctf["challenges"][challenge_id] = {
            "completed": True,
            "score": result["score"],
            "time": result["time"],
            "hints_used": result["hints_used"],
        }
        if was_new:
            ctf["total_flags"] = sum(
                1 for c in ctf["challenges"].values() if c.get("completed")
            )
        ctf["total_score"] = sum(
            c.get("score", 0) for c in ctf["challenges"].values() if c.get("completed")
        )

    save_progress(progress)


def show_ctf_scoreboard(progress):
    """Display CTF scoreboard with all challenge status."""
    init_ctf_progress(progress)
    ctf = progress["ctf"]

    section_header("CTF Scoreboard")

    print(f"  {'ID':<20} {'Category':<22} {'Diff':<8} {'Pts':<6} {'Status':<10} {'Score':<8} {'Time'}")
    print(f"  {'─' * 90}")

    for ch in CTF_CHALLENGES:
        data = ctf["challenges"].get(ch["id"], {})
        if data.get("completed"):
            status = f"{G}[Done]{RESET}"
            score = str(data.get("score", 0))
            elapsed = data.get("time", 0)
            minutes = int(elapsed) // 60
            seconds = int(elapsed) % 60
            time_str = f"{minutes:02d}:{seconds:02d}"
        else:
            status = f"{Y}[Todo]{RESET}"
            score = "-"
            time_str = "-"

        print(f"  {ch['title']:<20} {ch['category']:<22} {ch['difficulty']:<8} {ch['points']:<6} {status:<21} {score:<8} {time_str}")

    print(f"  {'─' * 90}")
    total_flags = ctf.get("total_flags", 0)
    total_score = ctf.get("total_score", 0)
    max_score = sum(c["points"] for c in CTF_CHALLENGES)
    print(f"\n  {C}Flags captured:{RESET} {total_flags}/{len(CTF_CHALLENGES)}")
    print(f"  {C}Total score:{RESET}    {total_score}/{max_score}")
    progress_bar(total_flags, len(CTF_CHALLENGES), "Flags   ")
    print()
    press_enter()


def ctf_menu(progress, session=None):
    """CTF challenge selection menu."""
    init_ctf_progress(progress)

    while True:
        ctf = progress["ctf"]
        options = []

        for ch in CTF_CHALLENGES:
            data = ctf["challenges"].get(ch["id"], {})
            if data.get("completed"):
                status = f"{G}[Done]{RESET}"
            else:
                status = f"{Y}[Todo]{RESET}"

            options.append(
                (ch["id"], f"{status} {ch['title']} ({ch['category']}, {ch['difficulty']}, {ch['points']}pts)")
            )

        options.append(("scoreboard", f"{C}View Scoreboard{RESET}"))

        choice = show_menu("CTF Challenges", options)
        if choice == "back":
            return
        if choice == "quit":
            raise SystemExit

        if choice == "scoreboard":
            show_ctf_scoreboard(progress)
            continue

        # Find and run the challenge
        challenge = next((c for c in CTF_CHALLENGES if c["id"] == choice), None)
        if not challenge:
            continue

        result = run_ctf_challenge(challenge, progress)

        if result["completed"]:
            mark_ctf_complete(progress, challenge["id"], result)

            # Award XP (score // 2)
            xp = result["score"] // 2
            if xp > 0:
                info(f"Earned {xp} XP from this challenge!")

            # Update analytics streak
            analytics = progress.setdefault("analytics", {})
            import datetime
            today = datetime.datetime.now().strftime("%Y-%m-%d")
            days = analytics.setdefault("days_active", [])
            if today not in days:
                days.insert(0, today)

            # Check badges if gamification exists
            try:
                from utils.gamification import check_and_award_badges
                check_and_award_badges(progress)
            except ImportError:
                pass

            save_progress(progress)

        press_enter()
