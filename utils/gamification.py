"""
Gamification system for JJ's LAB.
Badges and achievement tracking.
"""

from utils.display import success, info, C, G, Y, RESET, BRIGHT
from utils.progress import save_progress


BADGES = [
    ("first_lesson",    "First Steps",    "🎓", "Complete your first lesson"),
    ("module_complete", "Module Master",  "📚", "Complete all lessons in a module"),
    ("quiz_ace",        "Quiz Ace",       "💯", "Score 100% on a quiz"),
    ("challenger",      "Challenger",     "⚔️",  "Complete your first challenge"),
    ("flag_hunter",     "Flag Hunter",    "🚩", "Capture your first CTF flag"),
    ("flag_collector",  "Flag Collector", "🏴", "Capture 5 CTF flags"),
    ("ctf_champion",    "CTF Champion",   "👑", "Complete all 8 CTF challenges"),
    ("speedrun",        "Speedrunner",    "⏱️",  "Complete a CTF challenge in under 2 minutes"),
]


def check_and_award_badges(progress):
    """Check all badge conditions and award any newly earned badges."""
    badges = progress.setdefault("badges", [])
    newly_awarded = []

    checks = {}

    # Lesson-based badges
    total_lessons = sum(
        len(m.get("completed_lessons", []))
        for m in progress.get("modules", {}).values()
    )
    checks["first_lesson"] = total_lessons >= 1

    # Module completion
    from utils.progress import MODULE_LESSON_COUNTS
    checks["module_complete"] = any(
        len(m.get("completed_lessons", [])) >= MODULE_LESSON_COUNTS.get(mk, 999)
        for mk, m in progress.get("modules", {}).items()
    )

    # Quiz ace
    checks["quiz_ace"] = any(
        q.get("score", 0) == q.get("total", 0) and q.get("total", 0) > 0
        for m in progress.get("modules", {}).values()
        for q in m.get("quiz_scores", {}).values()
    )

    # Challenge completion
    total_challenges = sum(
        len(m.get("challenges_done", []))
        for m in progress.get("modules", {}).values()
    )
    checks["challenger"] = total_challenges >= 1

    # CTF badges
    ctf_data = progress.get("ctf", {})
    ctf_flags = ctf_data.get("total_flags", 0)
    ctf_challenges = ctf_data.get("challenges", {})
    fastest_ctf = min(
        (c.get("time", 9999) for c in ctf_challenges.values() if c.get("completed")),
        default=9999
    )

    checks["flag_hunter"] = ctf_flags >= 1
    checks["flag_collector"] = ctf_flags >= 5
    checks["ctf_champion"] = ctf_flags >= 8
    checks["speedrun"] = fastest_ctf < 120

    # Award new badges
    for badge_id, name, icon, desc in BADGES:
        if badge_id not in badges and checks.get(badge_id, False):
            badges.append(badge_id)
            newly_awarded.append((badge_id, name, icon, desc))

    if newly_awarded:
        save_progress(progress)
        for badge_id, name, icon, desc in newly_awarded:
            print()
            success(f"Badge earned: {icon} {name} -- {desc}")

    return newly_awarded
