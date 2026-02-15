"""
Story Mode mission selection menu with completion status.
"""

import importlib

from utils.display import (
    show_menu, section_header, info, warning, error, press_enter,
    ask_yes_no, G, Y, R, C, DIM, BRIGHT, RESET,
)
from utils.progress import MISSION_NAMES, MODULE_NAMES, MODULE_LESSON_COUNTS


MISSION_MODULES = {
    "mission1": "missions.mission1_web_pentest",
    "mission2": "missions.mission2_network_intrusion",
    "mission3": "missions.mission3_password_cracking",
    "mission4": "missions.mission4_osint_investigation",
    "mission5": "missions.mission5_incident_response",
}

MISSION_TOPICS = {
    "mission1": "Web Pentest",
    "mission2": "Network Intrusion",
    "mission3": "Password Cracking",
    "mission4": "OSINT Investigation",
    "mission5": "Incident Response",
}

MISSION_DIFFICULTY = {
    "mission1": ("Beginner", G),
    "mission2": ("Intermediate", Y),
    "mission3": ("Beginner", G),
    "mission4": ("Intermediate", Y),
    "mission5": ("Advanced", R),
}

# Recommended modules to complete before attempting each mission
MISSION_PREREQUISITES = {
    "mission1": ["module3"],   # Web Pentest → Web Application Security
    "mission2": ["module2"],   # Network Intrusion → Network Fundamentals
    "mission3": ["module4"],   # Password Cracking → Password Security
    "mission4": ["module5"],   # OSINT → Reconnaissance & OSINT
    "mission5": ["module7"],   # Incident Response → Log Analysis & IR
}


def missions_menu(progress: dict):
    """Display the Story Mode menu and launch selected missions."""
    while True:
        options = []
        missions = progress.get("missions", {})
        for mk, name in MISSION_NAMES.items():
            mdata = missions.get(mk, {})
            topic = MISSION_TOPICS.get(mk, "")
            if mdata.get("completed"):
                score = mdata.get("score", 0)
                status = f"{G}[{score}%]{RESET}"
            else:
                status = f"{DIM}[--]{RESET}"
            num = mk.replace("mission", "")
            diff_label, diff_color = MISSION_DIFFICULTY.get(mk, ("", ""))
            diff_tag = f"  {diff_color}[{diff_label}]{RESET}" if diff_label else ""
            options.append((mk, f"{status} Mission {num}: {name}  ({diff_color}{topic}{RESET}){diff_tag}"))

        choice = show_menu("Story Mode Missions", options)
        if choice == "back":
            return
        if choice == "quit":
            raise SystemExit

        _launch_mission(choice, progress)


def _check_prerequisites(mission_key: str, progress: dict) -> bool:
    """Check if the learner has completed recommended modules. Returns True to proceed."""
    prereqs = MISSION_PREREQUISITES.get(mission_key, [])
    missing = []
    for mod_key in prereqs:
        completed = len(progress.get("modules", {}).get(mod_key, {}).get("completed_lessons", []))
        total = MODULE_LESSON_COUNTS.get(mod_key, 0)
        if completed < total:
            missing.append((mod_key, MODULE_NAMES.get(mod_key, mod_key), completed, total))

    if not missing:
        return True

    warning("This mission builds on knowledge from modules you haven't completed yet:")
    for mod_key, mod_name, done, total in missing:
        print(f"  {Y}•{RESET} {mod_name} ({done}/{total} lessons)")
    print()
    info("Completing these modules first will help you succeed in this mission.")
    return ask_yes_no("Continue anyway?")


def _launch_mission(mission_key: str, progress: dict):
    """Lazy-load and run a mission."""
    if not _check_prerequisites(mission_key, progress):
        return
    try:
        mod = importlib.import_module(MISSION_MODULES[mission_key])
        mod.run(progress)
    except Exception as e:
        error(f"Error loading mission: {e}")
        import traceback
        traceback.print_exc()
        press_enter()
