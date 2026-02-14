"""
Story Mode mission selection menu with completion status.
"""

import importlib

from utils.display import (
    show_menu, section_header, info, error, press_enter,
    G, Y, R, C, DIM, BRIGHT, RESET,
)
from utils.progress import MISSION_NAMES


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
            options.append((mk, f"{status} Mission {num}: {name}  ({topic})"))

        choice = show_menu("Story Mode Missions", options)
        if choice == "back":
            return
        if choice == "quit":
            raise SystemExit

        _launch_mission(choice, progress)


def _launch_mission(mission_key: str, progress: dict):
    """Lazy-load and run a mission."""
    try:
        mod = importlib.import_module(MISSION_MODULES[mission_key])
        mod.run(progress)
    except Exception as e:
        error(f"Error loading mission: {e}")
        import traceback
        traceback.print_exc()
        press_enter()
