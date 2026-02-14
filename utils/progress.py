"""
Progress tracking system.
Saves and loads user progress from a local JSON file.
"""

import json
import os
from datetime import datetime

PROGRESS_FILE = os.path.join(os.path.dirname(os.path.dirname(__file__)), "progress.json")

DEFAULT_MISSIONS = {
    "mission1": {"completed": False, "score": 0, "max_score": 100},
    "mission2": {"completed": False, "score": 0, "max_score": 100},
    "mission3": {"completed": False, "score": 0, "max_score": 100},
    "mission4": {"completed": False, "score": 0, "max_score": 100},
    "mission5": {"completed": False, "score": 0, "max_score": 100},
}

MISSION_NAMES = {
    "mission1": "Operation Broken Gate",
    "mission2": "Shadow on the Wire",
    "mission3": "The Vault",
    "mission4": "Ghost Protocol",
    "mission5": "Code Red",
}

DEFAULT_PROGRESS = {
    "user": "",
    "started": "",
    "last_active": "",
    "modules": {
        "module0": {"completed_lessons": [], "quiz_scores": {}, "challenges_done": []},
        "module1": {"completed_lessons": [], "quiz_scores": {}, "challenges_done": []},
        "module2": {"completed_lessons": [], "quiz_scores": {}, "challenges_done": []},
        "module3": {"completed_lessons": [], "quiz_scores": {}, "challenges_done": []},
        "module4": {"completed_lessons": [], "quiz_scores": {}, "challenges_done": []},
        "module5": {"completed_lessons": [], "quiz_scores": {}, "challenges_done": []},
        "module6": {"completed_lessons": [], "quiz_scores": {}, "challenges_done": []},
        "module7": {"completed_lessons": [], "quiz_scores": {}, "challenges_done": []},
        "module8": {"completed_lessons": [], "quiz_scores": {}, "challenges_done": []},
    },
    "missions": DEFAULT_MISSIONS.copy(),
    "difficulty": "beginner",
    "audit_checklists_generated": 0,
    "site_tests_run": 0,
}

MODULE_NAMES = {
    "module0": "Python Fundamentals (Start Here!)",
    "module1": "Python for Security",
    "module2": "Network Fundamentals",
    "module3": "Web Application Security",
    "module4": "Password Security",
    "module5": "Reconnaissance & OSINT",
    "module6": "Vulnerability Scanning",
    "module7": "Log Analysis & Incident Response",
    "module8": "Secure Coding Practices",
}

# Total lessons per module (used for progress tracking)
MODULE_LESSON_COUNTS = {
    "module0": 6,
    "module1": 6,
    "module2": 4,
    "module3": 5,
    "module4": 4,
    "module5": 4,
    "module6": 4,
    "module7": 4,
    "module8": 4,
}


def load_progress() -> dict:
    """Load progress from disk, or return defaults."""
    if os.path.exists(PROGRESS_FILE):
        with open(PROGRESS_FILE, "r") as f:
            try:
                progress = json.load(f)
            except json.JSONDecodeError:
                return DEFAULT_PROGRESS.copy()
        # Backfill any new modules added after initial save
        for mod_key in MODULE_NAMES:
            if mod_key not in progress.get("modules", {}):
                progress.setdefault("modules", {})[mod_key] = {
                    "completed_lessons": [], "quiz_scores": {}, "challenges_done": []
                }
        # Backfill missions for existing users
        if "missions" not in progress:
            progress["missions"] = {
                k: {"completed": False, "score": 0, "max_score": 100}
                for k in MISSION_NAMES
            }
        else:
            for mk in MISSION_NAMES:
                if mk not in progress["missions"]:
                    progress["missions"][mk] = {"completed": False, "score": 0, "max_score": 100}
        return progress
    return DEFAULT_PROGRESS.copy()


def save_progress(progress: dict):
    """Persist progress to disk."""
    progress["last_active"] = datetime.now().isoformat()
    with open(PROGRESS_FILE, "w") as f:
        json.dump(progress, f, indent=2)


def init_progress(username: str) -> dict:
    """Create a new progress record."""
    progress = DEFAULT_PROGRESS.copy()
    progress["user"] = username
    progress["started"] = datetime.now().isoformat()
    progress["modules"] = {
        k: {"completed_lessons": [], "quiz_scores": {}, "challenges_done": []}
        for k in MODULE_NAMES
    }
    progress["missions"] = {
        k: {"completed": False, "score": 0, "max_score": 100}
        for k in MISSION_NAMES
    }
    save_progress(progress)
    return progress


def mark_lesson_complete(progress: dict, module_key: str, lesson_id: str):
    if lesson_id not in progress["modules"][module_key]["completed_lessons"]:
        progress["modules"][module_key]["completed_lessons"].append(lesson_id)
    save_progress(progress)


def record_quiz_score(progress: dict, module_key: str, quiz_id: str, score: int, total: int):
    progress["modules"][module_key]["quiz_scores"][quiz_id] = {
        "score": score,
        "total": total,
        "date": datetime.now().isoformat(),
    }
    save_progress(progress)


def mark_challenge_complete(progress: dict, module_key: str, challenge_id: str):
    if challenge_id not in progress["modules"][module_key]["challenges_done"]:
        progress["modules"][module_key]["challenges_done"].append(challenge_id)
    save_progress(progress)


def mark_mission_complete(progress: dict, mission_key: str, score: int, max_score: int):
    """Record a completed mission with its score."""
    progress.setdefault("missions", {})[mission_key] = {
        "completed": True,
        "score": score,
        "max_score": max_score,
        "date": datetime.now().isoformat(),
    }
    save_progress(progress)


def get_overall_stats(progress: dict) -> dict:
    """Return aggregate stats across all modules."""
    total_lessons = sum(MODULE_LESSON_COUNTS.values())
    completed = sum(
        len(m["completed_lessons"]) for m in progress["modules"].values()
    )
    total_quizzes = 0
    total_quiz_score = 0
    total_quiz_possible = 0
    for m in progress["modules"].values():
        for q in m["quiz_scores"].values():
            total_quizzes += 1
            total_quiz_score += q["score"]
            total_quiz_possible += q["total"]
    total_challenges = sum(
        len(m["challenges_done"]) for m in progress["modules"].values()
    )
    return {
        "total_lessons": total_lessons,
        "completed_lessons": completed,
        "total_quizzes": total_quizzes,
        "quiz_score": total_quiz_score,
        "quiz_possible": total_quiz_possible,
        "total_challenges": total_challenges,
        "difficulty": progress.get("difficulty", "beginner"),
    }
