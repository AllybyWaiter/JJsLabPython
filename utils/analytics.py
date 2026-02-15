"""
Progress analytics module for JJ's LAB.
Provides time tracking, weak-area identification, and study recommendations.
"""

import time
from datetime import datetime, timedelta

from utils.display import (
    section_header,
    sub_header,
    info,
    success,
    warning,
    progress_bar,
    press_enter,
    C,
    G,
    Y,
    R,
    RESET,
    BRIGHT,
    DIM,
)
from utils.progress import (
    save_progress,
    MODULE_NAMES,
    MODULE_LESSON_COUNTS,
    MISSION_NAMES,
)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _ensure_analytics(progress: dict) -> dict:
    """Make sure the analytics sub-dict exists with all required keys."""
    analytics = progress.setdefault("analytics", {})
    analytics.setdefault("lesson_timing", {})
    analytics.setdefault("task_attempts", {})
    analytics.setdefault("days_active", [])
    return analytics


# ---------------------------------------------------------------------------
# Recording functions
# ---------------------------------------------------------------------------

def record_lesson_start(progress: dict, module_key: str, lesson_id: str):
    """Record when a lesson starts (for timing).

    Stores the start timestamp in
    progress["analytics"]["lesson_timing"]["<module_key>:<lesson_id>"]["started"].
    """
    analytics = _ensure_analytics(progress)
    timing_key = f"{module_key}:{lesson_id}"
    timing = analytics["lesson_timing"].setdefault(timing_key, {})
    timing["started"] = datetime.now().isoformat()
    save_progress(progress)


def record_lesson_end(progress: dict, module_key: str, lesson_id: str):
    """Record when a lesson ends and calculate duration.

    Calculates the elapsed seconds between started and now, then stores
    the completed timestamp and duration_sec in the timing entry.
    If no start time was recorded the function still stores the completed
    timestamp with a duration of 0.
    """
    analytics = _ensure_analytics(progress)
    timing_key = f"{module_key}:{lesson_id}"
    timing = analytics["lesson_timing"].setdefault(timing_key, {})

    now = datetime.now()
    timing["completed"] = now.isoformat()

    started_iso = timing.get("started")
    if started_iso:
        try:
            started_dt = datetime.fromisoformat(started_iso)
            timing["duration_sec"] = max(0, int((now - started_dt).total_seconds()))
        except (ValueError, TypeError):
            timing["duration_sec"] = 0
    else:
        timing["duration_sec"] = 0

    save_progress(progress)


def record_task_attempt(progress: dict, task_id: str, scored: int, max_score: int):
    """Track an individual task attempt for identifying weak areas.

    Appends an entry to
    progress["analytics"]["task_attempts"][task_id] list.
    """
    analytics = _ensure_analytics(progress)
    attempts = analytics["task_attempts"].setdefault(task_id, [])
    attempts.append({
        "score": scored,
        "max": max_score,
        "date": datetime.now().isoformat(),
    })
    save_progress(progress)


# ---------------------------------------------------------------------------
# Analysis functions
# ---------------------------------------------------------------------------

def get_weak_areas(progress: dict) -> list[dict]:
    """Identify modules/topics where the learner scored below 70%.

    Returns a list of dicts, each containing:
        module_key  -- e.g. "module3"
        module_name -- e.g. "Web Application Security"
        score       -- total quiz score in that module
        possible    -- total quiz possible in that module
        pct         -- percentage (0-100)
    """
    weak = []
    modules = progress.get("modules", {})
    for mod_key, mod_name in MODULE_NAMES.items():
        mod = modules.get(mod_key, {})
        quiz_scores = mod.get("quiz_scores", {})
        if not quiz_scores:
            continue
        total_score = sum(q.get("score", 0) for q in quiz_scores.values())
        total_possible = sum(q.get("total", 0) for q in quiz_scores.values())
        if total_possible == 0:
            continue
        pct = total_score / total_possible * 100
        if pct < 70:
            weak.append({
                "module_key": mod_key,
                "module_name": mod_name,
                "score": total_score,
                "possible": total_possible,
                "pct": round(pct, 1),
            })
    # Sort weakest first
    weak.sort(key=lambda w: w["pct"])
    return weak


def _calc_streak(days_active: list[str]) -> int:
    """Return the current consecutive-day streak ending today or yesterday."""
    if not days_active:
        return 0
    try:
        dates = sorted({datetime.strptime(d, "%Y-%m-%d").date() for d in days_active}, reverse=True)
    except (ValueError, TypeError):
        return 0
    today = datetime.now().date()
    # The streak must start from today or yesterday
    if dates[0] != today and dates[0] != today - timedelta(days=1):
        return 0
    streak = 1
    for i in range(1, len(dates)):
        if dates[i - 1] - dates[i] == timedelta(days=1):
            streak += 1
        else:
            break
    return streak


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------

def analytics_dashboard(progress: dict):
    """Display a detailed analytics view covering time, performance, and recommendations."""
    analytics = _ensure_analytics(progress)

    section_header("ANALYTICS DASHBOARD")

    # ------------------------------------------------------------------
    # 1. Time Summary
    # ------------------------------------------------------------------
    sub_header("Time Summary")

    lesson_timing = analytics.get("lesson_timing", {})
    total_seconds = 0
    timed_lessons = 0
    for _key, entry in lesson_timing.items():
        dur = entry.get("duration_sec", 0)
        if dur > 0:
            total_seconds += dur
            timed_lessons += 1

    if total_seconds > 0:
        hours = total_seconds // 3600
        minutes = (total_seconds % 3600) // 60
        if hours > 0:
            info(f"Total time spent learning: {hours}h {minutes}m")
        else:
            info(f"Total time spent learning: {minutes}m")
        if timed_lessons > 0:
            avg_sec = total_seconds // timed_lessons
            avg_min = avg_sec // 60
            avg_rem = avg_sec % 60
            info(f"Average time per lesson:   {avg_min}m {avg_rem}s  ({timed_lessons} lessons timed)")
    else:
        info("No lesson timing data recorded yet.")

    # ------------------------------------------------------------------
    # 2. Module Performance
    # ------------------------------------------------------------------
    sub_header("Module Performance")

    modules = progress.get("modules", {})
    any_quiz = False
    for mod_key in sorted(MODULE_NAMES.keys()):
        mod = modules.get(mod_key, {})
        quiz_scores = mod.get("quiz_scores", {})
        if not quiz_scores:
            continue
        any_quiz = True
        total_score = sum(q.get("score", 0) for q in quiz_scores.values())
        total_possible = sum(q.get("total", 0) for q in quiz_scores.values())
        pct = (total_score / total_possible * 100) if total_possible else 0
        mod_name = MODULE_NAMES[mod_key]

        # Color-code by performance
        if pct >= 70:
            color = G
        elif pct >= 50:
            color = Y
        else:
            color = R

        filled = min(int(pct / 100 * 20), 20)
        bar = f"{'█' * filled}{'░' * (20 - filled)}"
        print(f"  {mod_name}")
        print(f"    [{color}{bar}{RESET}] {total_score}/{total_possible} ({color}{pct:.0f}%{RESET})")

    if not any_quiz:
        info("No quiz scores recorded yet.")

    # ------------------------------------------------------------------
    # 3. Weak Areas
    # ------------------------------------------------------------------
    sub_header("Weak Areas (below 70%)")

    weak_areas = get_weak_areas(progress)
    if weak_areas:
        for w in weak_areas:
            warning(
                f"{w['module_name']} -- {w['score']}/{w['possible']} "
                f"({R}{w['pct']}%{RESET})"
            )
    else:
        success("No weak areas detected. Great job!")

    # ------------------------------------------------------------------
    # 4. Streak
    # ------------------------------------------------------------------
    sub_header("Activity Streak")

    days_active = analytics.get("days_active", [])
    streak = _calc_streak(days_active)
    total_days = len(set(days_active))

    if streak > 0:
        flame = "".join([">" for _ in range(min(streak, 20))])
        print(f"  {Y}{BRIGHT}Current streak: {streak} day{'s' if streak != 1 else ''}{RESET}  {R}{flame}{RESET}")
    else:
        info("No active streak. Start one today!")
    info(f"Total unique days active: {total_days}")

    # ------------------------------------------------------------------
    # 5. Missions
    # ------------------------------------------------------------------
    sub_header("Mission Scores")

    missions = progress.get("missions", {})
    any_mission = False
    for m_key in sorted(MISSION_NAMES.keys()):
        m = missions.get(m_key, {})
        if not m.get("completed", False):
            continue
        any_mission = True
        m_name = MISSION_NAMES[m_key]
        m_score = m.get("score", 0)
        m_max = m.get("max_score", 100)
        m_pct = (m_score / m_max * 100) if m_max else 0

        if m_pct >= 70:
            color = G
        elif m_pct >= 50:
            color = Y
        else:
            color = R

        filled = min(int(m_pct / 100 * 20), 20)
        bar = f"{'█' * filled}{'░' * (20 - filled)}"
        print(f"  {m_name}")
        print(f"    [{color}{bar}{RESET}] {m_score}/{m_max} ({color}{m_pct:.0f}%{RESET})")

    if not any_mission:
        info("No missions completed yet.")

    # ------------------------------------------------------------------
    # 6. Recommendations
    # ------------------------------------------------------------------
    sub_header("Recommendations")

    recommendations = []

    # Recommend review of weak modules
    for w in weak_areas:
        recommendations.append(
            f"You should review {C}{BRIGHT}{w['module_name']}{RESET} "
            f"(scored {w['pct']}%)"
        )

    # Recommend next uncompleted mission
    for m_key in sorted(MISSION_NAMES.keys()):
        m = missions.get(m_key, {})
        if not m.get("completed", False):
            recommendations.append(
                f"Ready for {Y}{BRIGHT}{MISSION_NAMES[m_key]}{RESET}? "
                f"Start it from the Missions menu!"
            )
            break

    # Recommend continuing incomplete modules
    for mod_key in sorted(MODULE_NAMES.keys()):
        mod = modules.get(mod_key, {})
        completed_count = len(mod.get("completed_lessons", []))
        total_count = MODULE_LESSON_COUNTS.get(mod_key, 0)
        if 0 < completed_count < total_count:
            recommendations.append(
                f"Continue {C}{BRIGHT}{MODULE_NAMES[mod_key]}{RESET} "
                f"-- {completed_count}/{total_count} lessons done"
            )

    if recommendations:
        for rec in recommendations:
            print(f"  {G}>{RESET} {rec}")
    else:
        success("You're on track! Keep up the great work.")

    print()
    press_enter()


# ---------------------------------------------------------------------------
# Session timer & attempt tracking (Feature: Progress Analytics)
# ---------------------------------------------------------------------------

def start_session_timer(progress: dict):
    """Record the start of a learning session."""
    progress.setdefault("analytics", {})
    progress["analytics"]["session_start"] = time.time()


def end_session_timer(progress: dict):
    """Record session end and accumulate total time."""
    analytics = progress.get("analytics", {})
    start = analytics.pop("session_start", None)
    if start:
        elapsed = time.time() - start
        analytics["total_time_seconds"] = analytics.get("total_time_seconds", 0) + elapsed
        analytics["session_count"] = analytics.get("session_count", 0) + 1
    progress["analytics"] = analytics
    save_progress(progress)


def record_attempt(progress: dict, module_key: str, lesson_id: str, success_flag: bool):
    """Record a practice attempt (pass or fail) for weak-topic tracking."""
    analytics = progress.setdefault("analytics", {})
    attempts = analytics.setdefault("attempts", {})
    key = f"{module_key}:{lesson_id}"
    entry = attempts.setdefault(key, {"total": 0, "passed": 0})
    entry["total"] += 1
    if success_flag:
        entry["passed"] += 1
    save_progress(progress)


def show_analytics_dashboard(progress: dict):
    """Display detailed analytics about the learner's progress."""
    section_header("Learning Analytics")
    analytics = progress.get("analytics", {})

    # Time tracking
    sub_header("Time Invested")
    total_seconds = analytics.get("total_time_seconds", 0)
    hours = int(total_seconds // 3600)
    minutes = int((total_seconds % 3600) // 60)
    sessions = analytics.get("session_count", 0)
    info(f"Total study time: {hours}h {minutes}m")
    info(f"Sessions: {sessions}")
    if sessions > 0:
        avg = total_seconds / sessions / 60
        info(f"Average session: {avg:.0f} minutes")

    # Weak topics
    sub_header("Topic Mastery")
    attempts = analytics.get("attempts", {})
    weak_topics = []
    for key, data in attempts.items():
        rate = data["passed"] / data["total"] if data["total"] > 0 else 0
        mod_key = key.split(":")[0]
        mod_name = MODULE_NAMES.get(mod_key, mod_key)
        if rate < 0.5 and data["total"] >= 2:
            weak_topics.append((mod_name, key, rate, data["total"]))

    if weak_topics:
        warning("Topics that need more practice:")
        for mod_name, key, rate, total in sorted(weak_topics, key=lambda x: x[2]):
            print(f"  {R}*{RESET} {mod_name} -- {key.split(':')[1]} ({rate*100:.0f}% success, {total} attempts)")
    else:
        success("No weak topics identified yet. Keep practicing!")

    # Module completion rates
    sub_header("Completion Rates")
    for mod_key, mod_name in MODULE_NAMES.items():
        completed = len(progress.get("modules", {}).get(mod_key, {}).get("completed_lessons", []))
        total = MODULE_LESSON_COUNTS.get(mod_key, 0)
        if total > 0:
            progress_bar(completed, total, f"{mod_name[:20]:20s}")

    # Mission scores
    sub_header("Mission Performance")
    missions = progress.get("missions", {})
    for mk, mdata in missions.items():
        if mdata.get("completed"):
            score = mdata.get("score", 0)
            color = G if score >= 90 else Y if score >= 50 else R
            print(f"  {color}*{RESET} {mk}: {score}%")

    press_enter()
