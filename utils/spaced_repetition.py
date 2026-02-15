"""
Spaced repetition quiz review system for JJ's LAB.

Tracks quiz performance over time and schedules reviews at scientifically-backed
intervals (1, 3, 7, 14, 30 days). Poor scores reset the interval so learners
revisit weak topics sooner.

Usage:
    from utils.spaced_repetition import record_quiz_review, reviews_summary, review_menu
"""

from datetime import datetime, timedelta

from utils.display import (
    section_header,
    sub_header,
    info,
    success,
    warning,
    press_enter,
    show_menu,
    C,
    G,
    Y,
    RESET,
    BRIGHT,
    DIM,
)
from utils.progress import save_progress, MODULE_NAMES

# Intervals indexed by successful-attempt count (0-based).
# Each entry is the number of days until the next review.
_INTERVALS = [1, 3, 7, 14, 30]

# Score threshold -- below this percentage the interval resets.
_PASSING_PCT = 70


# ---------------------------------------------------------------------------
# Core helpers
# ---------------------------------------------------------------------------

def _review_key(module_key: str, quiz_id: str) -> str:
    """Build the composite key used inside progress['quiz_reviews']."""
    return f"{module_key}:{quiz_id}"


def _next_interval(attempts: list[dict]) -> int:
    """Return the number of days until the next scheduled review.

    Walk the attempt history forward.  Every passing attempt (>= 70 %)
    advances one step through ``_INTERVALS``.  A failing attempt resets
    the position back to the beginning.
    """
    level = 0
    for attempt in attempts:
        pct = (attempt["score"] / attempt["total"] * 100) if attempt["total"] else 0
        if pct >= _PASSING_PCT:
            level = min(level + 1, len(_INTERVALS) - 1)
        else:
            level = 0
    return _INTERVALS[level]


def _is_due(attempts: list, now=None) -> bool:
    """Return True if the quiz is due for review right now."""
    if not attempts:
        return False
    now = now or datetime.now()
    last = attempts[-1]
    last_date = datetime.fromisoformat(last["date"])
    interval_days = _next_interval(attempts)
    return now >= last_date + timedelta(days=interval_days)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def record_quiz_review(
    progress: dict,
    module_key: str,
    quiz_id: str,
    score: int,
    total: int,
) -> None:
    """Record a quiz attempt for spaced repetition tracking.

    Appends the result to ``progress["quiz_reviews"][module_key:quiz_id]``.
    The progress dict is saved to disk automatically.
    """
    reviews = progress.setdefault("quiz_reviews", {})
    key = _review_key(module_key, quiz_id)
    history = reviews.setdefault(key, [])
    history.append(
        {
            "date": datetime.now().isoformat(),
            "score": score,
            "total": total,
        }
    )
    save_progress(progress)


def get_due_reviews(progress: dict) -> list[dict]:
    """Return a list of quizzes that are due for review today.

    Each element is a dict with:
        module_key  -- e.g. "module0"
        quiz_id     -- e.g. "python_fundamentals"
        last_score  -- score from the most recent attempt
        last_total  -- total from the most recent attempt
        days_since  -- days since the last attempt
    """
    reviews = progress.get("quiz_reviews", {})
    now = datetime.now()
    due: list[dict] = []

    for key, attempts in reviews.items():
        if not attempts:
            continue
        if not _is_due(attempts, now):
            continue

        module_key, quiz_id = key.split(":", 1)
        last = attempts[-1]
        last_date = datetime.fromisoformat(last["date"])
        days_since = (now - last_date).days

        due.append(
            {
                "module_key": module_key,
                "quiz_id": quiz_id,
                "last_score": last["score"],
                "last_total": last["total"],
                "days_since": days_since,
            }
        )

    # Sort so the most overdue reviews appear first.
    due.sort(key=lambda r: r["days_since"], reverse=True)
    return due


def reviews_summary(progress: dict) -> str:
    """Return a short dashboard string.

    Examples:
        "3 quizzes ready for review"
        "1 quiz ready for review"
        "All caught up!"
    """
    count = len(get_due_reviews(progress))
    if count == 0:
        return "All caught up!"
    noun = "quiz" if count == 1 else "quizzes"
    return f"{count} {noun} ready for review"


def review_menu(progress: dict) -> None:
    """Interactive menu that shows due reviews and lets the user pick one.

    Displays each overdue quiz with its module name, last score, and how
    many days have passed.  The user can select a quiz to see details and
    is directed to the appropriate module to retake it.
    """
    while True:
        due = get_due_reviews(progress)

        if not due:
            section_header("Spaced Repetition Reviews")
            success("All caught up! No quizzes are due for review right now.")
            _show_schedule(progress)
            press_enter()
            return

        options: list[tuple[str, str]] = []
        for i, rev in enumerate(due):
            mod_name = MODULE_NAMES.get(rev["module_key"], rev["module_key"])
            quiz_label = rev["quiz_id"].replace("_", " ").title()
            pct = (
                (rev["last_score"] / rev["last_total"] * 100)
                if rev["last_total"]
                else 0
            )

            if pct < _PASSING_PCT:
                score_color = f"{Y}"
            else:
                score_color = f"{G}"

            label = (
                f"{mod_name} -- {quiz_label}  "
                f"{DIM}|{RESET} Last: {score_color}{rev['last_score']}/{rev['last_total']} "
                f"({pct:.0f}%){RESET}  "
                f"{DIM}|{RESET} {rev['days_since']}d ago"
            )
            options.append((str(i), label))

        choice = show_menu(
            f"Spaced Repetition Reviews  ({len(due)} due)",
            options,
        )

        if choice in ("back", "quit"):
            return

        try:
            idx = int(choice)
        except ValueError:
            continue

        if 0 <= idx < len(due):
            _show_review_detail(due[idx])


def _show_review_detail(review: dict) -> None:
    """Show details for a single due review and direct the user."""
    mod_name = MODULE_NAMES.get(review["module_key"], review["module_key"])
    quiz_label = review["quiz_id"].replace("_", " ").title()
    pct = (
        (review["last_score"] / review["last_total"] * 100)
        if review["last_total"]
        else 0
    )

    sub_header(f"Review: {quiz_label}")
    info(f"Module:     {mod_name}")
    info(f"Last score: {review['last_score']}/{review['last_total']} ({pct:.0f}%)")
    info(f"Last taken: {review['days_since']} day(s) ago")
    print()

    if pct < _PASSING_PCT:
        warning(
            "Your last score was below 70%. The interval has been reset "
            "so you can strengthen this topic sooner."
        )
    else:
        info(
            "You passed last time -- this is a scheduled refresher to "
            "keep the knowledge sharp."
        )
    print()

    mod_num = review["module_key"].replace("module", "")
    info(
        f"To retake this quiz, go to {C}{BRIGHT}Learning Modules > "
        f"Module {mod_num}: {mod_name}{RESET} and select the quiz option."
    )
    press_enter()


def _show_schedule(progress: dict) -> None:
    """Print upcoming review dates so the user knows what is coming."""
    reviews = progress.get("quiz_reviews", {})
    if not reviews:
        return

    now = datetime.now()
    upcoming: list[tuple[str, str, int]] = []

    for key, attempts in reviews.items():
        if not attempts:
            continue
        module_key, quiz_id = key.split(":", 1)
        last_date = datetime.fromisoformat(attempts[-1]["date"])
        interval = _next_interval(attempts)
        due_date = last_date + timedelta(days=interval)
        days_left = (due_date - now).days
        if days_left > 0:
            mod_name = MODULE_NAMES.get(module_key, module_key)
            quiz_label = quiz_id.replace("_", " ").title()
            upcoming.append((mod_name, quiz_label, days_left))

    if upcoming:
        upcoming.sort(key=lambda x: x[2])
        print()
        sub_header("Upcoming Reviews")
        for mod_name, quiz_label, days_left in upcoming:
            day_word = "day" if days_left == 1 else "days"
            print(
                f"  {DIM}-{RESET} {mod_name} -- {quiz_label}  "
                f"{C}(in {days_left} {day_word}){RESET}"
            )
        print()
