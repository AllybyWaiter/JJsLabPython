"""
Quiz engine for JJ's LAB.
Presents multiple-choice questions, scores them, and records results.
"""

from utils.display import (
    sub_header, success, error, info, press_enter, G, R, Y, C, RESET, BRIGHT, DIM
)
from utils.progress import record_quiz_score


def run_quiz(
    questions: list[dict],
    quiz_id: str,
    module_key: str,
    progress: dict,
) -> tuple[int, int]:
    """Run a quiz and return (score, total).

    Each question dict:
      {
        "q": "Question text",
        "options": ["A) ...", "B) ...", "C) ...", "D) ..."],
        "answer": "a",
        "explanation": "Why this is correct..."
      }
    """
    sub_header(f"Quiz: {quiz_id.replace('_', ' ').title()}")
    info(f"{len(questions)} questions — type the letter of your answer.\n")

    score = 0
    for i, q in enumerate(questions, 1):
        print(f"  {C}{BRIGHT}Q{i}.{RESET} {q['q']}\n")
        for opt in q["options"]:
            print(f"      {opt}")
        print()

        while True:
            ans = input(f"  {C}Your answer: {RESET}").strip().lower()
            if ans in ("a", "b", "c", "d"):
                break
            error("Please enter a, b, c, or d.")

        if ans == q["answer"]:
            score += 1
            success(f"Correct! {q.get('explanation', '')}")
        else:
            error(f"Incorrect. The answer is {q['answer'].upper()}.")
            info(q.get("explanation", ""))
        print()

    total = len(questions)
    pct = (score / total * 100) if total else 0

    print(f"\n  {'─' * 40}")
    if pct >= 80:
        print(f"  {G}{BRIGHT}Score: {score}/{total} ({pct:.0f}%) — Excellent!{RESET}")
    elif pct >= 60:
        print(f"  {Y}{BRIGHT}Score: {score}/{total} ({pct:.0f}%) — Good, review missed topics.{RESET}")
    else:
        print(f"  {R}{BRIGHT}Score: {score}/{total} ({pct:.0f}%) — Consider re-reading the lesson.{RESET}")
    print(f"  {'─' * 40}")

    record_quiz_score(progress, module_key, quiz_id, score, total)
    press_enter()
    return score, total
