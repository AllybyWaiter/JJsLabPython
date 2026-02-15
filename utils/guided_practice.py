"""
Guided Practice engine for JJ's LAB.

Breaks a practice challenge into small, verified steps with progressive hints.
Each step checks for required keywords in the user's code, gives hints on
failure, and shows the answer before moving on — so beginners are never stuck.
"""

from utils.display import (
    sub_header, info, success, error, hint_text, code_block,
    nice_work, press_enter, C, G, Y, DIM, BRIGHT, RESET, TERM_WIDTH,
)


def guided_practice(
    title: str,
    intro: str,
    steps: list = None,
    complete_solution: str = None,
    difficulty: str = "beginner",
) -> dict:
    """Run a multi-step guided practice challenge.

    Parameters
    ----------
    title : str
        Name of the practice challenge.
    intro : str
        Brief description shown before step 1.
    steps : list[dict]
        Each dict must have: instruction, required_keywords, hints, solution.
        Optional: context_code (str) shown before the prompt.
    complete_solution : str or None
        Full solution shown at end. If None, assembled from step solutions.
    difficulty : str
        Difficulty level: "beginner" (3 attempts), "intermediate" (2),
        "advanced" (1).

    Returns
    -------
    dict  {"steps_passed": int, "steps_total": int}
    """
    sub_header(f"Guided Practice: {title}")
    info(intro)
    info(f"This challenge has {len(steps)} steps. Let's build it one piece at a time.\n")
    press_enter()

    max_attempts = {"beginner": 3, "intermediate": 2, "advanced": 1}.get(difficulty, 3)

    steps_passed = 0
    collected_code = []

    for i, step in enumerate(steps, 1):
        passed, code = _run_step(i, len(steps), step, max_attempts=max_attempts, difficulty=difficulty)
        collected_code.append(code)
        if passed:
            steps_passed += 1

    _show_summary(title, steps_passed, len(steps), collected_code, complete_solution)

    return {"steps_passed": steps_passed, "steps_total": len(steps)}


def _run_step(
    step_num: int,
    total_steps: int,
    step: dict,
    max_attempts: int = 3,
    difficulty: str = "beginner",
) -> tuple[bool, str]:
    """Run a single guided practice step. Returns (passed, code)."""
    print(f"\n{C}{BRIGHT}  Step {step_num}/{total_steps}{RESET}")
    print(f"  {'─' * (TERM_WIDTH - 4)}")
    info(step["instruction"])
    print()

    context = step.get("context_code")
    if context:
        info("Here's what you have so far:")
        code_block(context)

    info("Type your code below (blank line to submit):")
    print()

    hints = step.get("hints", [])
    hint_idx = 0
    required = step["required_keywords"]
    solution = step["solution"]
    attempt = 0

    while attempt < max_attempts:
        lines = []
        while True:
            line = input(f"  {G}>>>{RESET} ")
            if line == "":
                break
            lines.append(line)

        code = "\n".join(lines)
        if not code.strip():
            continue

        found = [kw for kw in required if kw.lower() in code.lower()]

        if len(found) >= len(required):
            print()
            success(f"Step {step_num} complete!")
            print()
            return True, code

        attempt += 1
        remaining = max_attempts - attempt
        missing = [kw for kw in required if kw.lower() not in code.lower()]

        if remaining > 0:
            error(f"Not quite — missing: {', '.join(missing)}. {remaining} attempt(s) left.")
            if difficulty != "advanced" and hint_idx < len(hints):
                hint_text(hints[hint_idx])
                hint_idx += 1
        else:
            print()
            error(f"No attempts left for step {step_num}.")
            info("Here's the answer for this step:")
            code_block(solution)
            press_enter()
            return False, solution

    return False, solution


def _show_summary(
    title: str,
    steps_passed: int,
    total_steps: int,
    collected_code: list,
    complete_solution: str,
):
    """Show results and the full assembled solution."""
    sub_header(f"Practice Complete: {title}")
    print(f"  Steps passed: {steps_passed}/{total_steps}")
    print()

    if steps_passed == total_steps:
        nice_work("You completed every step! Excellent work.")
    elif steps_passed >= total_steps // 2:
        info("Good effort! Review the steps you missed and try again later.")
    else:
        info("Keep practicing — each step builds your skills.")

    print()
    sub_header("Complete Solution")
    if complete_solution:
        code_block(complete_solution)
    else:
        assembled = "\n\n".join(collected_code)
        code_block(assembled)

    press_enter()
