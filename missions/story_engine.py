"""
Story Engine — reusable interactive task types for story-mode missions.

Provides five task types that missions can use:
  - command_task:  user types a command (validated against accepted answers)
  - code_task:     user writes a Python snippet (validated by keywords)
  - puzzle_task:   user solves a puzzle (decode, identify, etc.)
  - choice_task:   pick an approach — different choices award different points
  - quiz_task:     quick inline knowledge check
"""

from __future__ import annotations

import re
import textwrap

from utils.display import (
    C, G, Y, R, M, DIM, BRIGHT, RESET, TERM_WIDTH,
    narrator, terminal_prompt, sub_header, info, success,
    warning, error, hint_text, code_block, press_enter, nice_work,
)


# ---------------------------------------------------------------------------
# Command task — type a real command
# ---------------------------------------------------------------------------

def command_task(
    prompt_text: str,
    accepted: list[str],
    points: int = 20,
    hints: list[str] | None = None,
    case_sensitive: bool = False,
) -> int:
    """Ask the user to type a command.  Returns points earned."""
    sub_header("COMMAND TASK")
    narrator(prompt_text)
    print()

    hints = hints or []
    hint_idx = 0
    attempts = 0
    max_attempts = 3

    while attempts < max_attempts:
        answer = input(f"  {G}{BRIGHT}root@target:~${RESET} ").strip()
        if not answer:
            continue

        match = _check_answer(answer, accepted, case_sensitive)
        if match:
            success(f"Correct!  +{points} pts")
            print()
            return points

        attempts += 1
        remaining = max_attempts - attempts
        if remaining > 0:
            error(f"Not quite. {remaining} attempt(s) remaining.")
            if hint_idx < len(hints):
                hint_text(hints[hint_idx])
                hint_idx += 1
        else:
            error("Out of attempts.")
            info(f"The expected command was:  {accepted[0]}")
            half = points // 2
            info(f"Partial credit: +{half} pts")
            print()
            return half

    return 0


# ---------------------------------------------------------------------------
# Code task — write a Python snippet
# ---------------------------------------------------------------------------

def code_task(
    prompt_text: str,
    required_keywords: list[str],
    points: int = 25,
    hints: list[str] | None = None,
    example_solution: str = "",
) -> int:
    """Ask the user to write a code snippet.  Returns points earned."""
    sub_header("CODE TASK")
    narrator(prompt_text)
    info("Type your code below (enter a blank line to submit):")
    print()

    hints = hints or []
    hint_idx = 0
    attempts = 0
    max_attempts = 3

    while attempts < max_attempts:
        lines = []
        while True:
            line = input(f"  {G}>>>{RESET} ")
            if line == "":
                break
            lines.append(line)

        code = "\n".join(lines)
        if not code.strip():
            continue

        # Check if required keywords appear in code
        found = [kw for kw in required_keywords if kw.lower() in code.lower()]
        if len(found) >= len(required_keywords):
            success(f"Great code!  +{points} pts")
            print()
            return points

        attempts += 1
        remaining = max_attempts - attempts
        missing = [kw for kw in required_keywords if kw.lower() not in code.lower()]
        if remaining > 0:
            error(f"Missing key elements: {', '.join(missing)}. {remaining} attempt(s) left.")
            if hint_idx < len(hints):
                hint_text(hints[hint_idx])
                hint_idx += 1
        else:
            error("Out of attempts.")
            if example_solution:
                info("Here's one approach:")
                code_block(example_solution, "python")
            half = points // 2
            info(f"Partial credit: +{half} pts")
            print()
            return half

    return 0


# ---------------------------------------------------------------------------
# Puzzle task — decode / identify / answer
# ---------------------------------------------------------------------------

def puzzle_task(
    prompt_text: str,
    accepted: list[str],
    points: int = 20,
    hints: list[str] | None = None,
    case_sensitive: bool = False,
) -> int:
    """Present a puzzle (decode hash, find vuln, read log). Returns points."""
    sub_header("PUZZLE TASK")
    narrator(prompt_text)
    print()

    hints = hints or []
    hint_idx = 0
    attempts = 0
    max_attempts = 3

    while attempts < max_attempts:
        answer = input(f"  {M}{BRIGHT}Answer:{RESET} ").strip()
        if not answer:
            continue

        match = _check_answer(answer, accepted, case_sensitive)
        if match:
            success(f"That's it!  +{points} pts")
            print()
            return points

        attempts += 1
        remaining = max_attempts - attempts
        if remaining > 0:
            error(f"Not quite. {remaining} attempt(s) remaining.")
            if hint_idx < len(hints):
                hint_text(hints[hint_idx])
                hint_idx += 1
        else:
            error("Out of attempts.")
            info(f"The answer was:  {accepted[0]}")
            half = points // 2
            info(f"Partial credit: +{half} pts")
            print()
            return half

    return 0


# ---------------------------------------------------------------------------
# Choice task — pick your approach
# ---------------------------------------------------------------------------

def choice_task(
    prompt_text: str,
    options: list[tuple[str, str, int]],
) -> int:
    """Present a tactical choice.  Returns points based on chosen option.

    options: list of (key_label, description, points_awarded)
    """
    sub_header("TACTICAL CHOICE")
    narrator(prompt_text)
    print()

    for i, (label, desc, _pts) in enumerate(options, 1):
        print(f"  {C}{BRIGHT}{i}.{RESET} {label}")
        wrapped = textwrap.fill(desc, width=TERM_WIDTH - 10)
        for line in wrapped.split("\n"):
            print(f"       {DIM}{line}{RESET}")
    print()

    while True:
        raw = input(f"  {C}  ▶ Your choice: {RESET}").strip()
        try:
            idx = int(raw) - 1
            if 0 <= idx < len(options):
                label, desc, pts = options[idx]
                print()
                if pts == max(o[2] for o in options):
                    success(f"Excellent choice — {label}.  +{pts} pts")
                else:
                    info(f"You chose: {label}.  +{pts} pts")
                print()
                return pts
        except ValueError:
            pass
        error("Pick a number from the list.")


# ---------------------------------------------------------------------------
# Quiz task — inline knowledge check
# ---------------------------------------------------------------------------

def quiz_task(
    question: str,
    options: list[str],
    correct_index: int,
    explanation: str = "",
    points: int = 10,
) -> int:
    """Quick inline quiz question.  Returns points earned."""
    sub_header("KNOWLEDGE CHECK")
    narrator(question)
    print()

    labels = "ABCD"
    for i, opt in enumerate(options):
        print(f"  {C}{labels[i]}.{RESET} {opt}")
    print()

    attempts = 0
    while attempts < 2:
        raw = input(f"  {C}  ▶ Your answer: {RESET}").strip().upper()
        if not raw:
            continue
        idx = labels.find(raw)
        if idx == -1:
            error("Enter A, B, C, or D.")
            continue
        if idx == correct_index:
            success(f"Correct!  +{points} pts")
            if explanation:
                info(explanation)
            print()
            return points
        attempts += 1
        if attempts < 2:
            error("Not quite — try once more.")
        else:
            error(f"The answer was {labels[correct_index]}.")
            if explanation:
                info(explanation)
            half = points // 2
            info(f"Partial credit: +{half} pts")
            print()
            return half

    return 0


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _check_answer(answer: str, accepted: list[str], case_sensitive: bool) -> bool:
    """Check if answer matches any accepted answer (supports regex patterns)."""
    for pattern in accepted:
        if case_sensitive:
            if re.fullmatch(pattern, answer):
                return True
        else:
            if re.fullmatch(pattern, answer, re.IGNORECASE):
                return True
    return False


def stage_intro(stage_num: int, title: str):
    """Print a stage header within a mission."""
    width = TERM_WIDTH
    print()
    print(f"  {Y}{BRIGHT}{'━' * (width - 4)}")
    print(f"   STAGE {stage_num}: {title}")
    print(f"  {'━' * (width - 4)}{RESET}")
    print()
