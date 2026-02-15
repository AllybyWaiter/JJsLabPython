"""
Code execution engine for JJ's LAB.
Provides embedded code running, multiline input, and auto-graded exercises.
"""

import sys
import os
import tempfile
import subprocess

from utils.display import (
    section_header, sub_header, lesson_block, code_block, info, success,
    error as error_msg, warning, hint_text, press_enter, ask_yes_no,
    C, G, Y, R, RESET, BRIGHT, DIM
)


def run_code(code, stdin_input="", timeout=5):
    """Run Python code in a subprocess and return results.

    Returns dict with keys: stdout, stderr, returncode, timed_out, error
    """
    tmp = None
    try:
        tmp = tempfile.NamedTemporaryFile(
            mode="w", suffix=".py", delete=False
        )
        tmp.write(code)
        tmp.close()

        result = subprocess.run(
            [sys.executable, tmp.name],
            input=stdin_input,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return {
            "stdout": result.stdout,
            "stderr": result.stderr,
            "returncode": result.returncode,
            "timed_out": False,
            "error": None,
        }
    except subprocess.TimeoutExpired:
        return {
            "stdout": "",
            "stderr": "",
            "returncode": -1,
            "timed_out": True,
            "error": f"Code timed out after {timeout} seconds",
        }
    except Exception as e:
        return {
            "stdout": "",
            "stderr": str(e),
            "returncode": -1,
            "timed_out": False,
            "error": str(e),
        }
    finally:
        if tmp and os.path.exists(tmp.name):
            os.unlink(tmp.name)


def collect_code(starter_code="", prompt_text="Enter your code"):
    """Collect multiline code input with line numbers.

    Blank line submits. Returns the code string, or "" on Ctrl+C.
    """
    print(f"\n  {C}{BRIGHT}{prompt_text}{RESET}")
    print(f"  {DIM}(enter a blank line to submit, Ctrl+C to cancel){RESET}\n")

    lines = []

    # Display starter code if provided
    if starter_code:
        starter_lines = starter_code.strip().split("\n")
        for i, line in enumerate(starter_lines, 1):
            print(f"  {DIM}{i:02d}|{RESET} {line}")
        lines = list(starter_lines)
        start_num = len(starter_lines) + 1
    else:
        start_num = 1

    try:
        line_num = start_num
        while True:
            try:
                user_input = input(f"  {DIM}{line_num:02d}|{RESET} ")
            except EOFError:
                break
            if user_input == "":
                break
            lines.append(user_input)
            line_num += 1
    except KeyboardInterrupt:
        print(f"\n  {DIM}(cancelled){RESET}")
        return ""

    return "\n".join(lines)


def code_exercise(instruction, test_cases, starter_code="", hints=None, solution="", max_attempts=3):
    """Run an auto-graded coding exercise.

    Args:
        instruction: What the user should write
        test_cases: List of dicts with keys: input, expected_output, description
        starter_code: Optional pre-populated code
        hints: List of hint strings
        solution: Complete solution code
        max_attempts: Max tries before showing solution

    Returns True if all tests passed.
    """
    if hints is None:
        hints = []

    sub_header("Coding Exercise")
    lesson_block(instruction)

    # Show test case descriptions
    print(f"  {C}Test Cases:{RESET}")
    for i, tc in enumerate(test_cases, 1):
        print(f"  {C}{i}.{RESET} {tc['description']}")
    print()

    hints_shown = 0
    attempts = 0

    while attempts < max_attempts:
        code = collect_code(starter_code=starter_code)
        if not code:
            return False

        attempts += 1
        all_passed = True

        print(f"\n  {C}Running tests...{RESET}\n")
        for tc in test_cases:
            result = run_code(code, stdin_input=tc.get("input", ""))

            if result["timed_out"]:
                print(f"  {R}[TIMEOUT]{RESET} {tc['description']} -- code took too long")
                all_passed = False
            elif result["error"]:
                print(f"  {R}[ERROR]{RESET}   {tc['description']} -- {result['error']}")
                all_passed = False
            elif tc["expected_output"] in result["stdout"]:
                print(f"  {G}[PASS]{RESET}    {tc['description']}")
            else:
                print(f"  {R}[FAIL]{RESET}    {tc['description']}")
                if result["stderr"]:
                    print(f"           {DIM}Error: {result['stderr'].strip().split(chr(10))[-1]}{RESET}")
                else:
                    print(f"           {DIM}Expected output to contain: {tc['expected_output']}{RESET}")
                    if result["stdout"].strip():
                        print(f"           {DIM}Got: {result['stdout'].strip()[:100]}{RESET}")
                all_passed = False

        print()

        if all_passed:
            success("All tests passed!")
            return True

        remaining = max_attempts - attempts
        if remaining > 0:
            warning(f"{remaining} attempt(s) remaining")

            # Offer a hint if available
            if hints_shown < len(hints):
                if ask_yes_no("Would you like a hint?"):
                    hint_text(hints[hints_shown])
                    hints_shown += 1
            print()
        else:
            warning("No attempts remaining.")
            if solution:
                if ask_yes_no("Would you like to see the solution?"):
                    code_block(solution)
            return False

    return False
