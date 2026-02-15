"""Pre-assessment quiz — helps new users find the right starting point."""

from utils.display import (
    section_header, sub_header, info, success, warning, error,
    press_enter, show_menu, C, G, Y, R, DIM, BRIGHT, RESET
)
from utils.progress import MODULE_NAMES, save_progress


QUESTIONS = [
    {
        "question": "What does 'print(type(42))' output in Python?",
        "options": ["<class 'int'>", "<class 'str'>", "42", "Error"],
        "correct": 0,
        "module": "module0",  # Python basics
    },
    {
        "question": "What does a 'for' loop do in Python?",
        "options": [
            "Repeats code a set number of times",
            "Defines a function",
            "Imports a module",
            "Creates a variable",
        ],
        "correct": 0,
        "module": "module0",
    },
    {
        "question": "What port does HTTP typically run on?",
        "options": ["21", "22", "80", "443"],
        "correct": 2,
        "module": "module2",  # Network fundamentals
    },
    {
        "question": "What does TCP's three-way handshake establish?",
        "options": [
            "A reliable connection between two hosts",
            "An encrypted tunnel",
            "A DNS resolution",
            "A firewall rule",
        ],
        "correct": 0,
        "module": "module2",
    },
    {
        "question": "What is SQL injection?",
        "options": [
            "Inserting malicious SQL into application queries",
            "A type of encryption",
            "A network scanning technique",
            "A password cracking method",
        ],
        "correct": 0,
        "module": "module3",  # Web security
    },
    {
        "question": "What does XSS stand for?",
        "options": [
            "Cross-Site Scripting",
            "Extended Security Standard",
            "Cross-Server Sync",
            "XML Security Schema",
        ],
        "correct": 0,
        "module": "module3",
    },
    {
        "question": "Which hash algorithm is considered insecure for password storage?",
        "options": ["bcrypt", "Argon2", "MD5", "scrypt"],
        "correct": 2,
        "module": "module4",  # Password security
    },
    {
        "question": "What is OSINT?",
        "options": [
            "Open Source Intelligence — gathering info from public sources",
            "Operating System Integration",
            "Online Security Investigation Network",
            "Output Signal Intelligence",
        ],
        "correct": 0,
        "module": "module5",  # Recon/OSINT
    },
    {
        "question": "In a web server log, what does HTTP status code 401 mean?",
        "options": [
            "Success",
            "Unauthorized — authentication required",
            "Not Found",
            "Server Error",
        ],
        "correct": 1,
        "module": "module7",  # Log analysis
    },
    {
        "question": "What is the principle of least privilege?",
        "options": [
            "Users should only have the minimum access needed for their role",
            "All users should have admin access",
            "Privileges should be granted permanently",
            "Security rules should be as simple as possible",
        ],
        "correct": 0,
        "module": "module8",  # Secure coding / general
    },
]


def run_pre_assessment(progress: dict):
    """Run the pre-assessment quiz and recommend a starting module."""
    section_header("Skills Assessment")
    info("Answer 10 quick questions to find the best starting point for you.")
    info("Don't worry about getting them wrong — that's the whole point!")
    print()
    press_enter()

    # Track scores per module
    module_scores = {}
    total_correct = 0

    for i, q in enumerate(QUESTIONS, 1):
        sub_header(f"Question {i}/10")
        print(f"  {BRIGHT}{q['question']}{RESET}")
        print()

        labels = "ABCD"
        for j, opt in enumerate(q["options"]):
            print(f"  {C}{labels[j]}.{RESET} {opt}")
        print()

        while True:
            answer = input(f"  {C}▶ Your answer: {RESET}").strip().upper()
            if answer in labels[:len(q["options"])]:
                break
            error("Enter A, B, C, or D.")

        idx = labels.index(answer)
        mod = q["module"]
        module_scores.setdefault(mod, {"correct": 0, "total": 0})
        module_scores[mod]["total"] += 1

        if idx == q["correct"]:
            success("Correct!")
            module_scores[mod]["correct"] += 1
            total_correct += 1
        else:
            info(f"The answer was {labels[q['correct']]}. {q['options'][q['correct']]}")
        print()

    # Determine recommendation
    section_header("Your Results")
    print(f"  Score: {total_correct}/10")
    print()

    # Find weakest areas
    weak_modules = []
    for mod_key, scores in sorted(module_scores.items()):
        rate = scores["correct"] / scores["total"]
        mod_name = MODULE_NAMES.get(mod_key, mod_key)
        if rate < 1.0:
            color = R if rate == 0 else Y
            print(f"  {color}•{RESET} {mod_name}: {scores['correct']}/{scores['total']}")
            weak_modules.append((mod_key, mod_name, rate))
        else:
            print(f"  {G}•{RESET} {mod_name}: {scores['correct']}/{scores['total']}")

    print()

    # Save assessment results
    progress.setdefault("analytics", {})
    progress["analytics"]["pre_assessment_score"] = total_correct
    progress["analytics"]["pre_assessment_taken"] = True
    save_progress(progress)

    # Recommendation
    sub_header("Recommendation")
    if total_correct <= 3:
        success("Start with Module 0: Python Fundamentals")
        info("Build a strong foundation — the lessons are designed to take you step by step!")
        progress["recommended_start"] = "module0"
    elif total_correct <= 6:
        # Find the weakest module
        if weak_modules:
            weakest = sorted(weak_modules, key=lambda x: x[2])[0]
            success(f"Start with {weakest[1]}")
            info("You have some knowledge — focus on the areas where you need more practice.")
            progress["recommended_start"] = weakest[0]
        else:
            success("Start with Module 2: Network Fundamentals")
            progress["recommended_start"] = "module2"
    else:
        success("You're ready for the intermediate modules!")
        info("Try Module 5 (Recon & OSINT) or jump straight into Story Mode Missions.")
        progress["recommended_start"] = "module5"

    save_progress(progress)
    press_enter()
