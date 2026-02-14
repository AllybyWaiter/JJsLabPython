#!/usr/bin/env python3
"""
JJ's LAB — Ethical Hacking & Penetration Testing Learning Platform

A terminal-based interactive application for learning security fundamentals.
For authorized internal use only. All exercises run against localhost.

Usage:
    python main.py

Requirements:
    pip install -r requirements.txt
"""

import sys
import os
import subprocess
import signal

# Ensure project root is on the path
sys.path.insert(0, os.path.dirname(__file__))

from utils.display import (
    clear_screen, banner, section_header, sub_header, show_menu,
    info, success, warning, error, disclaimer, press_enter,
    progress_bar, ask_yes_no, C, G, Y, R, RESET, BRIGHT, DIM
)
from utils.progress import (
    load_progress, save_progress, init_progress, get_overall_stats,
    MODULE_NAMES, MODULE_LESSON_COUNTS
)
from utils.audit_checklist import checklist_menu
from utils.site_tester import site_tester_menu
from exercises.exercise_runner import exercises_menu


# Module imports — lazy-loaded to avoid startup cost
MODULE_RUNNERS = {
    "module0": "lessons.module0_python_basics",
    "module1": "lessons.module1_python_security",
    "module2": "lessons.module2_network_fundamentals",
    "module3": "lessons.module3_web_security",
    "module4": "lessons.module4_password_security",
    "module5": "lessons.module5_recon_osint",
    "module6": "lessons.module6_vuln_scanning",
    "module7": "lessons.module7_log_analysis",
    "module8": "lessons.module8_secure_coding",
}

# Track the vulnerable app process
vuln_app_process = None


def load_module(module_key: str):
    """Lazy-import and return a module's run function."""
    import importlib
    mod = importlib.import_module(MODULE_RUNNERS[module_key])
    return mod.run


def show_progress_dashboard(progress: dict):
    """Display the progress dashboard."""
    section_header("Your Progress Dashboard")
    stats = get_overall_stats(progress)

    sub_header("Overall Progress")
    progress_bar(stats["completed_lessons"], stats["total_lessons"], "Lessons  ")
    progress_bar(stats["total_challenges"], 10, "Challenges")  # 10 total challenges

    if stats["total_quizzes"] > 0:
        avg = stats["quiz_score"] / stats["quiz_possible"] * 100 if stats["quiz_possible"] else 0
        info(f"Quizzes completed: {stats['total_quizzes']}  |  Average score: {avg:.0f}%")
    else:
        info("No quizzes completed yet.")

    info(f"Difficulty level: {stats['difficulty'].title()}")
    info(f"Audit checklists generated: {progress.get('audit_checklists_generated', 0)}")
    info(f"Site tests run: {progress.get('site_tests_run', 0)}")

    sub_header("Module Breakdown")
    for mod_key, mod_name in MODULE_NAMES.items():
        mod_data = progress["modules"][mod_key]
        completed = len(mod_data["completed_lessons"])
        total = MODULE_LESSON_COUNTS[mod_key]
        quizzes = len(mod_data["quiz_scores"])
        challenges = len(mod_data["challenges_done"])

        if completed == total:
            status = f"{G}[Complete]{RESET}"
        elif completed > 0:
            status = f"{Y}[In Progress]{RESET}"
        else:
            status = f"{DIM}[Not Started]{RESET}"

        print(f"  {status} {mod_name}")
        print(f"         Lessons: {completed}/{total}  |  Quizzes: {quizzes}  |  Challenges: {challenges}")

    press_enter()


def settings_menu(progress: dict):
    """Settings and configuration."""
    while True:
        choice = show_menu("Settings", [
            ("difficulty", f"Change Difficulty (current: {progress.get('difficulty', 'beginner').title()})"),
            ("reset", "Reset All Progress"),
            ("about", "About JJ's LAB"),
        ])

        if choice == "back":
            return
        if choice == "quit":
            raise SystemExit

        if choice == "difficulty":
            diff = show_menu("Select Difficulty", [
                ("beginner", "Beginner — Detailed explanations, step-by-step guidance"),
                ("intermediate", "Intermediate — Less hand-holding, harder challenges"),
                ("advanced", "Advanced — Minimal guidance, real-world complexity"),
            ], back=False)
            if diff != "quit":
                progress["difficulty"] = diff
                save_progress(progress)
                success(f"Difficulty set to: {diff.title()}")
                press_enter()

        elif choice == "reset":
            if ask_yes_no("Are you sure you want to reset ALL progress? This cannot be undone"):
                username = progress.get("user", "Analyst")
                progress.update(init_progress(username))
                success("Progress has been reset.")
                press_enter()

        elif choice == "about":
            section_header("About JJ's LAB")
            info("JJ's LAB — Ethical Hacking & Penetration Testing Learning Platform")
            info("Version: 1.0.0")
            info("Purpose: Internal security education and awareness")
            print()
            info("This application teaches defensive security concepts through")
            info("hands-on exercises that run entirely on your local machine.")
            print()
            sub_header("Resources")
            print(f"  {C}OWASP Top 10:{RESET}      https://owasp.org/www-project-top-ten/")
            print(f"  {C}NIST Framework:{RESET}     https://www.nist.gov/cyberframework")
            print(f"  {C}SANS Resources:{RESET}     https://www.sans.org/reading-room/")
            print(f"  {C}MITRE ATT&CK:{RESET}       https://attack.mitre.org/")
            print(f"  {C}CIS Benchmarks:{RESET}     https://www.cisecurity.org/cis-benchmarks")
            press_enter()


def start_vulnerable_app():
    """Start the vulnerable Flask app in the background."""
    global vuln_app_process

    if vuln_app_process and vuln_app_process.poll() is None:
        info("Vulnerable app is already running on http://127.0.0.1:5050")
        press_enter()
        return

    section_header("Start Vulnerable Practice App")
    disclaimer()

    warning("This starts an INTENTIONALLY VULNERABLE web application on localhost:5050.")
    warning("It is for practice ONLY and binds to 127.0.0.1 (not accessible externally).")
    print()

    if not ask_yes_no("Start the vulnerable practice app?"):
        return

    app_path = os.path.join(os.path.dirname(__file__), "vulnerable_app", "app.py")
    try:
        vuln_app_process = subprocess.Popen(
            [sys.executable, app_path],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        success(f"Vulnerable app started! PID: {vuln_app_process.pid}")
        info("Access it at: http://127.0.0.1:5050")
        info("It will run in the background until you stop it or exit JJ's LAB.")
    except Exception as e:
        error(f"Failed to start: {e}")

    press_enter()


def stop_vulnerable_app():
    """Stop the vulnerable Flask app."""
    global vuln_app_process
    if vuln_app_process and vuln_app_process.poll() is None:
        vuln_app_process.terminate()
        vuln_app_process.wait(timeout=5)
        vuln_app_process = None
        success("Vulnerable app stopped.")
    else:
        info("Vulnerable app is not running.")


def cleanup(signum=None, frame=None):
    """Clean up on exit."""
    stop_vulnerable_app()
    print(f"\n{C}Thanks for learning with JJ's LAB. Stay secure!{RESET}\n")
    sys.exit(0)


def modules_menu(progress: dict):
    """Learning modules menu."""
    while True:
        options = []
        for mod_key, mod_name in MODULE_NAMES.items():
            mod_data = progress["modules"][mod_key]
            completed = len(mod_data["completed_lessons"])
            total = MODULE_LESSON_COUNTS[mod_key]

            if completed == total:
                status = f"{G}✓{RESET}"
            elif completed > 0:
                status = f"{Y}◐{RESET}"
            else:
                status = f"{DIM}○{RESET}"

            num = mod_key.replace("module", "")
            options.append((mod_key, f"{status} Module {num}: {mod_name} ({completed}/{total})"))

        choice = show_menu("Learning Modules", options)
        if choice == "back":
            return
        if choice == "quit":
            raise SystemExit

        try:
            run_fn = load_module(choice)
            run_fn(progress)
        except Exception as e:
            error(f"Error loading module: {e}")
            import traceback
            traceback.print_exc()
            press_enter()


def main():
    """Main application entry point."""
    signal.signal(signal.SIGINT, cleanup)
    signal.signal(signal.SIGTERM, cleanup)

    clear_screen()
    banner()
    disclaimer()

    # Load or create progress
    progress = load_progress()
    if not progress.get("user"):
        print()
        info("Welcome to JJ's LAB! Let's get you set up.")
        username = input(f"  {C}What's your name? {RESET}").strip() or "Security Analyst"
        progress = init_progress(username)
        print()
        success(f"Hey {username}! Great to have you here.")
        print()
        info("A few tips before you start:")
        print(f"  {C}-{RESET} Start with Module 0 (Python Fundamentals) if you're new to coding")
        print(f"  {C}-{RESET} Each lesson is broken into small, easy steps")
        print(f"  {C}-{RESET} Take your time -- there's no rush!")
        print(f"  {C}-{RESET} Your progress is saved automatically")
        press_enter()

    # Main loop
    while True:
        clear_screen()
        banner()

        stats = get_overall_stats(progress)
        progress_bar(stats["completed_lessons"], stats["total_lessons"], "Overall ")
        print()

        user = progress.get("user", "Analyst")
        info(f"Welcome back, {user}!")
        print()

        choice = show_menu("Main Menu", [
            ("modules", "Learning Modules  (start here!)"),
            ("exercises", "Practice Challenges"),
            ("vuln_app", "Start Vulnerable Practice App"),
            ("site_test", "Test Your Own Site"),
            ("checklist", "Generate Security Audit Checklist"),
            ("progress", "View Progress Dashboard"),
            ("settings", "Settings"),
        ], back=False)

        if choice == "quit":
            cleanup()

        elif choice == "modules":
            modules_menu(progress)

        elif choice == "exercises":
            exercises_menu(progress)

        elif choice == "vuln_app":
            start_vulnerable_app()

        elif choice == "site_test":
            site_tester_menu(progress)

        elif choice == "checklist":
            checklist_menu(progress)

        elif choice == "progress":
            show_progress_dashboard(progress)

        elif choice == "settings":
            settings_menu(progress)


if __name__ == "__main__":
    main()
