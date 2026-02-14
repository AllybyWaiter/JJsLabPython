"""
Module 0: Python Fundamentals
A prerequisite module for learners who are new to Python. Assumes zero prior
programming knowledge and teaches Python from the ground up, building the
foundation needed for all subsequent security modules.
"""

from utils.display import (
    section_header, sub_header, lesson_block, code_block,
    scenario_block, why_it_matters, info, success, warning, press_enter,
    show_menu, disclaimer, hint_text, ask_yes_no, C, G, Y, R, RESET, BRIGHT, DIM,
    pace, learning_goal, nice_work, tip
)
from utils.progress import mark_lesson_complete, mark_challenge_complete
from utils.quiz import run_quiz
from utils.guided_practice import guided_practice


# ──────────────────────────────────────────────────────────────────────
#  Module metadata
# ──────────────────────────────────────────────────────────────────────
MODULE_KEY = "module0"


# ──────────────────────────────────────────────────────────────────────
#  Lesson 1 — Getting Started: Variables & Data Types
# ──────────────────────────────────────────────────────────────────────
def lesson_variables_and_types(progress):
    section_header("Lesson 1: Getting Started -- Variables & Data Types")

    learning_goal([
        "Understand what variables are and how to create them",
        "Know the four basic data types: int, float, str, bool",
        "Convert between data types",
        "Work with strings and get input from the user",
    ])

    pace()

    lesson_block(
        "Welcome to Python! Python is one of the most popular programming "
        "languages in the world, and it is the number one language used in "
        "cybersecurity."
    )

    lesson_block(
        "Whether you want to automate tasks, analyze log files, "
        "write security tools, or understand how hackers think, Python is where "
        "you start. It was designed to be easy to read and write, which makes "
        "it perfect for beginners."
    )

    pace()

    lesson_block(
        "A program is simply a set of instructions that tells a computer what "
        "to do. Think of it like a recipe: you write down the steps, and the "
        "computer follows them one by one, from top to bottom."
    )

    pace()

    why_it_matters(
        "Python is the go-to language for security professionals. It is used "
        "to write penetration testing tools (like parts of Metasploit), analyze "
        "malware, parse log files during incident response, automate security "
        "scans, and build custom exploits. Learning Python is not optional in "
        "cybersecurity -- it is essential."
    )

    press_enter()

    # ── Comments ──
    sub_header("Comments -- Notes for Humans")

    lesson_block(
        "Before we write any real code, let's learn about comments. A comment "
        "is a note you leave in your code for yourself or other people. The "
        "computer completely ignores comments. They start with the # symbol."
    )

    pace()

    code_block("""\
# This is a comment -- Python ignores this line completely
# Comments help you (and others) understand your code later

# You can also put comments at the end of a line:
x = 10  # This stores the number 10 in a variable called x""")

    pace()

    code_block("""\
# Multi-line comments use triple quotes (also called docstrings):
\"\"\"
This is a multi-line comment.
It can span as many lines as you need.
Often used to describe what a function or file does.
\"\"\"""")

    tip("Good comments explain WHY you did something, not what the code does.")

    press_enter()

    # ── Variables ──
    sub_header("Variables -- Storing Information")

    lesson_block(
        "A variable is like a labeled box where you store information. You give "
        "the box a name, put something inside it, and later you can look inside "
        "the box to see what is there."
    )

    pace()

    lesson_block(
        "In Python, you create a variable by choosing a name, typing an equals "
        "sign, and then the value you want to store."
    )

    pace()

    code_block("""\
# Creating variables -- think of each as a labeled box
name = "Alice"          # A box labeled 'name' containing the text "Alice"
age = 25                # A box labeled 'age' containing the number 25
temperature = 98.6      # A box labeled 'temperature' containing a decimal
is_admin = True         # A box labeled 'is_admin' containing True or False

# You can see what is in a box using print()
print(name)             # Output: Alice
print(age)              # Output: 25
print(temperature)      # Output: 98.6
print(is_admin)         # Output: True""")

    pace()

    lesson_block(
        "Variable naming rules: (1) Names can contain letters, numbers, and "
        "underscores, but must start with a letter or underscore, never a "
        "number. (2) Names are case-sensitive -- 'Age' and 'age' are different "
        "variables."
    )

    pace()

    lesson_block(
        "(3) You cannot use Python keywords like 'if', 'for', "
        "'while', 'class', etc. as variable names. (4) Use descriptive names: "
        "'user_age' is better than 'x'."
    )

    pace()

    code_block("""\
# Good variable names -- clear and descriptive
user_name = "bob"
login_attempts = 3
max_password_length = 128
is_authenticated = False

# Bad variable names -- avoid these
x = "bob"              # What does 'x' mean? No one knows.
n = 3                  # Unclear
# 3attempts = 5        # ERROR: cannot start with a number
# my-var = 10          # ERROR: hyphens are not allowed, use underscores""")

    nice_work("You just learned about variables! That is a huge first step.")

    press_enter()

    # ── Data Types ──
    sub_header("Data Types -- Different Kinds of Information")

    lesson_block(
        "Not all information is the same. A person's name is text, their age "
        "is a whole number, their weight might have decimals, and whether they "
        "are logged in is either yes or no."
    )

    pace()

    lesson_block(
        "Python has different data types for each kind of information. "
        "Let's look at the four basic types."
    )

    pace()

    code_block("""\
# int -- whole numbers (no decimal point)
port_number = 443
failed_attempts = 7
year = 2025

# float -- decimal numbers
success_rate = 99.7
pi = 3.14159
temperature = -40.0""")

    pace()

    code_block("""\
# str -- strings of text (always in quotes)
hostname = "server01.company.com"
greeting = 'Hello, World!'     # Single or double quotes both work
ip_address = "192.168.1.1"

# bool -- True or False (only two possible values)
is_connected = True
has_firewall = False""")

    pace()

    code_block("""\
# Check the type of any variable using type()
print(type(port_number))    # Output: <class 'int'>
print(type(success_rate))   # Output: <class 'float'>
print(type(hostname))       # Output: <class 'str'>
print(type(is_connected))   # Output: <class 'bool'>""")

    tip("You can always check a variable's type with type(). It is great for debugging!")

    press_enter()

    # ── Type Conversion ──
    sub_header("Type Conversion -- Changing Between Types")

    lesson_block(
        "Sometimes you need to convert one type to another. For example, when "
        "you read input from a user, Python always gives you a string, even if "
        "the user typed a number."
    )

    pace()

    lesson_block(
        "You need to convert it to an integer before "
        "you can do math with it."
    )

    pace()

    code_block("""\
# Converting between types
age_text = "25"           # This is a string, not a number
age_number = int("25")    # Now it is an integer: 25
print(age_number + 5)     # Output: 30

price = float("19.99")    # Convert string to decimal: 19.99
count = str(42)            # Convert number to string: "42" """)

    pace()

    code_block("""\
# Be careful -- not everything can be converted!
# int("hello")  # ERROR: Python cannot turn "hello" into a number
# int("3.14")   # ERROR: Use float() first, then int()

# Safe conversion chain:
value = "3.14"
as_float = float(value)   # "3.14" -> 3.14
as_int = int(as_float)    # 3.14 -> 3 (drops the decimal part)
print(as_int)             # Output: 3""")

    nice_work("Data types and type conversion down. You are doing great!")

    press_enter()

    # ── Arithmetic ──
    sub_header("Arithmetic Operators -- Doing Math")

    code_block("""\
# Basic math operators
a = 10
b = 3

print(a + b)    # Addition:       13
print(a - b)    # Subtraction:    7
print(a * b)    # Multiplication: 30
print(a / b)    # Division:       3.3333... (always returns a float)
print(a // b)   # Floor division: 3 (rounds down to whole number)
print(a % b)    # Modulo:         1 (remainder of 10 / 3)
print(a ** b)   # Exponent:       1000 (10 to the power of 3)""")

    pace()

    code_block("""\
# Order of operations works like regular math: PEMDAS
result = 2 + 3 * 4     # 3 * 4 happens first = 14, not 20
result = (2 + 3) * 4   # Parentheses first = 20

# Shorthand operators (very common in real code)
count = 0
count += 1      # Same as: count = count + 1    -> count is now 1
count += 5      # Same as: count = count + 5    -> count is now 6
count -= 2      # Same as: count = count - 2    -> count is now 4
count *= 3      # Same as: count = count * 3    -> count is now 12""")

    press_enter()

    # ── Strings ──
    sub_header("String Basics -- Working with Text")

    lesson_block(
        "Strings are one of the most important data types, especially in "
        "security work where you are constantly dealing with usernames, "
        "passwords, IP addresses, log entries, URLs, and more."
    )

    pace()

    code_block("""\
# String concatenation (joining strings together)
first = "Cyber"
last = "Security"
full = first + last         # "CyberSecurity"
full_space = first + " " + last  # "Cyber Security"

# f-strings (formatted strings) -- the modern, preferred way
name = "Alice"
role = "analyst"
print(f"User {name} has the role: {role}")
# Output: User Alice has the role: analyst

# You can put any expression inside the curly braces
port = 443
print(f"Connecting to port {port + 1}")  # Output: Connecting to port 444""")

    pace()

    code_block("""\
# Useful string methods
message = "Hello, World!"
print(message.upper())        # "HELLO, WORLD!"
print(message.lower())        # "hello, world!"
print(message.replace("World", "Hacker"))  # "Hello, Hacker!"
print(len(message))           # 13 (length of the string)""")

    pace()

    code_block("""\
# Checking contents
email = "admin@company.com"
print(email.startswith("admin"))   # True
print(email.endswith(".com"))      # True
print("@" in email)                # True (checks if @ appears anywhere)

# Stripping whitespace (very useful when reading files or user input)
raw_input = "  hello  "
clean = raw_input.strip()     # "hello" (removes spaces from both sides)""")

    nice_work("You now know how to work with strings. That skill comes up everywhere!")

    press_enter()

    # ── User Input ──
    sub_header("Getting Input from the User")

    lesson_block(
        "The input() function pauses your program and waits for the user to "
        "type something. Whatever they type is returned as a string."
    )

    pace()

    code_block("""\
# Getting input from the user
name = input("What is your name? ")
print(f"Hello, {name}!")

# Remember: input() always returns a string!
age_text = input("How old are you? ")   # User types: 25
# age_text is the STRING "25", not the NUMBER 25
age = int(age_text)                      # Now it is the number 25
print(f"In 10 years you will be {age + 10}")

# You can combine input() and int() in one line:
port = int(input("Enter a port number: "))
print(f"Scanning port {port}...")""")

    pace()

    scenario_block("Social Engineering Awareness Tool", (
        "You are building a quick training tool that asks employees to enter "
        "their email address and then checks if it follows the company format. "
        "Using variables, strings, and input(), you collect the email, check "
        "if it ends with '@company.com' using .endswith(), and display whether "
        "it is valid. This simple script helps train employees to recognize "
        "phishing emails that use look-alike domains."
    ))

    tip("You can always come back and re-read this lesson later!")

    press_enter()

    # ── Guided Practice ──
    guided_practice(
        title="Simple Calculator",
        intro="Let's build a calculator step by step. Each step builds on the last.",
        steps=[
            {
                "instruction": (
                    "Get the user's input. Use input() to ask for two numbers "
                    "and convert them to floats. Store them in num1 and num2."
                ),
                "required_keywords": ["input", "float"],
                "hints": [
                    "Use float(input('Enter first number: ')) to get a number.",
                    "You need two separate input() calls — one for each number.",
                    "Pattern: num1 = float(input('...'))",
                ],
                "solution": (
                    'num1 = float(input("Enter first number: "))\n'
                    'num2 = float(input("Enter second number: "))'
                ),
            },
            {
                "instruction": (
                    "Ask the user for an operator (+, -, *, /). "
                    "Store it in a variable called operator."
                ),
                "context_code": (
                    'num1 = float(input("Enter first number: "))\n'
                    'num2 = float(input("Enter second number: "))'
                ),
                "required_keywords": ["input", "operator"],
                "hints": [
                    "Use input() again — no need to convert to float this time.",
                    'operator = input("Enter operator (+, -, *, /): ").strip()',
                ],
                "solution": 'operator = input("Enter operator (+, -, *, /): ").strip()',
            },
            {
                "instruction": (
                    "Use if/elif to check the operator and calculate the result. "
                    "Handle +, -, *, and /. Store the answer in a variable called result."
                ),
                "context_code": (
                    'num1 = float(input("Enter first number: "))\n'
                    'num2 = float(input("Enter second number: "))\n'
                    'operator = input("Enter operator (+, -, *, /): ").strip()'
                ),
                "required_keywords": ["if", "elif", "result"],
                "hints": [
                    'Start with: if operator == "+": result = num1 + num2',
                    "Add elif branches for -, *, and /.",
                    "For division, check if num2 == 0 before dividing.",
                ],
                "solution": (
                    'if operator == "+":\n'
                    '    result = num1 + num2\n'
                    'elif operator == "-":\n'
                    '    result = num1 - num2\n'
                    'elif operator == "*":\n'
                    '    result = num1 * num2\n'
                    'elif operator == "/":\n'
                    '    if num2 == 0:\n'
                    '        print("Error: Cannot divide by zero!")\n'
                    '        result = None\n'
                    '    else:\n'
                    '        result = num1 / num2'
                ),
            },
            {
                "instruction": (
                    "Print the result using an f-string that shows the full "
                    "equation, like: 15.0 * 4.0 = 60.0"
                ),
                "required_keywords": ["print", "result"],
                "hints": [
                    'Use an f-string: print(f"{num1} {operator} {num2} = {result}")',
                    "Check if result is not None before printing.",
                ],
                "solution": (
                    'if result is not None:\n'
                    '    print(f"Result: {num1} {operator} {num2} = {result}")'
                ),
            },
        ],
        complete_solution="""\
# Simple Calculator
num1 = float(input("Enter first number: "))
num2 = float(input("Enter second number: "))
operator = input("Enter operator (+, -, *, /): ").strip()

if operator == "+":
    result = num1 + num2
elif operator == "-":
    result = num1 - num2
elif operator == "*":
    result = num1 * num2
elif operator == "/":
    if num2 == 0:
        print("Error: Cannot divide by zero!")
        result = None
    else:
        result = num1 / num2
else:
    print(f"Unknown operator: {operator}")
    result = None

if result is not None:
    print(f"Result: {num1} {operator} {num2} = {result}")""",
    )

    mark_lesson_complete(progress, MODULE_KEY, "lesson1")
    success("Lesson 1 complete: Variables & Data Types")
    press_enter()


# ──────────────────────────────────────────────────────────────────────
#  Lesson 2 — Control Flow: Making Decisions
# ──────────────────────────────────────────────────────────────────────
def lesson_control_flow(progress):
    section_header("Lesson 2: Control Flow -- Making Decisions")

    learning_goal([
        "Use comparison operators to ask True/False questions",
        "Write if/elif/else blocks to make decisions",
        "Combine conditions with and, or, not",
        "Understand truthiness and falsy values",
    ])

    pace()

    lesson_block(
        "So far, our programs run every line from top to bottom without making "
        "any choices. But real programs need to make decisions: Is the password "
        "correct? Is this IP address on the blocklist?"
    )

    pace()

    lesson_block(
        "Control flow lets your program choose different paths depending "
        "on conditions. Think of it like a security guard at a door. The guard "
        "checks your badge: if the badge is valid, you get in; if it is expired, "
        "you are redirected; otherwise, you are turned away."
    )

    pace()

    why_it_matters(
        "Almost every security tool relies on decision-making. Firewalls "
        "decide whether to allow or block traffic. Intrusion detection systems "
        "decide whether network activity is suspicious. Login systems decide "
        "whether credentials are correct. Understanding control flow is the "
        "foundation for writing any security logic."
    )

    press_enter()

    # ── Comparison Operators ──
    sub_header("Comparison Operators -- Asking Questions")

    lesson_block(
        "Before you can make decisions, you need to ask questions. Comparison "
        "operators compare two values and return True or False (a boolean)."
    )

    pace()

    code_block("""\
# Comparison operators return True or False
x = 10
y = 20

print(x == y)     # Equal to?           False
print(x != y)     # Not equal to?       True
print(x < y)      # Less than?          True
print(x > y)      # Greater than?       False
print(x <= 10)    # Less than or equal? True
print(x >= 15)    # Greater or equal?   False""")

    pace()

    code_block("""\
# Works with strings too!
name = "Alice"
print(name == "Alice")     # True
print(name == "alice")     # False (case-sensitive!)
print(name != "Bob")       # True

# COMMON MISTAKE: == vs =
# x = 10     means "store 10 in x" (assignment)
# x == 10    means "is x equal to 10?" (comparison)""")

    tip("A single = assigns a value. A double == compares two values. Mix them up and you will get bugs!")

    press_enter()

    # ── if / elif / else ──
    sub_header("if / elif / else -- The Decision Structure")

    code_block("""\
# Basic if statement
age = 18

if age >= 18:
    print("You are an adult.")
    print("You can vote.")
# Output:
#   You are an adult.
#   You can vote.

# if/else -- two paths
password = "secret123"

if len(password) >= 8:
    print("Password length is acceptable.")
else:
    print("Password is too short! Must be at least 8 characters.")
# Output: Password length is acceptable.""")

    pace()

    code_block("""\
# if/elif/else -- multiple paths
score = 75

if score >= 90:
    grade = "A"
elif score >= 80:
    grade = "B"
elif score >= 70:
    grade = "C"
elif score >= 60:
    grade = "D"
else:
    grade = "F"

print(f"Your grade: {grade}")  # Output: Your grade: C""")

    pace()

    lesson_block(
        "Important: Notice the indentation (the spaces at the beginning of "
        "lines). Python uses indentation to know which lines belong inside "
        "the if block. Standard practice is to use 4 spaces for each level."
    )

    nice_work("You can now write programs that make decisions. That is a big deal!")

    press_enter()

    # ── Logical Operators ──
    sub_header("Logical Operators -- Combining Conditions")

    lesson_block(
        "Sometimes one condition is not enough. You might need to check if "
        "a user is BOTH logged in AND an admin. Or you might want to allow "
        "access if the user provides a valid password OR a valid token."
    )

    pace()

    code_block("""\
# 'and' -- BOTH conditions must be True
age = 25
has_id = True

if age >= 18 and has_id:
    print("Access granted")        # This runs
else:
    print("Access denied")

# 'or' -- at least ONE condition must be True
is_admin = False
has_override_key = True

if is_admin or has_override_key:
    print("Elevated access granted")  # This runs""")

    pace()

    code_block("""\
# 'not' -- reverses True to False and vice versa
is_blocked = False

if not is_blocked:
    print("User is not blocked")      # This runs

# Combining multiple operators
username = "admin"
password = "secure123"
is_locked = False

if username == "admin" and password == "secure123" and not is_locked:
    print("Login successful!")
else:
    print("Login failed.")""")

    press_enter()

    # ── Truthiness ──
    sub_header("Truthiness and Falsy Values")

    lesson_block(
        "In Python, every value can be treated as True or False, even if it "
        "is not a boolean. This is called 'truthiness'."
    )

    pace()

    lesson_block(
        "The following values "
        "are considered False (falsy): False, 0, 0.0, empty string '', empty "
        "list [], empty dict {}, and None. Everything else is True (truthy)."
    )

    pace()

    code_block("""\
# Falsy values -- these all act as False in an if statement
if not 0:
    print("0 is falsy")               # Prints
if not "":
    print("Empty string is falsy")     # Prints
if not []:
    print("Empty list is falsy")       # Prints
if not None:
    print("None is falsy")             # Prints""")

    pace()

    code_block("""\
# Truthy values -- these all act as True
if "hello":
    print("Non-empty string is truthy")  # Prints
if 42:
    print("Non-zero number is truthy")   # Prints
if [1, 2, 3]:
    print("Non-empty list is truthy")    # Prints

# Practical use: checking if a variable has a useful value
username = input("Enter username: ")

if username:
    print(f"Hello, {username}!")
else:
    print("Error: No username entered!")
# If the user presses Enter without typing, username is "" (falsy)""")

    nice_work("Truthiness is a tricky concept and you just nailed it!")

    press_enter()

    # ── Nested Conditions ──
    sub_header("Nested Conditions")

    code_block("""\
# You can put if statements inside other if statements
role = "admin"
mfa_verified = True
ip_address = "192.168.1.50"

if role == "admin":
    print("Admin user detected.")
    if mfa_verified:
        print("MFA verified -- full access granted.")
        if ip_address.startswith("192.168."):
            print("Connecting from internal network.")
        else:
            print("WARNING: Admin login from external network!")
    else:
        print("MFA required for admin accounts. Access denied.")
else:
    print("Standard user access.")""")

    pace()

    code_block("""\
# Tip: Deeply nested code (3+ levels) can be hard to read.
# Consider using 'and' to flatten conditions when possible:
if role == "admin" and mfa_verified and ip_address.startswith("192.168."):
    print("Internal admin with MFA -- full access.")""")

    tip("If your code is indented more than 3 levels deep, try to simplify with 'and'.")

    press_enter()

    # ── match/case ──
    sub_header("match/case -- Pattern Matching (Python 3.10+)")

    lesson_block(
        "Python 3.10 introduced match/case, which is similar to a switch "
        "statement in other languages. It is useful when you have many "
        "possible values to check against."
    )

    pace()

    code_block("""\
# match/case for clean multi-way branching
command = "scan"

match command:
    case "scan":
        print("Starting network scan...")
    case "report":
        print("Generating security report...")
    case "block":
        print("Adding to blocklist...")
    case "help":
        print("Available commands: scan, report, block, help")
    case _:
        print(f"Unknown command: {command}")
# The underscore _ is a wildcard that matches anything (like 'else')""")

    pace()

    scenario_block("Access Control Decision Engine", (
        "You are writing the logic for a company's internal portal. When an "
        "employee tries to access a sensitive resource, your Python script "
        "checks multiple conditions: Is the user authenticated? Is their "
        "account active? Is their IP from the corporate network? Do they "
        "have the right role? Each condition is an if/elif check, and the "
        "script logs every decision for the security team to audit later."
    ))

    press_enter()

    # ── Guided Practice ──
    guided_practice(
        title="Password Validator",
        intro="Let's build a password strength checker, one rule at a time.",
        steps=[
            {
                "instruction": (
                    "Define a function called validate_password that takes a "
                    "password parameter. Inside it, create an empty list called "
                    "issues, then check if the password is shorter than 8 characters "
                    "using len(). If it is, append a message to the issues list."
                ),
                "required_keywords": ["def", "len", "issues"],
                "hints": [
                    "Start with: def validate_password(password):",
                    "Create the list: issues = []",
                    'Check: if len(password) < 8: issues.append("Too short")',
                ],
                "solution": (
                    'def validate_password(password):\n'
                    '    issues = []\n'
                    '    if len(password) < 8:\n'
                    '        issues.append("Must be at least 8 characters long")'
                ),
            },
            {
                "instruction": (
                    "Add checks for uppercase, lowercase, and digit characters. "
                    "Loop through each character using a for loop and check with "
                    ".isupper(), .islower(), and .isdigit()."
                ),
                "required_keywords": ["for", "isupper", "isdigit"],
                "hints": [
                    "Use a boolean flag: has_upper = False, then set True when found.",
                    "for char in password: if char.isupper(): has_upper = True; break",
                    "After the loop, if not has_upper: issues.append('...')",
                ],
                "solution": (
                    '    has_upper = has_lower = has_digit = False\n'
                    '    for char in password:\n'
                    '        if char.isupper(): has_upper = True\n'
                    '        if char.islower(): has_lower = True\n'
                    '        if char.isdigit(): has_digit = True\n'
                    '    if not has_upper:\n'
                    '        issues.append("Must contain an uppercase letter")\n'
                    '    if not has_lower:\n'
                    '        issues.append("Must contain a lowercase letter")\n'
                    '    if not has_digit:\n'
                    '        issues.append("Must contain a digit")'
                ),
            },
            {
                "instruction": (
                    "Check if the password contains the forbidden word 'password' "
                    "(case-insensitive). Use .lower() to make the comparison work "
                    "regardless of capitalization."
                ),
                "required_keywords": ["password", "lower"],
                "hints": [
                    'Use: if "password" in password.lower()',
                    "This catches Password, PASSWORD, pAsSwOrD, etc.",
                ],
                "solution": (
                    '    if "password" in password.lower():\n'
                    '        issues.append("Must not contain the word \'password\'")'
                ),
            },
            {
                "instruction": (
                    "Print the results: if there are issues, print each one. "
                    "Otherwise print that the password is accepted."
                ),
                "required_keywords": ["print", "issues"],
                "hints": [
                    "Check: if issues: ... else: ...",
                    "Loop through issues with: for issue in issues: print(f'  - {issue}')",
                ],
                "solution": (
                    '    if issues:\n'
                    '        print("Password REJECTED:")\n'
                    '        for issue in issues:\n'
                    '            print(f"  - {issue}")\n'
                    '    else:\n'
                    '        print("Password ACCEPTED!")'
                ),
            },
        ],
        complete_solution="""\
def validate_password(password):
    issues = []

    if len(password) < 8:
        issues.append("Must be at least 8 characters long")

    has_upper = has_lower = has_digit = False
    for char in password:
        if char.isupper(): has_upper = True
        if char.islower(): has_lower = True
        if char.isdigit(): has_digit = True
    if not has_upper:
        issues.append("Must contain an uppercase letter")
    if not has_lower:
        issues.append("Must contain a lowercase letter")
    if not has_digit:
        issues.append("Must contain a digit")

    if "password" in password.lower():
        issues.append("Must not contain the word 'password'")

    if issues:
        print("Password REJECTED:")
        for issue in issues:
            print(f"  - {issue}")
    else:
        print("Password ACCEPTED!")

# Test it
for pw in ["short", "alllowercase1", "NoDigitsHere", "Str0ngP@ss!"]:
    print(f"\\nTesting: '{pw}'")
    validate_password(pw)""",
    )

    mark_lesson_complete(progress, MODULE_KEY, "lesson2")
    success("Lesson 2 complete: Control Flow")
    press_enter()


# ──────────────────────────────────────────────────────────────────────
#  Lesson 3 — Loops & Iteration
# ──────────────────────────────────────────────────────────────────────
def lesson_loops(progress):
    section_header("Lesson 3: Loops & Iteration")

    learning_goal([
        "Write for loops and while loops",
        "Use break, continue, and else on loops",
        "Loop with enumerate() and zip()",
        "Write list comprehensions for compact code",
    ])

    pace()

    lesson_block(
        "Imagine you need to check 1000 IP addresses to see which ones are "
        "online. You would not write 1000 separate lines of code. Instead, "
        "you use a loop -- a way to repeat a block of code over and over."
    )

    pace()

    lesson_block(
        "Python has two main types of loops. A 'for' loop repeats a fixed "
        "number of times. A 'while' loop keeps repeating as long as a "
        "condition is True."
    )

    pace()

    why_it_matters(
        "Security work is full of repetitive tasks: scanning every port on a "
        "server (65,535 of them), checking every line in a million-line log "
        "file, testing every URL in a wordlist for hidden pages, or trying "
        "every item in a password list. Without loops, none of this would be "
        "practical. Loops are the engine of every security tool."
    )

    press_enter()

    # ── for loops ──
    sub_header("for Loops -- Repeating a Known Number of Times")

    code_block("""\
# Looping through a list of items
ports = [22, 80, 443, 8080, 8443]

for port in ports:
    print(f"Scanning port {port}...")
# Output:
#   Scanning port 22...
#   Scanning port 80...
#   Scanning port 443...
#   Scanning port 8080...
#   Scanning port 8443...""")

    pace()

    code_block("""\
# range() generates a sequence of numbers
for i in range(5):
    print(f"Attempt {i}")
# Output: Attempt 0, Attempt 1, Attempt 2, Attempt 3, Attempt 4
# Note: range(5) gives 0, 1, 2, 3, 4 -- it stops BEFORE 5

# range() with start, stop, and step
for i in range(1, 11):        # 1 through 10
    print(i, end=" ")
print()  # Output: 1 2 3 4 5 6 7 8 9 10""")

    pace()

    code_block("""\
for i in range(0, 100, 10):   # 0, 10, 20, ... 90
    print(i, end=" ")
print()  # Output: 0 10 20 30 40 50 60 70 80 90

# Looping through a string (character by character)
password = "S3cur3!"
for char in password:
    print(f"  Character: {char}")""")

    nice_work("For loops are one of the most useful things in all of programming!")

    press_enter()

    # ── while loops ──
    sub_header("while Loops -- Repeating Until a Condition Changes")

    lesson_block(
        "A while loop checks a condition before each iteration. If the "
        "condition is True, it runs the code inside. Then it checks again. "
        "This continues until the condition becomes False."
    )

    tip("Be careful: if the condition never becomes False, you get an infinite loop!")

    pace()

    code_block("""\
# Basic while loop -- counting up
count = 0
while count < 5:
    print(f"Count is {count}")
    count += 1  # IMPORTANT: change the variable so the loop eventually stops
# Output: Count is 0, Count is 1, Count is 2, Count is 3, Count is 4""")

    pace()

    code_block("""\
# Practical example: retry logic for a network connection
import time
max_retries = 3
attempt = 0
connected = False

while attempt < max_retries and not connected:
    attempt += 1
    print(f"Connection attempt {attempt} of {max_retries}...")
    # Simulate a connection (in real code this would be a socket call)
    if attempt == 3:
        connected = True
        print("Connected!")
    else:
        print("Failed. Retrying...")""")

    pace()

    code_block("""\
# User input validation loop
while True:
    user_input = input("Enter a port (1-65535): ")
    if user_input.isdigit() and 1 <= int(user_input) <= 65535:
        port = int(user_input)
        print(f"Valid port: {port}")
        break  # Exit the loop
    else:
        print("Invalid input. Try again.")""")

    press_enter()

    # ── break, continue, else ──
    sub_header("break, continue, and else on Loops")

    lesson_block(
        "'break' immediately exits the loop -- the loop is done. 'continue' "
        "skips the rest of the current iteration and jumps to the next one."
    )

    pace()

    lesson_block(
        "The 'else' clause on a loop runs only if the loop finished normally "
        "(was not interrupted by break)."
    )

    pace()

    code_block("""\
# break -- stop the loop early
numbers = [1, 5, 3, 8, 2, 9, 4]

for num in numbers:
    if num > 7:
        print(f"Found a number greater than 7: {num}")
        break  # Stop looking
    print(f"  Checking {num}...")
# Output:
#   Checking 1...
#   Checking 5...
#   Checking 3...
#   Found a number greater than 7: 8""")

    pace()

    code_block("""\
# continue -- skip this iteration
log_lines = ["INFO: User logged in", "ERROR: Disk full",
             "INFO: File saved", "ERROR: Connection lost"]

print("Errors only:")
for line in log_lines:
    if not line.startswith("ERROR"):
        continue  # Skip non-error lines
    print(f"  {line}")
# Output:
#   ERROR: Disk full
#   ERROR: Connection lost""")

    pace()

    code_block("""\
# else on a loop -- runs only if loop completed without break
target_ip = "10.0.0.5"
suspicious_ips = ["192.168.1.100", "10.0.0.99", "172.16.0.50"]

for ip in suspicious_ips:
    if ip == target_ip:
        print(f"ALERT: {target_ip} is on the suspicious list!")
        break
else:
    print(f"{target_ip} is not on the suspicious list.")
# Output: 10.0.0.5 is not on the suspicious list.""")

    nice_work("break, continue, and else give you fine-grained control over your loops!")

    press_enter()

    # ── Nested Loops ──
    sub_header("Nested Loops -- Loops Inside Loops")

    code_block("""\
# Scanning multiple hosts on multiple ports
hosts = ["192.168.1.1", "192.168.1.2", "192.168.1.3"]
ports = [22, 80, 443]

for host in hosts:
    print(f"\\nScanning {host}:")
    for port in ports:
        print(f"  Checking port {port}...")
# Each host gets all three ports checked""")

    pace()

    code_block("""\
# Generating a multiplication table (just to illustrate)
for row in range(1, 4):
    for col in range(1, 4):
        print(f"{row * col:4}", end="")
    print()
# Output:
#    1   2   3
#    2   4   6
#    3   6   9""")

    press_enter()

    # ── enumerate and zip ──
    sub_header("enumerate() and zip() -- Loop Helpers")

    code_block("""\
# enumerate() -- get both the index AND the value
servers = ["web01", "db01", "mail01", "app01"]

for index, server in enumerate(servers):
    print(f"  Server #{index}: {server}")
# Output:
#   Server #0: web01
#   Server #1: db01
#   Server #2: mail01
#   Server #3: app01

# enumerate with a custom start number
for num, server in enumerate(servers, start=1):
    print(f"  {num}. {server}")""")

    pace()

    code_block("""\
# zip() -- loop through two lists in parallel
usernames = ["alice", "bob", "charlie"]
roles = ["admin", "user", "auditor"]

for user, role in zip(usernames, roles):
    print(f"  {user} -> {role}")
# Output:
#   alice -> admin
#   bob -> user
#   charlie -> auditor""")

    press_enter()

    # ── List Comprehensions ──
    sub_header("List Comprehensions -- Compact Loops")

    lesson_block(
        "A list comprehension is a shorthand way to create a new list by "
        "transforming or filtering items from another list. It puts a for "
        "loop and an optional if condition inside square brackets."
    )

    pace()

    code_block("""\
# Regular loop to create a list
squares = []
for i in range(10):
    squares.append(i ** 2)
print(squares)  # [0, 1, 4, 9, 16, 25, 36, 49, 64, 81]

# Same thing as a list comprehension (one line!)
squares = [i ** 2 for i in range(10)]
print(squares)  # [0, 1, 4, 9, 16, 25, 36, 49, 64, 81]""")

    pace()

    code_block("""\
# With a filter condition
numbers = [1, -2, 3, -4, 5, -6, 7]
positive = [n for n in numbers if n > 0]
print(positive)  # [1, 3, 5, 7]

# Practical: extract all IP addresses that start with "192."
all_ips = ["192.168.1.1", "10.0.0.5", "192.168.1.100", "172.16.0.1"]
internal = [ip for ip in all_ips if ip.startswith("192.")]
print(internal)  # ['192.168.1.1', '192.168.1.100']

# Transform strings
words = ["hello", "WORLD", "Python"]
lower_words = [w.lower() for w in words]
print(lower_words)  # ['hello', 'world', 'python']""")

    pace()

    scenario_block("Automated Port Scanning", (
        "A penetration tester needs to check which of the 65,535 TCP ports "
        "are open on a target server. Using a for loop with range(1, 65536), "
        "they attempt a connection to each port. For each successful connection "
        "they add the port to a list. After the scan, they use a list "
        "comprehension to filter only the 'interesting' ports (those commonly "
        "associated with vulnerable services). The entire scan is just 15 lines "
        "of Python."
    ))

    nice_work("Loops and list comprehensions are now in your toolkit!")

    press_enter()

    # ── Guided Practice ──
    guided_practice(
        title="Number Guessing Game",
        intro="Let's build a guessing game piece by piece.",
        steps=[
            {
                "instruction": (
                    "Import the random module and use random.randint(1, 100) to "
                    "pick a secret number. Store it in a variable called secret. "
                    "Also set up an attempts counter starting at 0."
                ),
                "required_keywords": ["import", "random", "randint"],
                "hints": [
                    "Start with: import random",
                    "Then: secret = random.randint(1, 100)",
                    "And: attempts = 0",
                ],
                "solution": (
                    'import random\n'
                    '\n'
                    'secret = random.randint(1, 100)\n'
                    'attempts = 0'
                ),
            },
            {
                "instruction": (
                    "Write a while loop that keeps running. Inside it, use "
                    "input() to get the user's guess and convert it to an int."
                ),
                "context_code": (
                    'import random\n'
                    'secret = random.randint(1, 100)\n'
                    'attempts = 0'
                ),
                "required_keywords": ["while", "input", "int"],
                "hints": [
                    "Use: while True: (or while attempts < 7:)",
                    "Get input: guess = int(input('Your guess: '))",
                    "Increment attempts: attempts += 1",
                ],
                "solution": (
                    'while attempts < 7:\n'
                    '    guess = int(input("Your guess: "))\n'
                    '    attempts += 1'
                ),
            },
            {
                "instruction": (
                    "Inside the loop, compare the guess to the secret. "
                    "If equal, print a success message and break. "
                    "If too low or too high, print a hint."
                ),
                "required_keywords": ["if", "elif", "break"],
                "hints": [
                    "if guess == secret: print('You got it!'); break",
                    "elif guess < secret: print('Too low!')",
                    "else: print('Too high!')",
                ],
                "solution": (
                    '    if guess == secret:\n'
                    '        print(f"You got it in {attempts} attempts!")\n'
                    '        break\n'
                    '    elif guess < secret:\n'
                    '        print("Too low!")\n'
                    '    else:\n'
                    '        print("Too high!")'
                ),
            },
            {
                "instruction": (
                    "Add a game-over message if the player runs out of guesses. "
                    "Use an else clause on the while loop (it runs if the loop "
                    "ends without a break) to reveal the secret number."
                ),
                "required_keywords": ["else", "secret"],
                "hints": [
                    "Add else: at the same indent level as while:",
                    "Inside: print(f'Game over! The number was {secret}.')",
                ],
                "solution": (
                    'else:\n'
                    '    print(f"Game over! The number was {secret}.")'
                ),
            },
        ],
        complete_solution="""\
import random

secret = random.randint(1, 100)
attempts = 0

print("I'm thinking of a number between 1 and 100.")
print("You have 7 guesses. Good luck!")

while attempts < 7:
    guess = int(input(f"\\nGuess #{attempts + 1}: "))
    attempts += 1

    if guess == secret:
        print(f"\\nYou got it in {attempts} attempts!")
        break
    elif guess < secret:
        print("Too low!")
    else:
        print("Too high!")
else:
    print(f"\\nGame over! The number was {secret}.")""",
    )

    mark_lesson_complete(progress, MODULE_KEY, "lesson3")
    success("Lesson 3 complete: Loops & Iteration")
    press_enter()


# ──────────────────────────────────────────────────────────────────────
#  Lesson 4 — Data Structures: Lists, Dicts, Sets, Tuples
# ──────────────────────────────────────────────────────────────────────
def lesson_data_structures(progress):
    section_header("Lesson 4: Data Structures -- Lists, Dicts, Sets, Tuples")

    learning_goal([
        "Use lists to store ordered collections of items",
        "Use dictionaries for key-value lookups",
        "Use sets for unique items and set operations",
        "Know when to use each data structure",
    ])

    pace()

    lesson_block(
        "So far, each variable has held a single value. But in the real world, "
        "you need to work with collections of data: a list of IP addresses, a "
        "mapping of usernames to roles, a set of unique ports, and more."
    )

    pace()

    why_it_matters(
        "Security tools process large amounts of structured data. A port "
        "scanner stores results in lists. A user database maps usernames to "
        "permissions using dictionaries. Deduplicating IP addresses uses sets. "
        "Choosing the right data structure makes your tools faster, more "
        "readable, and less error-prone."
    )

    press_enter()

    # ── Lists ──
    sub_header("Lists -- Ordered, Changeable Collections")

    lesson_block(
        "A list is an ordered collection of items. You can add, remove, and "
        "change items. Lists are created with square brackets [] and items "
        "are separated by commas."
    )

    tip("Lists are the most commonly used data structure in Python.")

    pace()

    code_block("""\
# Creating lists
ports = [22, 80, 443, 8080]
names = ["Alice", "Bob", "Charlie"]
mixed = [42, "hello", True, 3.14]  # Lists can hold different types
empty = []                          # An empty list

# Accessing items by index (position) -- starts at 0!
print(ports[0])    # 22  (first item)
print(ports[1])    # 80  (second item)
print(ports[-1])   # 8080 (last item)
print(ports[-2])   # 443  (second to last)

# Slicing -- getting a sub-list
print(ports[1:3])   # [80, 443]  (index 1 up to but not including 3)
print(ports[:2])    # [22, 80]   (from start to index 2)
print(ports[2:])    # [443, 8080] (from index 2 to end)""")

    pace()

    code_block("""\
# Modifying lists
servers = ["web01", "db01", "app01"]

# Adding items
servers.append("mail01")            # Add to end: ['web01', 'db01', 'app01', 'mail01']
servers.insert(1, "proxy01")        # Insert at index 1: ['web01', 'proxy01', 'db01', ...]

# Removing items
servers.remove("db01")              # Remove by value
last = servers.pop()                # Remove and return last item
specific = servers.pop(0)           # Remove and return item at index 0""")

    pace()

    code_block("""\
# Other useful operations
numbers = [3, 1, 4, 1, 5, 9, 2, 6]
numbers.sort()                      # Sort in place: [1, 1, 2, 3, 4, 5, 6, 9]
numbers.reverse()                   # Reverse in place: [9, 6, 5, 4, 3, 2, 1, 1]
print(len(numbers))                 # 8 (length of the list)
print(5 in numbers)                 # True (is 5 in the list?)
print(numbers.count(1))             # 2 (how many times does 1 appear?)
print(numbers.index(5))             # Index of first occurrence of 5""")

    nice_work("Lists are incredibly versatile. You will use them all the time!")

    press_enter()

    # ── Dictionaries ──
    sub_header("Dictionaries -- Key-Value Pairs")

    lesson_block(
        "A dictionary (dict) stores data as key-value pairs, like a real "
        "dictionary where each word (key) has a definition (value)."
    )

    pace()

    lesson_block(
        "Dictionaries are created with curly braces {} and use colons to "
        "separate keys from values. They are incredibly useful for "
        "representing structured data."
    )

    pace()

    code_block("""\
# Creating dictionaries
user = {
    "username": "alice",
    "role": "admin",
    "login_count": 42,
    "is_active": True
}

# Accessing values by key
print(user["username"])       # "alice"
print(user["role"])           # "admin"

# Using .get() is safer -- returns None (or a default) if key doesn't exist
print(user.get("email"))           # None (no error)
print(user.get("email", "N/A"))    # "N/A" (custom default)""")

    pace()

    code_block("""\
# Adding and modifying entries
user["email"] = "alice@company.com"   # Add a new key-value pair
user["login_count"] = 43              # Update an existing value

# Removing entries
del user["is_active"]                  # Delete a key-value pair
removed_role = user.pop("role")        # Remove and return the value

# Useful methods
print(user.keys())     # dict_keys(['username', 'login_count', 'email'])
print(user.values())   # dict_values(['alice', 43, 'alice@company.com'])
print(user.items())    # dict_items([('username', 'alice'), ...])""")

    pace()

    code_block("""\
# Looping through dictionaries
server_status = {
    "web01": "running",
    "db01": "stopped",
    "app01": "running",
    "mail01": "error"
}

# Loop through keys (default)
for server in server_status:
    print(f"  {server}: {server_status[server]}")

# Loop through key-value pairs (preferred)
for server, status in server_status.items():
    if status != "running":
        print(f"  ALERT: {server} is {status}!")""")

    pace()

    code_block("""\
# Nested dictionaries
employees = {
    "alice": {"role": "admin", "department": "IT Security"},
    "bob": {"role": "analyst", "department": "SOC"},
    "charlie": {"role": "engineer", "department": "DevOps"}
}
print(employees["alice"]["department"])  # "IT Security" """)

    nice_work("Dictionaries are a powerhouse. You just unlocked key-value storage!")

    press_enter()

    # ── Sets ──
    sub_header("Sets -- Unique Values Only")

    lesson_block(
        "A set is a collection of unique items -- no duplicates allowed. "
        "Sets are useful when you need to eliminate duplicates or perform "
        "mathematical set operations like union, intersection, and difference."
    )

    pace()

    code_block("""\
# Creating sets
open_ports = {22, 80, 443, 80, 22}  # Duplicates are removed automatically
print(open_ports)                    # {80, 443, 22} (order may vary)

# Sets from a list (removes duplicates)
ip_list = ["10.0.0.1", "10.0.0.2", "10.0.0.1", "10.0.0.3", "10.0.0.2"]
unique_ips = set(ip_list)
print(unique_ips)       # {'10.0.0.1', '10.0.0.2', '10.0.0.3'}
print(len(unique_ips))  # 3""")

    pace()

    code_block("""\
# Set operations
set_a = {22, 80, 443, 8080}
set_b = {80, 443, 3306, 5432}

print(set_a | set_b)    # Union: {22, 80, 443, 3306, 5432, 8080}
print(set_a & set_b)    # Intersection: {80, 443} (in both)
print(set_a - set_b)    # Difference: {22, 8080} (in A but not B)

# Practical: find new ports that appeared between two scans
scan_yesterday = {22, 80, 443}
scan_today = {22, 80, 443, 3306, 8080}

new_ports = scan_today - scan_yesterday
print(f"New ports detected: {new_ports}")  # {3306, 8080}""")

    press_enter()

    # ── Tuples ──
    sub_header("Tuples -- Immutable Sequences")

    lesson_block(
        "A tuple is like a list, but it cannot be changed after creation "
        "(it is immutable). Tuples use parentheses () instead of square "
        "brackets."
    )

    pace()

    lesson_block(
        "Use tuples for data that should not be modified, like "
        "coordinates, database records, or function return values."
    )

    pace()

    code_block("""\
# Creating tuples
coordinates = (40.7128, -74.0060)   # Latitude, longitude of New York
rgb_red = (255, 0, 0)
server_info = ("web01", "192.168.1.10", 443)

# Accessing items (same as lists)
print(coordinates[0])   # 40.7128
print(server_info[2])   # 443

# Tuple unpacking -- assign multiple variables at once
host, ip, port = server_info
print(f"Host: {host}, IP: {ip}, Port: {port}")""")

    pace()

    code_block("""\
# You cannot modify a tuple:
# coordinates[0] = 50.0   # ERROR: tuples do not support assignment

# Tuples are commonly returned by functions
# divmod() returns a tuple of (quotient, remainder)
quotient, remainder = divmod(17, 5)
print(f"17 / 5 = {quotient} remainder {remainder}")  # 3 remainder 2""")

    nice_work("You now know all four Python data structures!")

    press_enter()

    # ── When to Use Which ──
    sub_header("When to Use Which Data Structure")

    code_block("""\
# LIST -- Ordered collection that may change
#   Use for: log entries, scan results, to-do items
open_ports = [22, 80, 443]

# DICT -- Key-value lookups
#   Use for: user profiles, configurations, mappings
user = {"name": "Alice", "role": "admin"}

# SET -- Unique items, set operations
#   Use for: deduplication, comparing groups, membership testing
blocked_ips = {"10.0.0.1", "10.0.0.2"}

# TUPLE -- Fixed data that should not change
#   Use for: coordinates, database rows, function returns
address = ("192.168.1.1", 443)""", language="text")

    pace()

    scenario_block("Intrusion Detection Data Model", (
        "You are building a simple intrusion detection system. You use a "
        "dictionary to store alerts, where each key is a timestamp and the "
        "value is a dict with source IP, destination IP, and alert type. "
        "You use a set to track unique attacking IPs. You use a list to "
        "maintain the chronological order of events. Choosing the right "
        "data structure for each job makes your code clean and efficient."
    ))

    tip("When in doubt, start with a list. You can always switch later if needed.")

    press_enter()

    # ── Guided Practice ──
    guided_practice(
        title="Contact Book",
        intro="Let's build a contact book using dictionaries, step by step.",
        steps=[
            {
                "instruction": (
                    "Create an empty dictionary called contacts. Then write a "
                    "while True loop that prints a menu with numbered options "
                    "(Add, Look up, List, Delete, Quit) and gets the user's choice "
                    "with input()."
                ),
                "required_keywords": ["contacts", "while", "input"],
                "hints": [
                    "Start with: contacts = {}",
                    "Use while True: to keep the menu running.",
                    "Print options with print(), get choice with input().",
                ],
                "solution": (
                    'contacts = {}\n'
                    '\n'
                    'while True:\n'
                    '    print("\\n--- Contact Book ---")\n'
                    '    print("1. Add  2. Look up  3. List  4. Delete  5. Quit")\n'
                    '    choice = input("Choice: ").strip()'
                ),
            },
            {
                "instruction": (
                    "Handle the 'Add contact' option. Use input() to get the name, "
                    "phone, and email. Store them as a nested dictionary inside contacts."
                ),
                "required_keywords": ["name", "phone", "email"],
                "hints": [
                    "Get each field: name = input('Name: ').strip()",
                    "Store as nested dict: contacts[name] = {'phone': phone, 'email': email}",
                    "Print confirmation: print(f'Added {name}!')",
                ],
                "solution": (
                    '    if choice == "1":\n'
                    '        name = input("Name: ").strip()\n'
                    '        phone = input("Phone: ").strip()\n'
                    '        email = input("Email: ").strip()\n'
                    '        contacts[name] = {"phone": phone, "email": email}\n'
                    '        print(f"Added {name}!")'
                ),
            },
            {
                "instruction": (
                    "Handle 'Look up'. Ask for a name, use .get() to safely look "
                    "it up (returns None if not found), and print the contact details."
                ),
                "required_keywords": ["get", "print"],
                "hints": [
                    "Use contacts.get(name) — returns None if the key doesn't exist.",
                    "if contact: print details, else: print 'not found'.",
                ],
                "solution": (
                    '    elif choice == "2":\n'
                    '        name = input("Name: ").strip()\n'
                    '        contact = contacts.get(name)\n'
                    '        if contact:\n'
                    '            print(f"  {name}: {contact}")\n'
                    '        else:\n'
                    '            print("Not found.")'
                ),
            },
            {
                "instruction": (
                    "Handle 'List all' and 'Delete'. For listing, loop through "
                    "contacts.items(). For deleting, use del contacts[name]. "
                    "Also handle the Quit option with break."
                ),
                "required_keywords": ["for", "items", "del"],
                "hints": [
                    "for name, info in contacts.items(): print(...)",
                    "del contacts[name] removes a key from the dictionary.",
                    "if choice == '5': break",
                ],
                "solution": (
                    '    elif choice == "3":\n'
                    '        for name, info in contacts.items():\n'
                    '            print(f"  {name}: {info}")\n'
                    '    elif choice == "4":\n'
                    '        name = input("Name: ").strip()\n'
                    '        if name in contacts:\n'
                    '            del contacts[name]\n'
                    '            print(f"Deleted {name}.")\n'
                    '    elif choice == "5":\n'
                    '        break'
                ),
            },
        ],
        complete_solution="""\
contacts = {}

while True:
    print("\\n--- Contact Book ---")
    print("1. Add  2. Look up  3. List  4. Delete  5. Quit")
    choice = input("Choice: ").strip()

    if choice == "1":
        name = input("Name: ").strip()
        phone = input("Phone: ").strip()
        email = input("Email: ").strip()
        contacts[name] = {"phone": phone, "email": email}
        print(f"Added {name}!")
    elif choice == "2":
        name = input("Name: ").strip()
        contact = contacts.get(name)
        if contact:
            print(f"  {name}: {contact}")
        else:
            print("Not found.")
    elif choice == "3":
        for name, info in contacts.items():
            print(f"  {name}: {info}")
    elif choice == "4":
        name = input("Name: ").strip()
        if name in contacts:
            del contacts[name]
            print(f"Deleted {name}.")
    elif choice == "5":
        break""",
    )

    mark_lesson_complete(progress, MODULE_KEY, "lesson4")
    success("Lesson 4 complete: Data Structures")
    press_enter()


# ──────────────────────────────────────────────────────────────────────
#  Lesson 5 — Functions & Modules
# ──────────────────────────────────────────────────────────────────────
def lesson_functions_modules(progress):
    section_header("Lesson 5: Functions & Modules")

    learning_goal([
        "Define and call your own functions",
        "Use return values, default parameters, and keyword arguments",
        "Understand variable scope (local vs global)",
        "Import and use Python's built-in modules",
    ])

    pace()

    lesson_block(
        "As your programs get bigger, you need a way to organize your code "
        "into reusable pieces. A function is a named block of code that "
        "performs a specific task. You define it once and can call it as many "
        "times as you want."
    )

    pace()

    lesson_block(
        "Functions have three big benefits. First, they avoid repetition. "
        "Second, they make code readable. Third, they make testing easier: "
        "you can test each function independently."
    )

    pace()

    why_it_matters(
        "Professional security tools are built from functions and modules. "
        "A port scanner might have functions like scan_port(), grab_banner(), "
        "and generate_report(). A log analyzer might import the 're' module "
        "for regex and the 'datetime' module for timestamps. Knowing how to "
        "write functions and use modules is what takes you from writing "
        "scripts to building real tools."
    )

    press_enter()

    # ── Defining Functions ──
    sub_header("Defining Functions with def")

    code_block("""\
# A simple function with no parameters
def greet():
    print("Hello, welcome to JJ's LAB!")

# Call (use) the function
greet()           # Output: Hello, welcome to JJ's LAB!
greet()           # You can call it as many times as you want""")

    pace()

    code_block("""\
# A function with a parameter (input)
def greet_user(name):
    print(f"Hello, {name}! Welcome to JJ's LAB.")

greet_user("Alice")    # Output: Hello, Alice! Welcome to JJ's LAB.
greet_user("Bob")      # Output: Hello, Bob! Welcome to JJ's LAB.

# A function with multiple parameters
def check_port(host, port):
    print(f"Checking {host} on port {port}...")

check_port("192.168.1.1", 80)
check_port("10.0.0.5", 443)""")

    nice_work("You just wrote your first functions!")

    press_enter()

    # ── Return Values ──
    sub_header("Return Values -- Getting Results Back")

    lesson_block(
        "A function can send a result back to the code that called it using "
        "the 'return' statement. Think of it as the function handing you an "
        "answer."
    )

    pace()

    code_block("""\
# A function that returns a value
def add(a, b):
    return a + b

result = add(3, 5)
print(result)          # Output: 8
print(add(10, 20))     # Output: 30

# A function can return different types
def is_valid_port(port):
    \"\"\"Check if a port number is valid.\"\"\"
    return 1 <= port <= 65535

print(is_valid_port(80))       # True
print(is_valid_port(99999))    # False""")

    pace()

    code_block("""\
# A function can return multiple values (as a tuple)
def analyze_password(password):
    \"\"\"Return length and whether it has digits.\"\"\"
    length = len(password)
    has_digits = any(c.isdigit() for c in password)
    return length, has_digits

pw_length, pw_has_digits = analyze_password("Hello123")
print(f"Length: {pw_length}, Has digits: {pw_has_digits}")
# Output: Length: 8, Has digits: True""")

    pace()

    code_block("""\
# Early return -- exit a function immediately
def divide(a, b):
    if b == 0:
        return None  # Return early to avoid division by zero
    return a / b

print(divide(10, 3))    # 3.333...
print(divide(10, 0))    # None""")

    press_enter()

    # ── Parameters Deep Dive ──
    sub_header("Parameters: Default Values, Keyword Arguments")

    code_block("""\
# Default parameter values
def scan_host(host, port=80, timeout=5):
    \"\"\"Scan a host. Port defaults to 80, timeout to 5 seconds.\"\"\"
    print(f"Scanning {host}:{port} (timeout={timeout}s)")

scan_host("192.168.1.1")                # Uses defaults: port=80, timeout=5
scan_host("192.168.1.1", 443)           # port=443, timeout=5
scan_host("192.168.1.1", 443, 10)       # port=443, timeout=10

# Keyword arguments -- specify by name (order doesn't matter)
scan_host("192.168.1.1", timeout=2, port=8080)

# Mixing positional and keyword arguments
scan_host("10.0.0.1", 22, timeout=3)""")

    tip("Default parameters are great for making functions easy to call with common settings.")

    press_enter()

    # ── Scope ──
    sub_header("Scope -- Where Variables Live")

    lesson_block(
        "A variable created inside a function only exists inside that "
        "function. This is called 'local scope'."
    )

    pace()

    lesson_block(
        "A variable created outside all functions exists everywhere and is "
        "called 'global scope'. This separation prevents functions from "
        "accidentally changing each other's data."
    )

    pace()

    code_block("""\
# Global vs local scope
message = "I am global"     # Global variable

def my_function():
    message = "I am local"  # Local variable (different from the global one!)
    secret = "hidden"       # Local variable
    print(message)          # "I am local"

my_function()
print(message)              # "I am global" (unchanged!)
# print(secret)             # ERROR: secret does not exist outside the function""")

    pace()

    code_block("""\
# Accessing global variables inside a function (read only)
app_name = "JJ's LAB"

def show_app():
    print(f"App: {app_name}")  # Can READ the global variable

show_app()  # Output: App: JJ's LAB""")

    nice_work("Scope can be confusing at first, but you handled it!")

    press_enter()

    # ── *args and **kwargs ──
    sub_header("*args and **kwargs -- Flexible Parameters")

    code_block("""\
# *args -- accept any number of positional arguments
def scan_ports(host, *ports):
    \"\"\"Scan multiple ports on a host.\"\"\"
    print(f"Host: {host}")
    for port in ports:
        print(f"  Scanning port {port}...")

scan_ports("192.168.1.1", 22, 80, 443, 8080)
# ports becomes a tuple: (22, 80, 443, 8080)""")

    pace()

    code_block("""\
# **kwargs -- accept any number of keyword arguments
def create_user(**kwargs):
    \"\"\"Create a user from keyword arguments.\"\"\"
    print("Creating user:")
    for key, value in kwargs.items():
        print(f"  {key}: {value}")

create_user(name="Alice", role="admin", department="Security")
# kwargs becomes a dict: {"name": "Alice", "role": "admin", ...}""")

    press_enter()

    # ── Lambda Functions ──
    sub_header("Lambda Functions -- Quick One-Liners")

    code_block("""\
# Lambda: a mini-function defined in a single line
# Useful for simple operations, especially with sort() and map()

double = lambda x: x * 2
print(double(5))    # 10

# Most common use: as a key function for sorting
servers = [
    {"name": "web01", "load": 85},
    {"name": "db01", "load": 42},
    {"name": "app01", "load": 67},
]

# Sort by load (ascending)
servers.sort(key=lambda s: s["load"])
for s in servers:
    print(f"  {s['name']}: {s['load']}%")
# Output: db01: 42%, app01: 67%, web01: 85%""")

    press_enter()

    # ── Importing Modules ──
    sub_header("Importing Modules -- Using Python's Built-in Libraries")

    lesson_block(
        "Python comes with a huge standard library -- hundreds of modules "
        "that provide pre-built functionality. Instead of writing everything "
        "from scratch, you import what you need."
    )

    pace()

    code_block("""\
# Different ways to import
import os                     # Import the entire module
print(os.getcwd())            # Use as: module.function()

from os import path            # Import specific items
print(path.exists("/tmp"))

from datetime import datetime  # Import a specific class
now = datetime.now()
print(f"Current time: {now}")

import random as rng           # Import with an alias (nickname)
print(rng.randint(1, 100))""")

    pace()

    code_block("""\
# Common modules for security work:
import os          # Operating system interface (files, paths, env vars)
import sys         # System info (Python version, command line args)
import math        # Math functions (log, sqrt, pow, ceil, floor)
import random      # Random numbers (for testing, not cryptography!)
import datetime    # Dates and times
import hashlib     # Hashing (MD5, SHA-256, etc.)
import json        # JSON parsing and creation
import re          # Regular expressions (pattern matching)
import socket      # Network connections""")

    pace()

    code_block("""\
# Quick examples of common modules

# os -- file and system operations
import os
print(f"Current directory: {os.getcwd()}")
print(f"Home directory: {os.path.expanduser('~')}")
print(f"File exists: {os.path.exists('/etc/passwd')}")""")

    pace()

    code_block("""\
# math -- mathematical operations
import math
print(f"Square root of 144: {math.sqrt(144)}")     # 12.0
print(f"Ceiling of 4.2: {math.ceil(4.2)}")         # 5
print(f"Log base 2 of 256: {math.log2(256)}")      # 8.0

# random -- generating random values
import random
print(f"Random int 1-100: {random.randint(1, 100)}")
print(f"Random choice: {random.choice(['red', 'blue', 'green'])}")""")

    pace()

    code_block("""\
# datetime -- working with dates and times
from datetime import datetime, timedelta
now = datetime.now()
print(f"Now: {now.strftime('%Y-%m-%d %H:%M:%S')}")
yesterday = now - timedelta(days=1)
print(f"Yesterday: {yesterday.strftime('%Y-%m-%d')}")""")

    pace()

    scenario_block("Building a Security Toolkit", (
        "A security analyst creates a Python file called sec_utils.py that "
        "contains utility functions: hash_string() for computing SHA-256 "
        "hashes, validate_ip() for checking IP address format, and "
        "timestamp_log() for adding timestamps to log entries. Other scripts "
        "in the project import these functions with 'from sec_utils import "
        "hash_string, validate_ip'. This modular approach means the team "
        "writes each utility once and reuses it across dozens of scripts."
    ))

    nice_work("Functions and modules are how real software is built. Great job!")

    press_enter()

    # ── Guided Practice ──
    guided_practice(
        title="Utility Function Library",
        intro="Let's write three useful functions, one at a time.",
        steps=[
            {
                "instruction": (
                    "Write a function called is_valid_ip(ip) that checks if a "
                    "string is a valid IPv4 address. Split the string by '.', "
                    "check there are 4 parts, and each part is a number between "
                    "0 and 255. Return True or False."
                ),
                "required_keywords": ["def", "split", "255"],
                "hints": [
                    "Start: def is_valid_ip(ip): parts = ip.split('.')",
                    "Check: if len(parts) != 4: return False",
                    "Loop: for part in parts — check isdigit() and 0 <= int(part) <= 255",
                ],
                "solution": (
                    'def is_valid_ip(ip):\n'
                    '    parts = ip.split(".")\n'
                    '    if len(parts) != 4:\n'
                    '        return False\n'
                    '    for part in parts:\n'
                    '        if not part.isdigit():\n'
                    '            return False\n'
                    '        if int(part) < 0 or int(part) > 255:\n'
                    '            return False\n'
                    '    return True'
                ),
            },
            {
                "instruction": (
                    "Write a function called generate_password(length) that "
                    "creates a random password. Import random, define a charset "
                    "string of letters and digits, then use random.choice() in "
                    "a loop to pick random characters."
                ),
                "required_keywords": ["def", "random", "choice"],
                "hints": [
                    "import random",
                    "charset = 'abcdefghijklmnopqrstuvwxyzABCDEF...0123456789!@#'",
                    "Loop: for _ in range(length): password += random.choice(charset)",
                ],
                "solution": (
                    'import random\n'
                    'import string\n'
                    '\n'
                    'def generate_password(length=16):\n'
                    '    charset = string.ascii_letters + string.digits + "!@#$%^&*"\n'
                    '    password = ""\n'
                    '    for _ in range(length):\n'
                    '        password += random.choice(charset)\n'
                    '    return password'
                ),
            },
            {
                "instruction": (
                    "Write a function called caesar_cipher(text, shift) that "
                    "shifts each letter by the shift amount. Use ord() to get "
                    "the character code and chr() to convert back. Non-letter "
                    "characters should stay unchanged."
                ),
                "required_keywords": ["def", "ord", "chr"],
                "hints": [
                    "Loop through each char in text.",
                    "Check char.isalpha() — only shift letters.",
                    "base = ord('A') if char.isupper() else ord('a'); "
                    "shifted = (ord(char) - base + shift) % 26 + base; chr(shifted)",
                ],
                "solution": (
                    'def caesar_cipher(text, shift):\n'
                    '    result = ""\n'
                    '    for char in text:\n'
                    '        if char.isalpha():\n'
                    '            base = ord("A") if char.isupper() else ord("a")\n'
                    '            shifted = (ord(char) - base + shift) % 26 + base\n'
                    '            result += chr(shifted)\n'
                    '        else:\n'
                    '            result += char\n'
                    '    return result'
                ),
            },
        ],
        complete_solution="""\
import random
import string

def is_valid_ip(ip):
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    for part in parts:
        if not part.isdigit():
            return False
        if int(part) < 0 or int(part) > 255:
            return False
    return True

def generate_password(length=16):
    charset = string.ascii_letters + string.digits + "!@#$%^&*"
    password = ""
    for _ in range(length):
        password += random.choice(charset)
    return password

def caesar_cipher(text, shift):
    result = ""
    for char in text:
        if char.isalpha():
            base = ord("A") if char.isupper() else ord("a")
            shifted = (ord(char) - base + shift) % 26 + base
            result += chr(shifted)
        else:
            result += char
    return result

# Test
print(is_valid_ip("192.168.1.1"))   # True
print(generate_password(20))         # Random password
print(caesar_cipher("Hello", 3))     # Khoor""",
    )

    mark_lesson_complete(progress, MODULE_KEY, "lesson5")
    success("Lesson 5 complete: Functions & Modules")
    press_enter()


# ──────────────────────────────────────────────────────────────────────
#  Lesson 6 — Error Handling & File Basics
# ──────────────────────────────────────────────────────────────────────
def lesson_error_handling_files(progress):
    section_header("Lesson 6: Error Handling & File Basics")

    learning_goal([
        "Use try/except to catch and handle errors",
        "Know the most common exception types",
        "Read and write files safely with the 'with' statement",
        "Work with file paths using os.path",
    ])

    pace()

    lesson_block(
        "Things go wrong. A lot. The file you are trying to read does not "
        "exist. The user types 'abc' when you expected a number. The network "
        "connection times out."
    )

    pace()

    lesson_block(
        "Good programs do not crash when things go wrong -- they handle errors "
        "gracefully. Python's try/except system lets you catch errors and "
        "decide what to do about them."
    )

    pace()

    lesson_block(
        "In Python, errors are called 'exceptions'. When an error occurs, "
        "Python 'raises' (throws) an exception. If you do not catch it, your "
        "program crashes. But if you wrap the risky code in a try/except block, "
        "you can catch the exception and handle it."
    )

    pace()

    why_it_matters(
        "Security tools MUST handle errors well. A port scanner that crashes "
        "on the first unreachable host is useless. A log parser that stops "
        "at the first malformed line misses everything after it. Error "
        "handling is also a security concern: poor error messages can leak "
        "sensitive information (file paths, database details, stack traces) "
        "to attackers."
    )

    press_enter()

    # ── try/except ──
    sub_header("try / except -- Catching Errors")

    code_block("""\
# Without error handling -- this crashes!
# number = int("hello")  # ValueError: invalid literal for int()

# With error handling -- graceful recovery
try:
    number = int("hello")
    print(f"The number is {number}")
except ValueError:
    print("That is not a valid number!")
# Output: That is not a valid number!

# The program continues running after the except block
print("Program continues...")""")

    pace()

    code_block("""\
# Catching the error details
try:
    result = 10 / 0
except ZeroDivisionError as e:
    print(f"Math error: {e}")
# Output: Math error: division by zero

# Catching multiple exception types
try:
    data = {"name": "Alice"}
    print(data["age"])      # KeyError: 'age'
except KeyError as e:
    print(f"Missing key: {e}")
except TypeError as e:
    print(f"Type error: {e}")""")

    nice_work("You can now prevent your programs from crashing!")

    press_enter()

    # ── Common Exceptions ──
    sub_header("Common Exception Types")

    code_block("""\
# ValueError -- wrong type of value
try:
    age = int("twenty")
except ValueError:
    print("ValueError: Cannot convert 'twenty' to int")

# TypeError -- wrong type for an operation
try:
    result = "hello" + 5
except TypeError:
    print("TypeError: Cannot add string and integer")

# KeyError -- dictionary key does not exist
try:
    user = {"name": "Alice"}
    print(user["email"])
except KeyError:
    print("KeyError: 'email' not found in dictionary")""")

    pace()

    code_block("""\
# IndexError -- list index out of range
try:
    items = [1, 2, 3]
    print(items[10])
except IndexError:
    print("IndexError: List index out of range")

# FileNotFoundError -- file does not exist
try:
    with open("/nonexistent/file.txt") as f:
        data = f.read()
except FileNotFoundError:
    print("FileNotFoundError: File not found")

# Catching any exception (use sparingly!)
try:
    # some risky code
    x = 1 / 0
except Exception as e:
    print(f"Something went wrong: {type(e).__name__}: {e}")""")

    tip("Always catch specific exceptions when you can. Catching everything with 'except Exception' can hide real bugs.")

    press_enter()

    # ── try/except/else/finally ──
    sub_header("The Full try/except/else/finally Structure")

    code_block("""\
# The complete error handling structure
try:
    # Code that might raise an exception
    number = int(input("Enter a number: "))
    result = 100 / number
except ValueError:
    # Runs ONLY if a ValueError was raised
    print("Error: Please enter a valid number.")
except ZeroDivisionError:
    # Runs ONLY if ZeroDivisionError was raised
    print("Error: Cannot divide by zero.")
else:
    # Runs ONLY if NO exception was raised (success!)
    print(f"Result: {result}")
finally:
    # ALWAYS runs, whether there was an exception or not
    # Great for cleanup (closing files, network connections, etc.)
    print("Operation complete.")""")

    pace()

    lesson_block(
        "Example flow if user enters '5': "
        "try block runs, no error, then else block runs, then finally runs. "
        "Output: Result: 20.0, Operation complete."
    )

    pace()

    lesson_block(
        "Example flow if user enters 'abc': "
        "try block raises ValueError, except block runs, then finally runs. "
        "Output: Error: Please enter a valid number. Operation complete."
    )

    press_enter()

    # ── Raising Exceptions ──
    sub_header("Raising Exceptions -- Signaling Your Own Errors")

    code_block("""\
# You can raise exceptions in your own code
def set_port(port):
    \"\"\"Set a port number, raising an error if invalid.\"\"\"
    if not isinstance(port, int):
        raise TypeError(f"Port must be an integer, got {type(port).__name__}")
    if port < 1 or port > 65535:
        raise ValueError(f"Port must be 1-65535, got {port}")
    print(f"Port set to {port}")

try:
    set_port(80)         # Works fine
    set_port(99999)      # Raises ValueError
except ValueError as e:
    print(f"Invalid port: {e}")""")

    pace()

    code_block("""\
# Custom exceptions (brief introduction)
class AuthenticationError(Exception):
    \"\"\"Raised when authentication fails.\"\"\"
    pass

def login(username, password):
    if username != "admin" or password != "secret":
        raise AuthenticationError(f"Login failed for user: {username}")
    return True

try:
    login("admin", "wrong")
except AuthenticationError as e:
    print(f"Auth error: {e}")""")

    nice_work("You can now raise your own exceptions and create custom error types!")

    press_enter()

    # ── Reading Files ──
    sub_header("Reading Files")

    lesson_block(
        "Python makes it easy to read and write files. The most important "
        "thing to remember is to use the 'with' statement (called a context "
        "manager). It automatically closes the file when you are done, even "
        "if an error occurs."
    )

    pace()

    code_block("""\
# Reading an entire file at once
with open("example.txt", "r") as f:
    content = f.read()
    print(content)
# The file is automatically closed when the 'with' block ends

# Reading line by line (memory-efficient for large files)
with open("log.txt", "r") as f:
    for line in f:
        print(line.strip())  # strip() removes the newline at the end""")

    pace()

    code_block("""\
# Reading all lines into a list
with open("targets.txt", "r") as f:
    lines = f.readlines()
    print(f"File has {len(lines)} lines")

# Reading with error handling (always do this!)
try:
    with open("config.txt", "r") as f:
        config = f.read()
        print("Config loaded successfully!")
except FileNotFoundError:
    print("Config file not found. Using defaults.")
except PermissionError:
    print("Permission denied. Cannot read config file.")""")

    press_enter()

    # ── Writing Files ──
    sub_header("Writing Files")

    code_block("""\
# Writing to a file (creates it if it doesn't exist, overwrites if it does)
with open("report.txt", "w") as f:
    f.write("Security Scan Report\\n")
    f.write("=" * 40 + "\\n")
    f.write("Date: 2025-01-15\\n")
    f.write("Target: 192.168.1.0/24\\n")
    f.write("\\nOpen Ports Found:\\n")

    ports = [22, 80, 443]
    for port in ports:
        f.write(f"  - Port {port}\\n")""")

    pace()

    code_block("""\
# Appending to a file (adds to the end, doesn't overwrite)
with open("report.txt", "a") as f:
    f.write("\\n--- Scan Complete ---\\n")

# Writing multiple lines at once
lines = ["Line 1\\n", "Line 2\\n", "Line 3\\n"]
with open("output.txt", "w") as f:
    f.writelines(lines)""")

    pace()

    lesson_block(
        "File modes explained: 'r' = read (file must exist), 'w' = write "
        "(creates new or overwrites existing), 'a' = append (adds to end "
        "of existing file), 'x' = exclusive create (fails if file exists)."
    )

    pace()

    lesson_block(
        "Add 'b' for binary mode: 'rb' reads binary files, 'wb' writes them."
    )

    press_enter()

    # ── Context Managers ──
    sub_header("Context Managers -- The 'with' Statement")

    lesson_block(
        "The 'with' statement is not just for files. It is a general pattern "
        "for managing resources that need to be cleaned up."
    )

    pace()

    code_block("""\
# WITHOUT 'with' -- you must close manually (error-prone)
f = open("data.txt", "r")
try:
    content = f.read()
finally:
    f.close()  # Must remember to close!

# WITH 'with' -- automatic cleanup (recommended!)
with open("data.txt", "r") as f:
    content = f.read()
# File is closed automatically here, even if an error occurred""")

    pace()

    code_block("""\
# You can open multiple files at once
with open("input.txt", "r") as infile, open("output.txt", "w") as outfile:
    for line in infile:
        outfile.write(line.upper())  # Convert each line to uppercase""")

    tip("Always use 'with' when working with files. It is the safest and cleanest approach.")

    press_enter()

    # ── Working with Paths ──
    sub_header("Working with File Paths using os.path")

    code_block("""\
import os

# Building file paths safely (works on all operating systems)
home = os.path.expanduser("~")           # /Users/yourname or /home/yourname
desktop = os.path.join(home, "Desktop")  # Joins with correct separator
report = os.path.join(desktop, "scan_report.txt")
print(f"Report path: {report}")

# Checking if files and directories exist
print(os.path.exists("/tmp"))            # True (on macOS/Linux)
print(os.path.isfile("/etc/passwd"))     # True if it is a file
print(os.path.isdir("/tmp"))             # True if it is a directory""")

    pace()

    code_block("""\
# Getting file information
if os.path.exists(report):
    size = os.path.getsize(report)       # Size in bytes
    print(f"File size: {size} bytes")

# Splitting paths
path = "/var/log/auth.log"
directory = os.path.dirname(path)        # "/var/log"
filename = os.path.basename(path)        # "auth.log"
name, ext = os.path.splitext(filename)   # ("auth", ".log")
print(f"Dir: {directory}, File: {filename}, Extension: {ext}")""")

    pace()

    code_block("""\
# Listing files in a directory
for item in os.listdir("/tmp"):
    full_path = os.path.join("/tmp", item)
    if os.path.isfile(full_path):
        print(f"  File: {item}")""")

    pace()

    scenario_block("Log File Analysis During Incident Response", (
        "During a security incident at 2 AM, you need to quickly analyze "
        "server logs. Your Python script uses error handling to gracefully "
        "skip corrupted log lines, reads files line-by-line to handle the "
        "500 MB file without running out of memory, and writes a summary "
        "report. The try/except blocks ensure that a single malformed line "
        "does not crash the entire analysis. The with statement guarantees "
        "all files are properly closed even under pressure."
    ))

    nice_work("Error handling and file I/O are essential skills. You have got them both now!")

    press_enter()

    # ── Guided Practice ──
    guided_practice(
        title="Note-Taking App",
        intro="Let's build an app that saves notes to a file, with error handling.",
        steps=[
            {
                "instruction": (
                    "Write a function called add_note() that gets a note from "
                    "the user with input(), then opens a file in append mode ('a') "
                    "and writes the note. Wrap the file operation in try/except "
                    "to catch errors."
                ),
                "required_keywords": ["open", "write", "try", "except"],
                "hints": [
                    "def add_note(): note = input('Enter your note: ')",
                    "Use: with open('notes.txt', 'a') as f: f.write(note + '\\n')",
                    "Wrap in try/except to catch PermissionError or OSError.",
                ],
                "solution": (
                    'def add_note():\n'
                    '    note = input("Enter your note: ").strip()\n'
                    '    try:\n'
                    '        with open("notes.txt", "a") as f:\n'
                    '            f.write(note + "\\n")\n'
                    '        print("Note saved!")\n'
                    '    except OSError as e:\n'
                    '        print(f"Error: {e}")'
                ),
            },
            {
                "instruction": (
                    "Write a function called view_notes() that opens the file "
                    "in read mode, reads all lines, and prints each one. "
                    "Handle FileNotFoundError for when the file doesn't exist yet."
                ),
                "required_keywords": ["open", "read", "FileNotFoundError"],
                "hints": [
                    "Use: with open('notes.txt', 'r') as f: notes = f.readlines()",
                    "except FileNotFoundError: print('No notes yet!')",
                    "Loop and print: for i, note in enumerate(notes, 1): print(...)",
                ],
                "solution": (
                    'def view_notes():\n'
                    '    try:\n'
                    '        with open("notes.txt", "r") as f:\n'
                    '            notes = f.readlines()\n'
                    '        for i, note in enumerate(notes, 1):\n'
                    '            print(f"  {i}. {note.strip()}")\n'
                    '    except FileNotFoundError:\n'
                    '        print("No notes yet! Add one first.")'
                ),
            },
            {
                "instruction": (
                    "Write a function called search_notes(keyword) that reads "
                    "the file and prints only lines that contain the keyword. "
                    "Use .lower() on both to make it case-insensitive."
                ),
                "required_keywords": ["for", "if", "lower"],
                "hints": [
                    "Read the file, then loop through lines.",
                    "if keyword.lower() in line.lower(): print the match.",
                    "Don't forget to handle FileNotFoundError.",
                ],
                "solution": (
                    'def search_notes(keyword):\n'
                    '    try:\n'
                    '        with open("notes.txt", "r") as f:\n'
                    '            for line in f:\n'
                    '                if keyword.lower() in line.lower():\n'
                    '                    print(f"  - {line.strip()}")\n'
                    '    except FileNotFoundError:\n'
                    '        print("No notes file found.")'
                ),
            },
            {
                "instruction": (
                    "Write the main menu loop: a while True loop that shows "
                    "options (Add, View, Search, Quit), gets the user's choice "
                    "with input(), and calls the right function."
                ),
                "required_keywords": ["while", "input", "choice"],
                "hints": [
                    "while True: print the menu, choice = input('Choice: ')",
                    "if choice == '1': add_note() elif choice == '2': view_notes()",
                    "Break out of the loop for the quit option.",
                ],
                "solution": (
                    'while True:\n'
                    '    print("\\n1. Add  2. View  3. Search  4. Quit")\n'
                    '    choice = input("Choice: ").strip()\n'
                    '    if choice == "1": add_note()\n'
                    '    elif choice == "2": view_notes()\n'
                    '    elif choice == "3":\n'
                    '        kw = input("Search for: ")\n'
                    '        search_notes(kw)\n'
                    '    elif choice == "4": break'
                ),
            },
        ],
        complete_solution="""\
def add_note():
    note = input("Enter your note: ").strip()
    try:
        with open("notes.txt", "a") as f:
            f.write(note + "\\n")
        print("Note saved!")
    except OSError as e:
        print(f"Error: {e}")

def view_notes():
    try:
        with open("notes.txt", "r") as f:
            notes = f.readlines()
        for i, note in enumerate(notes, 1):
            print(f"  {i}. {note.strip()}")
    except FileNotFoundError:
        print("No notes yet! Add one first.")

def search_notes(keyword):
    try:
        with open("notes.txt", "r") as f:
            for line in f:
                if keyword.lower() in line.lower():
                    print(f"  - {line.strip()}")
    except FileNotFoundError:
        print("No notes file found.")

while True:
    print("\\n1. Add  2. View  3. Search  4. Quit")
    choice = input("Choice: ").strip()
    if choice == "1": add_note()
    elif choice == "2": view_notes()
    elif choice == "3":
        kw = input("Search for: ")
        search_notes(kw)
    elif choice == "4": break""",
    )

    mark_lesson_complete(progress, MODULE_KEY, "lesson6")
    success("Lesson 6 complete: Error Handling & File Basics")
    success("You have completed all lessons in Module 0!")
    info("You now have the Python foundation needed for the security modules.")
    press_enter()


# ──────────────────────────────────────────────────────────────────────
#  Quiz
# ──────────────────────────────────────────────────────────────────────
QUIZ_QUESTIONS = [
    {
        "q": "What is the correct way to create a variable in Python?",
        "options": [
            "A) var age = 25",
            "B) int age = 25",
            "C) age = 25",
            "D) let age = 25",
        ],
        "answer": "c",
        "explanation": (
            "In Python, you create a variable simply by writing the name, "
            "an equals sign, and the value: age = 25. There is no need for "
            "keywords like 'var', 'let', or type declarations."
        ),
    },
    {
        "q": "What does the expression 10 // 3 evaluate to?",
        "options": [
            "A) 3.333...",
            "B) 3",
            "C) 1",
            "D) 30",
        ],
        "answer": "b",
        "explanation": (
            "The // operator is floor division (integer division). It divides "
            "and rounds down to the nearest whole number. 10 // 3 = 3. "
            "Regular division (/) would give 3.333..."
        ),
    },
    {
        "q": "Which of these is a FALSY value in Python?",
        "options": [
            'A) "False" (the string)',
            "B) 1",
            "C) [0] (a list containing zero)",
            "D) 0 (the integer zero)",
        ],
        "answer": "d",
        "explanation": (
            "The integer 0 is falsy in Python. The string 'False' is truthy "
            "(because it is a non-empty string). The list [0] is truthy "
            "(because it is a non-empty list). The number 1 is truthy."
        ),
    },
    {
        "q": "What does the 'break' keyword do inside a loop?",
        "options": [
            "A) Skips the current iteration and moves to the next one",
            "B) Immediately exits the loop entirely",
            "C) Pauses the loop for one second",
            "D) Restarts the loop from the beginning",
        ],
        "answer": "b",
        "explanation": (
            "'break' immediately exits the loop. The code after the loop "
            "continues. 'continue' is the keyword that skips to the next "
            "iteration."
        ),
    },
    {
        "q": "What is the main difference between a list and a tuple?",
        "options": [
            "A) Lists use square brackets, tuples use angle brackets",
            "B) Tuples can hold more items than lists",
            "C) Lists are mutable (changeable), tuples are immutable (fixed)",
            "D) Tuples are faster but can only hold numbers",
        ],
        "answer": "c",
        "explanation": (
            "The key difference is mutability. Lists can be modified after "
            "creation (append, remove, change items). Tuples cannot be "
            "changed once created. Both use parentheses () for tuples and "
            "square brackets [] for lists."
        ),
    },
    {
        "q": "What does the .get() method on a dictionary do?",
        "options": [
            "A) Gets all keys from the dictionary",
            "B) Returns the value for a key, or a default if the key does not exist",
            "C) Gets the first item in the dictionary",
            "D) Removes and returns a key-value pair",
        ],
        "answer": "b",
        "explanation": (
            "dict.get(key, default) returns the value associated with the "
            "key if it exists. If the key is not found, it returns the "
            "default value (or None if no default is specified) instead of "
            "raising a KeyError."
        ),
    },
    {
        "q": "What is the purpose of the 'finally' block in a try/except/finally?",
        "options": [
            "A) It runs only if an exception was raised",
            "B) It runs only if no exception was raised",
            "C) It always runs, whether an exception occurred or not",
            "D) It catches any exceptions not caught by except",
        ],
        "answer": "c",
        "explanation": (
            "The 'finally' block ALWAYS runs -- after the try block succeeds, "
            "after an exception is caught, or even if an unhandled exception "
            "occurs. It is used for cleanup like closing files or network "
            "connections."
        ),
    },
    {
        "q": "Which file mode would you use to add data to the end of an existing file?",
        "options": [
            'A) "r" (read)',
            'B) "w" (write)',
            'C) "a" (append)',
            'D) "x" (exclusive create)',
        ],
        "answer": "c",
        "explanation": (
            "'a' (append) mode opens a file for writing at the end. Existing "
            "content is preserved and new data is added after it. 'w' mode "
            "would overwrite the entire file. 'r' is for reading only."
        ),
    },
    {
        "q": "What does this list comprehension produce: [x * 2 for x in range(5)]?",
        "options": [
            "A) [0, 1, 2, 3, 4]",
            "B) [2, 4, 6, 8, 10]",
            "C) [0, 2, 4, 6, 8]",
            "D) [1, 2, 3, 4, 5]",
        ],
        "answer": "c",
        "explanation": (
            "range(5) produces 0, 1, 2, 3, 4. Each value is multiplied by 2: "
            "0*2=0, 1*2=2, 2*2=4, 3*2=6, 4*2=8. Result: [0, 2, 4, 6, 8]."
        ),
    },
    {
        "q": "Why should you use 'with open(...)' instead of just 'open(...)'?",
        "options": [
            "A) 'with' makes file reads faster",
            "B) 'with' automatically closes the file, even if an error occurs",
            "C) 'with' encrypts the file contents",
            "D) 'with' is required in Python 3 -- 'open()' alone does not work",
        ],
        "answer": "b",
        "explanation": (
            "The 'with' statement (context manager) guarantees that the file "
            "is properly closed when the block ends, even if an exception "
            "occurs. Without 'with', you must manually call f.close(), and "
            "if an error occurs before that line, the file stays open."
        ),
    },
]


# ──────────────────────────────────────────────────────────────────────
#  Module entry point
# ──────────────────────────────────────────────────────────────────────
def run(progress):
    """Main entry point called from the menu system."""
    # Ensure module0 exists in progress
    if MODULE_KEY not in progress.get("modules", {}):
        progress.setdefault("modules", {})[MODULE_KEY] = {
            "completed_lessons": [],
            "quiz_scores": {},
            "challenges_done": [],
        }

    while True:
        choice = show_menu("Module 0: Python Fundamentals", [
            ("lesson1", "Lesson 1: Variables & Data Types"),
            ("lesson2", "Lesson 2: Control Flow -- Making Decisions"),
            ("lesson3", "Lesson 3: Loops & Iteration"),
            ("lesson4", "Lesson 4: Data Structures"),
            ("lesson5", "Lesson 5: Functions & Modules"),
            ("lesson6", "Lesson 6: Error Handling & File Basics"),
            ("quiz", "Take the Quiz"),
        ])

        if choice == "back":
            return
        if choice == "quit":
            raise SystemExit

        if choice == "lesson1":
            lesson_variables_and_types(progress)
        elif choice == "lesson2":
            lesson_control_flow(progress)
        elif choice == "lesson3":
            lesson_loops(progress)
        elif choice == "lesson4":
            lesson_data_structures(progress)
        elif choice == "lesson5":
            lesson_functions_modules(progress)
        elif choice == "lesson6":
            lesson_error_handling_files(progress)
        elif choice == "quiz":
            run_quiz(QUIZ_QUESTIONS, "python_fundamentals", MODULE_KEY, progress)
