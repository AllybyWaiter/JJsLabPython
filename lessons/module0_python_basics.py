"""
Module 0: Python Fundamentals
A prerequisite module for learners who are new to Python. Assumes zero prior
programming knowledge and teaches Python from the ground up, building the
foundation needed for all subsequent security modules.
"""

from utils.display import (
    section_header, sub_header, lesson_block, code_block,
    scenario_block, why_it_matters, info, success, warning, press_enter,
    show_menu, disclaimer, hint_text, ask_yes_no, C, G, Y, R, RESET, BRIGHT, DIM
)
from utils.progress import mark_lesson_complete, mark_challenge_complete
from utils.quiz import run_quiz


# ──────────────────────────────────────────────────────────────────────
#  Module metadata
# ──────────────────────────────────────────────────────────────────────
MODULE_KEY = "module0"


# ──────────────────────────────────────────────────────────────────────
#  Lesson 1 — Getting Started: Variables & Data Types
# ──────────────────────────────────────────────────────────────────────
def lesson_variables_and_types(progress):
    section_header("Lesson 1: Getting Started -- Variables & Data Types")

    lesson_block(
        "Welcome to Python! Python is one of the most popular programming "
        "languages in the world, and it is the number one language used in "
        "cybersecurity. Whether you want to automate tasks, analyze log files, "
        "write security tools, or understand how hackers think, Python is where "
        "you start. It was designed to be easy to read and write, which makes "
        "it perfect for beginners."
    )

    lesson_block(
        "A program is simply a set of instructions that tells a computer what "
        "to do. Think of it like a recipe: you write down the steps, and the "
        "computer follows them one by one, from top to bottom. Python lets you "
        "write those instructions in a language that looks almost like English."
    )

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
        "computer completely ignores comments. They start with the # symbol. "
        "Good comments explain WHY you did something, not what the code does."
    )

    code_block("""\
# This is a comment -- Python ignores this line completely
# Comments help you (and others) understand your code later

# You can also put comments at the end of a line:
x = 10  # This stores the number 10 in a variable called x

# Multi-line comments use triple quotes (also called docstrings):
\"\"\"
This is a multi-line comment.
It can span as many lines as you need.
Often used to describe what a function or file does.
\"\"\"""")

    press_enter()

    # ── Variables ──
    sub_header("Variables -- Storing Information")

    lesson_block(
        "A variable is like a labeled box where you store information. You give "
        "the box a name, put something inside it, and later you can look inside "
        "the box to see what is there. In Python, you create a variable by "
        "choosing a name, typing an equals sign, and then the value you want "
        "to store."
    )

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

    lesson_block(
        "Variable naming rules: (1) Names can contain letters, numbers, and "
        "underscores, but must start with a letter or underscore, never a "
        "number. (2) Names are case-sensitive -- 'Age' and 'age' are different "
        "variables. (3) You cannot use Python keywords like 'if', 'for', "
        "'while', 'class', etc. as variable names. (4) Use descriptive names: "
        "'user_age' is better than 'x'."
    )

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

    press_enter()

    # ── Data Types ──
    sub_header("Data Types -- Different Kinds of Information")

    lesson_block(
        "Not all information is the same. A person's name is text, their age "
        "is a whole number, their weight might have decimals, and whether they "
        "are logged in is either yes or no. Python has different data types for "
        "each kind of information."
    )

    code_block("""\
# int -- whole numbers (no decimal point)
port_number = 443
failed_attempts = 7
year = 2025

# float -- decimal numbers
success_rate = 99.7
pi = 3.14159
temperature = -40.0

# str -- strings of text (always in quotes)
hostname = "server01.company.com"
greeting = 'Hello, World!'     # Single or double quotes both work
ip_address = "192.168.1.1"

# bool -- True or False (only two possible values)
is_connected = True
has_firewall = False

# Check the type of any variable using type()
print(type(port_number))    # Output: <class 'int'>
print(type(success_rate))   # Output: <class 'float'>
print(type(hostname))       # Output: <class 'str'>
print(type(is_connected))   # Output: <class 'bool'>""")

    press_enter()

    # ── Type Conversion ──
    sub_header("Type Conversion -- Changing Between Types")

    lesson_block(
        "Sometimes you need to convert one type to another. For example, when "
        "you read input from a user, Python always gives you a string, even if "
        "the user typed a number. You need to convert it to an integer before "
        "you can do math with it."
    )

    code_block("""\
# Converting between types
age_text = "25"           # This is a string, not a number
age_number = int("25")    # Now it is an integer: 25
print(age_number + 5)     # Output: 30

price = float("19.99")    # Convert string to decimal: 19.99
count = str(42)            # Convert number to string: "42"

# Be careful -- not everything can be converted!
# int("hello")  # ERROR: Python cannot turn "hello" into a number
# int("3.14")   # ERROR: Use float() first, then int()

# Safe conversion chain:
value = "3.14"
as_float = float(value)   # "3.14" -> 3.14
as_int = int(as_float)    # 3.14 -> 3 (drops the decimal part)
print(as_int)             # Output: 3""")

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
print(a ** b)   # Exponent:       1000 (10 to the power of 3)

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
        "passwords, IP addresses, log entries, URLs, and more. Python gives "
        "you powerful tools for working with strings."
    )

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
print(f"Connecting to port {port + 1}")  # Output: Connecting to port 444

# Useful string methods
message = "Hello, World!"
print(message.upper())        # "HELLO, WORLD!"
print(message.lower())        # "hello, world!"
print(message.replace("World", "Hacker"))  # "Hello, Hacker!"
print(len(message))           # 13 (length of the string)

# Checking contents
email = "admin@company.com"
print(email.startswith("admin"))   # True
print(email.endswith(".com"))      # True
print("@" in email)                # True (checks if @ appears anywhere)

# Stripping whitespace (very useful when reading files or user input)
raw_input = "  hello  "
clean = raw_input.strip()     # "hello" (removes spaces from both sides)""")

    press_enter()

    # ── User Input ──
    sub_header("Getting Input from the User")

    lesson_block(
        "The input() function pauses your program and waits for the user to "
        "type something. Whatever they type is returned as a string. This is "
        "how you make interactive programs."
    )

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

    scenario_block("Social Engineering Awareness Tool", (
        "You are building a quick training tool that asks employees to enter "
        "their email address and then checks if it follows the company format. "
        "Using variables, strings, and input(), you collect the email, check "
        "if it ends with '@company.com' using .endswith(), and display whether "
        "it is valid. This simple script helps train employees to recognize "
        "phishing emails that use look-alike domains."
    ))

    press_enter()

    # ── Practice Challenge ──
    sub_header("Practice Challenge: Simple Calculator")
    info("Build a calculator that asks the user for two numbers and an")
    info("operator (+, -, *, /), then prints the result.\n")
    info("Example:")
    info("  Enter first number: 15")
    info("  Enter second number: 4")
    info("  Enter operator (+, -, *, /): *")
    info("  Result: 15 * 4 = 60\n")

    if ask_yes_no("Would you like a hint?"):
        hint_text("Use input() to get the numbers and operator.")
        hint_text("Convert the numbers with float() so decimals work too.")
        hint_text("Use if/elif to check which operator was entered.")

    press_enter()

    if ask_yes_no("Show the full solution?"):
        code_block("""\
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
    print(f"Result: {num1} {operator} {num2} = {result}")""")
    press_enter()

    mark_lesson_complete(progress, MODULE_KEY, "lesson1")
    success("Lesson 1 complete: Variables & Data Types")
    press_enter()


# ──────────────────────────────────────────────────────────────────────
#  Lesson 2 — Control Flow: Making Decisions
# ──────────────────────────────────────────────────────────────────────
def lesson_control_flow(progress):
    section_header("Lesson 2: Control Flow -- Making Decisions")

    lesson_block(
        "So far, our programs run every line from top to bottom without making "
        "any choices. But real programs need to make decisions: Is the password "
        "correct? Is this IP address on the blocklist? Did the user enter valid "
        "data? Control flow lets your program choose different paths depending "
        "on conditions."
    )

    lesson_block(
        "Think of it like a security guard at a door. The guard checks your "
        "badge: if the badge is valid, you get in; if it is expired, you are "
        "redirected; otherwise, you are turned away. Python uses if, elif "
        "(short for 'else if'), and else to make these kinds of decisions."
    )

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
        "operators compare two values and return True or False (a boolean). "
        "Think of each operator as asking a yes/no question."
    )

    code_block("""\
# Comparison operators return True or False
x = 10
y = 20

print(x == y)     # Equal to?           False
print(x != y)     # Not equal to?       True
print(x < y)      # Less than?          True
print(x > y)      # Greater than?       False
print(x <= 10)    # Less than or equal? True
print(x >= 15)    # Greater or equal?   False

# Works with strings too!
name = "Alice"
print(name == "Alice")     # True
print(name == "alice")     # False (case-sensitive!)
print(name != "Bob")       # True

# COMMON MISTAKE: == vs =
# x = 10     means "store 10 in x" (assignment)
# x == 10    means "is x equal to 10?" (comparison)""")

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
# Output: Password length is acceptable.

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

    lesson_block(
        "Important: Notice the indentation (the spaces at the beginning of "
        "lines). Python uses indentation to know which lines belong inside "
        "the if block. Every line that is indented under the 'if' will only "
        "run when the condition is True. Standard practice is to use 4 spaces "
        "for each level of indentation."
    )

    press_enter()

    # ── Logical Operators ──
    sub_header("Logical Operators -- Combining Conditions")

    lesson_block(
        "Sometimes one condition is not enough. You might need to check if "
        "a user is BOTH logged in AND an admin. Or you might want to allow "
        "access if the user provides a valid password OR a valid token. "
        "Logical operators let you combine multiple conditions."
    )

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
    print("Elevated access granted")  # This runs

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
        "is not a boolean. This is called 'truthiness'. The following values "
        "are considered False (falsy): False, 0, 0.0, empty string '', empty "
        "list [], empty dict {}, and None. Everything else is True (truthy). "
        "This is very useful for quick checks."
    )

    code_block("""\
# Falsy values -- these all act as False in an if statement
if not 0:
    print("0 is falsy")               # Prints
if not "":
    print("Empty string is falsy")     # Prints
if not []:
    print("Empty list is falsy")       # Prints
if not None:
    print("None is falsy")             # Prints

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
    print("Standard user access.")

# Tip: Deeply nested code (3+ levels) can be hard to read.
# Consider using 'and' to flatten conditions when possible:
if role == "admin" and mfa_verified and ip_address.startswith("192.168."):
    print("Internal admin with MFA -- full access.")""")

    press_enter()

    # ── match/case ──
    sub_header("match/case -- Pattern Matching (Python 3.10+)")

    lesson_block(
        "Python 3.10 introduced match/case, which is similar to a switch "
        "statement in other languages. It is useful when you have many "
        "possible values to check against."
    )

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

    scenario_block("Access Control Decision Engine", (
        "You are writing the logic for a company's internal portal. When an "
        "employee tries to access a sensitive resource, your Python script "
        "checks multiple conditions: Is the user authenticated? Is their "
        "account active? Is their IP from the corporate network? Do they "
        "have the right role? Each condition is an if/elif check, and the "
        "script logs every decision for the security team to audit later."
    ))

    press_enter()

    # ── Practice Challenge ──
    sub_header("Practice Challenge: Password Validator")
    info("Build a password validator that checks if a password meets these rules:")
    info("  1. At least 8 characters long")
    info("  2. Contains at least one uppercase letter")
    info("  3. Contains at least one lowercase letter")
    info("  4. Contains at least one digit")
    info("  5. Does not contain the word 'password'\n")
    info("Print a message for each rule that passes or fails.\n")

    if ask_yes_no("Would you like a hint?"):
        hint_text("Use len(password) to check length.")
        hint_text("Loop through each character and check with .isupper(), .isdigit(), etc.")
        hint_text("Use 'password' in pw.lower() to check for the forbidden word.")

    press_enter()

    if ask_yes_no("Show the full solution?"):
        code_block("""\
def validate_password(password):
    \"\"\"Check a password against security rules.\"\"\"
    issues = []

    # Rule 1: Length
    if len(password) < 8:
        issues.append("Must be at least 8 characters long")

    # Rule 2: Uppercase
    has_upper = False
    for char in password:
        if char.isupper():
            has_upper = True
            break
    if not has_upper:
        issues.append("Must contain at least one uppercase letter")

    # Rule 3: Lowercase
    has_lower = False
    for char in password:
        if char.islower():
            has_lower = True
            break
    if not has_lower:
        issues.append("Must contain at least one lowercase letter")

    # Rule 4: Digit
    has_digit = False
    for char in password:
        if char.isdigit():
            has_digit = True
            break
    if not has_digit:
        issues.append("Must contain at least one digit")

    # Rule 5: No 'password'
    if "password" in password.lower():
        issues.append("Must not contain the word 'password'")

    # Results
    if issues:
        print("Password REJECTED. Issues found:")
        for issue in issues:
            print(f"  - {issue}")
    else:
        print("Password ACCEPTED! Meets all requirements.")

    return len(issues) == 0

# Test it
test_passwords = ["short", "alllowercase1", "ALLUPPERCASE1",
                  "NoDigitsHere", "MyPassword1", "Str0ngP@ss!"]
for pw in test_passwords:
    print(f"\\nTesting: '{pw}'")
    validate_password(pw)""")
    press_enter()

    mark_lesson_complete(progress, MODULE_KEY, "lesson2")
    success("Lesson 2 complete: Control Flow")
    press_enter()


# ──────────────────────────────────────────────────────────────────────
#  Lesson 3 — Loops & Iteration
# ──────────────────────────────────────────────────────────────────────
def lesson_loops(progress):
    section_header("Lesson 3: Loops & Iteration")

    lesson_block(
        "Imagine you need to check 1000 IP addresses to see which ones are "
        "online. You would not write 1000 separate lines of code. Instead, "
        "you use a loop -- a way to repeat a block of code over and over. "
        "Loops are one of the most powerful concepts in programming because "
        "they let a few lines of code do the work of thousands."
    )

    lesson_block(
        "Python has two main types of loops. A 'for' loop repeats a fixed "
        "number of times -- you know in advance how many iterations there "
        "will be. A 'while' loop keeps repeating as long as a condition is "
        "True -- you might not know in advance when it will stop."
    )

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
#   Scanning port 8443...

# range() generates a sequence of numbers
for i in range(5):
    print(f"Attempt {i}")
# Output: Attempt 0, Attempt 1, Attempt 2, Attempt 3, Attempt 4
# Note: range(5) gives 0, 1, 2, 3, 4 -- it stops BEFORE 5

# range() with start, stop, and step
for i in range(1, 11):        # 1 through 10
    print(i, end=" ")
print()  # Output: 1 2 3 4 5 6 7 8 9 10

for i in range(0, 100, 10):   # 0, 10, 20, ... 90
    print(i, end=" ")
print()  # Output: 0 10 20 30 40 50 60 70 80 90

# Looping through a string (character by character)
password = "S3cur3!"
for char in password:
    print(f"  Character: {char}")""")

    press_enter()

    # ── while loops ──
    sub_header("while Loops -- Repeating Until a Condition Changes")

    lesson_block(
        "A while loop checks a condition before each iteration. If the "
        "condition is True, it runs the code inside. Then it checks again. "
        "This continues until the condition becomes False. Be careful: if "
        "the condition never becomes False, you get an infinite loop!"
    )

    code_block("""\
# Basic while loop -- counting up
count = 0
while count < 5:
    print(f"Count is {count}")
    count += 1  # IMPORTANT: change the variable so the loop eventually stops
# Output: Count is 0, Count is 1, Count is 2, Count is 3, Count is 4

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
        print("Failed. Retrying...")

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
        "skips the rest of the current iteration and jumps to the next one. "
        "The 'else' clause on a loop runs only if the loop finished normally "
        "(was not interrupted by break)."
    )

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
#   Found a number greater than 7: 8

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
#   ERROR: Connection lost

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
# Each host gets all three ports checked

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
    print(f"  {num}. {server}")

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
        "loop and an optional if condition inside square brackets. It is "
        "more compact and often faster than a regular for loop."
    )

    code_block("""\
# Regular loop to create a list
squares = []
for i in range(10):
    squares.append(i ** 2)
print(squares)  # [0, 1, 4, 9, 16, 25, 36, 49, 64, 81]

# Same thing as a list comprehension (one line!)
squares = [i ** 2 for i in range(10)]
print(squares)  # [0, 1, 4, 9, 16, 25, 36, 49, 64, 81]

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

    scenario_block("Automated Port Scanning", (
        "A penetration tester needs to check which of the 65,535 TCP ports "
        "are open on a target server. Using a for loop with range(1, 65536), "
        "they attempt a connection to each port. For each successful connection "
        "they add the port to a list. After the scan, they use a list "
        "comprehension to filter only the 'interesting' ports (those commonly "
        "associated with vulnerable services). The entire scan is just 15 lines "
        "of Python."
    ))

    press_enter()

    # ── Practice Challenge ──
    sub_header("Practice Challenge: Number Guessing Game")
    info("Build a number guessing game:")
    info("  1. The program picks a random number between 1 and 100")
    info("  2. The user guesses, and the program says 'too high' or 'too low'")
    info("  3. The game continues until the user guesses correctly")
    info("  4. Count and display the number of attempts")
    info("  5. BONUS: Limit to 7 guesses and tell them if they lose\n")

    if ask_yes_no("Would you like a hint?"):
        hint_text("Use 'import random' and 'random.randint(1, 100)' to pick a number.")
        hint_text("Use a while loop that runs until the guess matches the secret.")
        hint_text("Use int(input(...)) to get the user's guess as a number.")

    press_enter()

    if ask_yes_no("Show the full solution?"):
        code_block("""\
import random

secret = random.randint(1, 100)
max_guesses = 7
attempts = 0

print("I'm thinking of a number between 1 and 100.")
print(f"You have {max_guesses} guesses. Good luck!")

while attempts < max_guesses:
    guess_text = input(f"\\nGuess #{attempts + 1}: ")

    if not guess_text.isdigit():
        print("Please enter a valid number.")
        continue

    guess = int(guess_text)
    attempts += 1

    if guess == secret:
        print(f"\\nYou got it in {attempts} attempts!")
        break
    elif guess < secret:
        print("Too low!")
    else:
        print("Too high!")

    remaining = max_guesses - attempts
    if remaining > 0:
        print(f"({remaining} guesses remaining)")
else:
    print(f"\\nGame over! The number was {secret}.")""")
    press_enter()

    mark_lesson_complete(progress, MODULE_KEY, "lesson3")
    success("Lesson 3 complete: Loops & Iteration")
    press_enter()


# ──────────────────────────────────────────────────────────────────────
#  Lesson 4 — Data Structures: Lists, Dicts, Sets, Tuples
# ──────────────────────────────────────────────────────────────────────
def lesson_data_structures(progress):
    section_header("Lesson 4: Data Structures -- Lists, Dicts, Sets, Tuples")

    lesson_block(
        "So far, each variable has held a single value. But in the real world, "
        "you need to work with collections of data: a list of IP addresses, a "
        "mapping of usernames to roles, a set of unique ports, and more. Python "
        "gives you four built-in data structures for organizing collections: "
        "lists, dictionaries, sets, and tuples."
    )

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
        "are separated by commas. Lists are the most commonly used data "
        "structure in Python."
    )

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

    code_block("""\
# Modifying lists
servers = ["web01", "db01", "app01"]

# Adding items
servers.append("mail01")            # Add to end: ['web01', 'db01', 'app01', 'mail01']
servers.insert(1, "proxy01")        # Insert at index 1: ['web01', 'proxy01', 'db01', ...]

# Removing items
servers.remove("db01")              # Remove by value
last = servers.pop()                # Remove and return last item
specific = servers.pop(0)           # Remove and return item at index 0

# Other useful operations
numbers = [3, 1, 4, 1, 5, 9, 2, 6]
numbers.sort()                      # Sort in place: [1, 1, 2, 3, 4, 5, 6, 9]
numbers.reverse()                   # Reverse in place: [9, 6, 5, 4, 3, 2, 1, 1]
print(len(numbers))                 # 8 (length of the list)
print(5 in numbers)                 # True (is 5 in the list?)
print(numbers.count(1))             # 2 (how many times does 1 appear?)
print(numbers.index(5))             # Index of first occurrence of 5""")

    press_enter()

    # ── Dictionaries ──
    sub_header("Dictionaries -- Key-Value Pairs")

    lesson_block(
        "A dictionary (dict) stores data as key-value pairs, like a real "
        "dictionary where each word (key) has a definition (value). "
        "Dictionaries are created with curly braces {} and use colons to "
        "separate keys from values. They are incredibly useful for "
        "representing structured data."
    )

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
print(user.get("email", "N/A"))    # "N/A" (custom default)

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
        print(f"  ALERT: {server} is {status}!")

# Nested dictionaries
employees = {
    "alice": {"role": "admin", "department": "IT Security"},
    "bob": {"role": "analyst", "department": "SOC"},
    "charlie": {"role": "engineer", "department": "DevOps"}
}
print(employees["alice"]["department"])  # "IT Security" """)

    press_enter()

    # ── Sets ──
    sub_header("Sets -- Unique Values Only")

    lesson_block(
        "A set is a collection of unique items -- no duplicates allowed. "
        "Sets are useful when you need to eliminate duplicates or perform "
        "mathematical set operations like union, intersection, and difference."
    )

    code_block("""\
# Creating sets
open_ports = {22, 80, 443, 80, 22}  # Duplicates are removed automatically
print(open_ports)                    # {80, 443, 22} (order may vary)

# Sets from a list (removes duplicates)
ip_list = ["10.0.0.1", "10.0.0.2", "10.0.0.1", "10.0.0.3", "10.0.0.2"]
unique_ips = set(ip_list)
print(unique_ips)       # {'10.0.0.1', '10.0.0.2', '10.0.0.3'}
print(len(unique_ips))  # 3

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
        "brackets. Use tuples for data that should not be modified, like "
        "coordinates, database records, or function return values."
    )

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
print(f"Host: {host}, IP: {ip}, Port: {port}")

# You cannot modify a tuple:
# coordinates[0] = 50.0   # ERROR: tuples do not support assignment

# Tuples are commonly returned by functions
# divmod() returns a tuple of (quotient, remainder)
quotient, remainder = divmod(17, 5)
print(f"17 / 5 = {quotient} remainder {remainder}")  # 3 remainder 2""")

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

    scenario_block("Intrusion Detection Data Model", (
        "You are building a simple intrusion detection system. You use a "
        "dictionary to store alerts, where each key is a timestamp and the "
        "value is a dict with source IP, destination IP, and alert type. "
        "You use a set to track unique attacking IPs. You use a list to "
        "maintain the chronological order of events. Choosing the right "
        "data structure for each job makes your code clean and efficient."
    ))

    press_enter()

    # ── Practice Challenge ──
    sub_header("Practice Challenge: Contact Book")
    info("Build a contact book program using a dictionary:")
    info("  1. Store contacts as {name: {phone, email, role}}")
    info("  2. Allow adding new contacts")
    info("  3. Allow looking up contacts by name")
    info("  4. Allow listing all contacts")
    info("  5. Allow deleting contacts\n")

    if ask_yes_no("Would you like a hint?"):
        hint_text("Use a while loop for the main menu with options for each action.")
        hint_text("Use a dict of dicts: contacts = {'Alice': {'phone': '555-0100', ...}}")
        hint_text("Use .get() to safely look up contacts that might not exist.")

    press_enter()

    if ask_yes_no("Show the full solution?"):
        code_block("""\
def contact_book():
    \"\"\"A simple contact book using dictionaries.\"\"\"
    contacts = {}

    while True:
        print("\\n--- Contact Book ---")
        print("1. Add contact")
        print("2. Look up contact")
        print("3. List all contacts")
        print("4. Delete contact")
        print("5. Quit")

        choice = input("\\nChoice: ").strip()

        if choice == "1":
            name = input("Name: ").strip()
            phone = input("Phone: ").strip()
            email = input("Email: ").strip()
            role = input("Role: ").strip()
            contacts[name] = {"phone": phone, "email": email, "role": role}
            print(f"Added {name}!")

        elif choice == "2":
            name = input("Name to look up: ").strip()
            contact = contacts.get(name)
            if contact:
                print(f"  Name:  {name}")
                print(f"  Phone: {contact['phone']}")
                print(f"  Email: {contact['email']}")
                print(f"  Role:  {contact['role']}")
            else:
                print(f"  '{name}' not found.")

        elif choice == "3":
            if not contacts:
                print("  No contacts yet.")
            else:
                for name, info in contacts.items():
                    print(f"  {name}: {info['email']} ({info['role']})")

        elif choice == "4":
            name = input("Name to delete: ").strip()
            if name in contacts:
                del contacts[name]
                print(f"Deleted {name}.")
            else:
                print(f"'{name}' not found.")

        elif choice == "5":
            print("Goodbye!")
            break

contact_book()""")
    press_enter()

    mark_lesson_complete(progress, MODULE_KEY, "lesson4")
    success("Lesson 4 complete: Data Structures")
    press_enter()


# ──────────────────────────────────────────────────────────────────────
#  Lesson 5 — Functions & Modules
# ──────────────────────────────────────────────────────────────────────
def lesson_functions_modules(progress):
    section_header("Lesson 5: Functions & Modules")

    lesson_block(
        "As your programs get bigger, you need a way to organize your code "
        "into reusable pieces. A function is a named block of code that "
        "performs a specific task. You define it once and can call it as many "
        "times as you want. Think of a function like a tool in a toolbox: you "
        "build the tool once, and then use it whenever you need it."
    )

    lesson_block(
        "Functions have three big benefits. First, they avoid repetition: "
        "instead of copying the same code in 10 places, you write it once "
        "in a function. Second, they make code readable: a well-named "
        "function tells you what a block of code does without reading every "
        "line. Third, they make testing easier: you can test each function "
        "independently."
    )

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
greet()           # You can call it as many times as you want

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

    press_enter()

    # ── Return Values ──
    sub_header("Return Values -- Getting Results Back")

    lesson_block(
        "A function can send a result back to the code that called it using "
        "the 'return' statement. Think of it as the function handing you an "
        "answer. Without return, a function does its work but gives you "
        "nothing back (technically it returns None)."
    )

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
print(is_valid_port(99999))    # False

# A function can return multiple values (as a tuple)
def analyze_password(password):
    \"\"\"Return length and whether it has digits.\"\"\"
    length = len(password)
    has_digits = any(c.isdigit() for c in password)
    return length, has_digits

pw_length, pw_has_digits = analyze_password("Hello123")
print(f"Length: {pw_length}, Has digits: {pw_has_digits}")
# Output: Length: 8, Has digits: True

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

    press_enter()

    # ── Scope ──
    sub_header("Scope -- Where Variables Live")

    lesson_block(
        "A variable created inside a function only exists inside that "
        "function. This is called 'local scope'. A variable created outside "
        "all functions exists everywhere and is called 'global scope'. This "
        "separation prevents functions from accidentally changing each other's "
        "data."
    )

    code_block("""\
# Global vs local scope
message = "I am global"     # Global variable

def my_function():
    message = "I am local"  # Local variable (different from the global one!)
    secret = "hidden"       # Local variable
    print(message)          # "I am local"

my_function()
print(message)              # "I am global" (unchanged!)
# print(secret)             # ERROR: secret does not exist outside the function

# Accessing global variables inside a function (read only)
app_name = "JJ's LAB"

def show_app():
    print(f"App: {app_name}")  # Can READ the global variable

show_app()  # Output: App: JJ's LAB""")

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
# ports becomes a tuple: (22, 80, 443, 8080)

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
        "from scratch, you import what you need. This is one of Python's "
        "biggest strengths: there is a module for almost everything."
    )

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
print(rng.randint(1, 100))

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

    code_block("""\
# Quick examples of common modules

# os -- file and system operations
import os
print(f"Current directory: {os.getcwd()}")
print(f"Home directory: {os.path.expanduser('~')}")
print(f"File exists: {os.path.exists('/etc/passwd')}")

# math -- mathematical operations
import math
print(f"Square root of 144: {math.sqrt(144)}")     # 12.0
print(f"Ceiling of 4.2: {math.ceil(4.2)}")         # 5
print(f"Log base 2 of 256: {math.log2(256)}")      # 8.0

# random -- generating random values
import random
print(f"Random int 1-100: {random.randint(1, 100)}")
print(f"Random choice: {random.choice(['red', 'blue', 'green'])}")

# datetime -- working with dates and times
from datetime import datetime, timedelta
now = datetime.now()
print(f"Now: {now.strftime('%Y-%m-%d %H:%M:%S')}")
yesterday = now - timedelta(days=1)
print(f"Yesterday: {yesterday.strftime('%Y-%m-%d')}")""")

    scenario_block("Building a Security Toolkit", (
        "A security analyst creates a Python file called sec_utils.py that "
        "contains utility functions: hash_string() for computing SHA-256 "
        "hashes, validate_ip() for checking IP address format, and "
        "timestamp_log() for adding timestamps to log entries. Other scripts "
        "in the project import these functions with 'from sec_utils import "
        "hash_string, validate_ip'. This modular approach means the team "
        "writes each utility once and reuses it across dozens of scripts."
    ))

    press_enter()

    # ── Practice Challenge ──
    sub_header("Practice Challenge: Utility Function Library")
    info("Create a collection of useful functions:")
    info("  1. is_valid_ip(ip) -- checks if a string is a valid IPv4 address")
    info("  2. generate_password(length) -- generates a random password")
    info("  3. caesar_cipher(text, shift) -- encrypts text with a Caesar cipher")
    info("  4. count_words(text) -- returns a dict of word frequencies")
    info("  5. format_bytes(num_bytes) -- converts bytes to KB/MB/GB\n")

    if ask_yes_no("Would you like a hint?"):
        hint_text("For is_valid_ip: split by '.', check 4 parts, each 0-255.")
        hint_text("For generate_password: use random.choice() in a loop with a charset string.")
        hint_text("For caesar_cipher: use ord() and chr() to shift characters.")

    press_enter()

    if ask_yes_no("Show the full solution?"):
        code_block("""\
import random
import string

def is_valid_ip(ip):
    \"\"\"Check if a string is a valid IPv4 address.\"\"\"
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    for part in parts:
        if not part.isdigit():
            return False
        num = int(part)
        if num < 0 or num > 255:
            return False
    return True

def generate_password(length=16):
    \"\"\"Generate a random password of the given length.\"\"\"
    charset = string.ascii_letters + string.digits + "!@#$%^&*"
    password = ""
    for _ in range(length):
        password += random.choice(charset)
    return password

def caesar_cipher(text, shift):
    \"\"\"Encrypt text using a Caesar cipher.\"\"\"
    result = ""
    for char in text:
        if char.isalpha():
            base = ord("A") if char.isupper() else ord("a")
            shifted = (ord(char) - base + shift) % 26 + base
            result += chr(shifted)
        else:
            result += char  # Keep non-letters unchanged
    return result

def count_words(text):
    \"\"\"Count word frequencies in a text string.\"\"\"
    words = text.lower().split()
    counts = {}
    for word in words:
        word = word.strip(".,!?;:")  # Remove punctuation
        counts[word] = counts.get(word, 0) + 1
    return counts

def format_bytes(num_bytes):
    \"\"\"Convert bytes to a human-readable string.\"\"\"
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if num_bytes < 1024:
            return f"{num_bytes:.1f} {unit}"
        num_bytes /= 1024
    return f"{num_bytes:.1f} PB"

# Test all functions
print(is_valid_ip("192.168.1.1"))    # True
print(is_valid_ip("999.0.0.1"))      # False
print(generate_password(20))          # Random 20-char password
print(caesar_cipher("Hello", 3))      # "Khoor"
print(caesar_cipher("Khoor", -3))     # "Hello" (decrypt)
print(count_words("the cat sat on the mat the cat"))
# {'the': 3, 'cat': 2, 'sat': 1, 'on': 1, 'mat': 1}
print(format_bytes(1536))             # "1.5 KB"
print(format_bytes(2_500_000_000))    # "2.3 GB" """)
    press_enter()

    mark_lesson_complete(progress, MODULE_KEY, "lesson5")
    success("Lesson 5 complete: Functions & Modules")
    press_enter()


# ──────────────────────────────────────────────────────────────────────
#  Lesson 6 — Error Handling & File Basics
# ──────────────────────────────────────────────────────────────────────
def lesson_error_handling_files(progress):
    section_header("Lesson 6: Error Handling & File Basics")

    lesson_block(
        "Things go wrong. A lot. The file you are trying to read does not "
        "exist. The user types 'abc' when you expected a number. The network "
        "connection times out. A dictionary key is missing. Good programs "
        "do not crash when things go wrong -- they handle errors gracefully. "
        "Python's try/except system lets you catch errors and decide what to "
        "do about them."
    )

    lesson_block(
        "In Python, errors are called 'exceptions'. When an error occurs, "
        "Python 'raises' (throws) an exception. If you do not catch it, your "
        "program crashes with an error message. But if you wrap the risky "
        "code in a try/except block, you can catch the exception and handle "
        "it -- maybe print a friendly error message, retry, or log the issue."
    )

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
print("Program continues...")

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
    print("KeyError: 'email' not found in dictionary")

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
    print("Operation complete.")

# Example flow if user enters "5":
#   try block runs, no error -> else block runs -> finally block runs
#   Output: Result: 20.0  \\n  Operation complete.

# Example flow if user enters "abc":
#   try block raises ValueError -> except block runs -> finally block runs
#   Output: Error: Please enter a valid number.  \\n  Operation complete.""")

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
    print(f"Invalid port: {e}")

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

    press_enter()

    # ── Reading Files ──
    sub_header("Reading Files")

    lesson_block(
        "Python makes it easy to read and write files. The most important "
        "thing to remember is to use the 'with' statement (called a context "
        "manager). It automatically closes the file when you are done, even "
        "if an error occurs. Forgetting to close files is a common bug."
    )

    code_block("""\
# Reading an entire file at once
with open("example.txt", "r") as f:
    content = f.read()
    print(content)
# The file is automatically closed when the 'with' block ends

# Reading line by line (memory-efficient for large files)
with open("log.txt", "r") as f:
    for line in f:
        print(line.strip())  # strip() removes the newline at the end

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
        f.write(f"  - Port {port}\\n")

# Appending to a file (adds to the end, doesn't overwrite)
with open("report.txt", "a") as f:
    f.write("\\n--- Scan Complete ---\\n")

# Writing multiple lines at once
lines = ["Line 1\\n", "Line 2\\n", "Line 3\\n"]
with open("output.txt", "w") as f:
    f.writelines(lines)""")

    lesson_block(
        "File modes explained: 'r' = read (file must exist), 'w' = write "
        "(creates new or overwrites existing), 'a' = append (adds to end "
        "of existing file), 'x' = exclusive create (fails if file exists). "
        "Add 'b' for binary mode: 'rb' reads binary files, 'wb' writes them."
    )

    press_enter()

    # ── Context Managers ──
    sub_header("Context Managers -- The 'with' Statement")

    lesson_block(
        "The 'with' statement is not just for files. It is a general pattern "
        "for managing resources that need to be cleaned up. When you use "
        "'with', Python guarantees the cleanup happens, even if an exception "
        "occurs. For files, 'cleanup' means closing the file."
    )

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
# File is closed automatically here, even if an error occurred

# You can open multiple files at once
with open("input.txt", "r") as infile, open("output.txt", "w") as outfile:
    for line in infile:
        outfile.write(line.upper())  # Convert each line to uppercase""")

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
print(os.path.isdir("/tmp"))             # True if it is a directory

# Getting file information
if os.path.exists(report):
    size = os.path.getsize(report)       # Size in bytes
    print(f"File size: {size} bytes")

# Splitting paths
path = "/var/log/auth.log"
directory = os.path.dirname(path)        # "/var/log"
filename = os.path.basename(path)        # "auth.log"
name, ext = os.path.splitext(filename)   # ("auth", ".log")
print(f"Dir: {directory}, File: {filename}, Extension: {ext}")

# Listing files in a directory
for item in os.listdir("/tmp"):
    full_path = os.path.join("/tmp", item)
    if os.path.isfile(full_path):
        print(f"  File: {item}")""")

    scenario_block("Log File Analysis During Incident Response", (
        "During a security incident at 2 AM, you need to quickly analyze "
        "server logs. Your Python script uses error handling to gracefully "
        "skip corrupted log lines, reads files line-by-line to handle the "
        "500 MB file without running out of memory, and writes a summary "
        "report. The try/except blocks ensure that a single malformed line "
        "does not crash the entire analysis. The with statement guarantees "
        "all files are properly closed even under pressure."
    ))

    press_enter()

    # ── Practice Challenge ──
    sub_header("Practice Challenge: Note-Taking App")
    info("Build a simple note-taking app that saves notes to a file:")
    info("  1. Add a new note (with a timestamp)")
    info("  2. View all notes")
    info("  3. Search notes by keyword")
    info("  4. Delete all notes")
    info("  5. Handle all possible file errors gracefully\n")

    if ask_yes_no("Would you like a hint?"):
        hint_text("Use 'a' mode to append new notes and 'r' mode to read them.")
        hint_text("Add timestamps with datetime.now().strftime('%Y-%m-%d %H:%M:%S').")
        hint_text("For search, read all lines and filter with 'keyword in line'.")

    press_enter()

    if ask_yes_no("Show the full solution?"):
        code_block("""\
import os
from datetime import datetime

NOTES_FILE = "my_notes.txt"

def add_note():
    \"\"\"Add a new note with a timestamp.\"\"\"
    note = input("Enter your note: ").strip()
    if not note:
        print("Empty note -- not saved.")
        return
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    try:
        with open(NOTES_FILE, "a") as f:
            f.write(f"[{timestamp}] {note}\\n")
        print("Note saved!")
    except PermissionError:
        print("Error: No permission to write to file.")
    except OSError as e:
        print(f"Error saving note: {e}")

def view_notes():
    \"\"\"Display all saved notes.\"\"\"
    try:
        with open(NOTES_FILE, "r") as f:
            notes = f.readlines()
        if not notes:
            print("No notes yet.")
        else:
            print(f"\\n--- Your Notes ({len(notes)} total) ---")
            for i, note in enumerate(notes, 1):
                print(f"  {i}. {note.strip()}")
    except FileNotFoundError:
        print("No notes file found. Add a note first!")

def search_notes(keyword):
    \"\"\"Search notes for a keyword.\"\"\"
    try:
        with open(NOTES_FILE, "r") as f:
            matches = [line.strip() for line in f
                       if keyword.lower() in line.lower()]
        if matches:
            print(f"\\nFound {len(matches)} matching notes:")
            for note in matches:
                print(f"  - {note}")
        else:
            print(f"No notes containing '{keyword}'.")
    except FileNotFoundError:
        print("No notes file found.")

def delete_all():
    \"\"\"Delete all notes after confirmation.\"\"\"
    confirm = input("Delete ALL notes? Type 'yes' to confirm: ")
    if confirm.lower() == "yes":
        try:
            os.remove(NOTES_FILE)
            print("All notes deleted.")
        except FileNotFoundError:
            print("No notes file to delete.")
    else:
        print("Cancelled.")

# Main loop
while True:
    print("\\n--- Note Taker ---")
    print("1. Add note")
    print("2. View notes")
    print("3. Search notes")
    print("4. Delete all")
    print("5. Quit")

    choice = input("Choice: ").strip()
    if choice == "1":
        add_note()
    elif choice == "2":
        view_notes()
    elif choice == "3":
        keyword = input("Search for: ").strip()
        search_notes(keyword)
    elif choice == "4":
        delete_all()
    elif choice == "5":
        print("Goodbye!")
        break""")
    press_enter()

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
