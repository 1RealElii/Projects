import os
import json
import hashlib
import getpass
import string

USERS_FILE = "users.json"

# ANSI colors
CYAN = "\033[96m"
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
RESET = "\033[0m"


def load_users():
    if not os.path.exists(USERS_FILE):
        return {}
    with open(USERS_FILE, "r") as f:
        try:
            return json.load(f)
        except json.JSONDecodeError:
            return {}


def save_users(users):
    with open(USERS_FILE, "w") as f:
        json.dump(users, f, indent=2)


def hash_password(password, salt):
    return hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt.encode("utf-8"),
        100_000
    ).hex()


def check_password_strength(password):
    if len(password) < 8:
        return False, "must be at least 8 characters."

    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(c in string.punctuation for c in password)

    if not has_upper:
        return False, "must include at least one uppercase letter."
    if not has_lower:
        return False, "must include at least one lowercase letter."
    if not has_digit:
        return False, "must include at least one number."
    if not has_special:
        return False, "must include at least one special character."

    return True, "Strong password."


def create_account(users):
    username = input(YELLOW + "Choose a username: " + RESET).strip()
    if username in users:
        print(RED + "Username already exists. Try another.\n" + RESET)
        return users

    password = getpass.getpass(YELLOW + "Choose a password: " + RESET)

    ok, msg = check_password_strength(password)
    if not ok:
        print(RED + f"Weak password: {msg}" + RESET)
        print(YELLOW + "Tip: Use upper/lowercase, numbers, and symbols.\n" + RESET)
        return users

    confirm = getpass.getpass(YELLOW + "Confirm password: " + RESET)
    if password != confirm:
        print(RED + "Passwords do not match.\n" + RESET)
        return users

    salt = f"{username}_salt"
    users[username] = {
        "salt": salt,
        "password_hash": hash_password(password, salt)
    }
    save_users(users)
    print(GREEN + "Account created successfully.\n" + RESET)
    return users


def login(users):
    username = input(YELLOW + "Username: " + RESET).strip()
    if username not in users:
        print(RED + "User not found.\n" + RESET)
        return

    password = getpass.getpass(YELLOW + "Password: " + RESET)
    salt = users[username]["salt"]
    expected = users[username]["password_hash"]

    if hash_password(password, salt) == expected:
        print(GREEN + f"\n✅ Login successful! Welcome, {username}.\n" + RESET)
    else:
        print(RED + "\n❌ Invalid password. Access denied.\n" + RESET)


def main():
    users = load_users()

    while True:
        print(CYAN + "=== Secure Login System ===" + RESET)
        print("1. Create Account")
        print("2. Log In")
        print("3. Quit")
        choice = input(YELLOW + "Select an option (1-3): " + RESET).strip()

        if choice == "1":
            users = create_account(users)
        elif choice == "2":
            login(users)
        elif choice == "3":
            print(GREEN + "Exiting. Goodbye." + RESET)
            break
        else:
            print(RED + "Invalid choice. Try again.\n" + RESET)


if __name__ == "__main__":
    main()
