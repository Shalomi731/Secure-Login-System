import json       # Used to read and write to your users.json file
import logging    # Used to automatically write timestamps and events to security.log
import re         # Used for "Regular Expressions" to validate inputs (e.g., forcing strong passwords)
import hashlib    # (Or bcrypt) Used to scramble passwords so they aren't readable

def validate_username(username):
    return (
        isinstance(username, str)
        and 4 <= len(username) <= 15
        and username.isalnum()
    )

    def validate_password(password):
    return (
        isinstance(password, str)
        and len(password) >= 8
        and any(not char.isalnum() and not char.isspace() for char in password)
    )

    import hashlib
import hmac
import secrets

PBKDF2_ITERATIONS = 600_000
SALT_BYTES = 16


def hash_password(password):
    if not isinstance(password, str):
        raise TypeError("password must be a string")

    salt = secrets.token_bytes(SALT_BYTES)
    digest = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        PBKDF2_ITERATIONS,
    )
    return f"pbkdf2_sha256${PBKDF2_ITERATIONS}${salt.hex()}${digest.hex()}"


def verify_password(password, stored_hash):
    if not isinstance(password, str) or not isinstance(stored_hash, str):
        return False

    try:
        algorithm, iterations_text, salt_hex, digest_hex = stored_hash.split("$")
        iterations = int(iterations_text)
        salt = bytes.fromhex(salt_hex)
        expected_digest = bytes.fromhex(digest_hex)
    except ValueError:
        return False

    if (
        algorithm != "pbkdf2_sha256"
        or iterations != PBKDF2_ITERATIONS
        or len(salt) != SALT_BYTES
        or len(expected_digest) != hashlib.sha256().digest_size
    ):
        return False

    actual_digest = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        iterations,
    )
    return hmac.compare_digest(actual_digest, expected_digest)

    MAX_FAILED_LOGIN_ATTEMPTS = 3
_failed_login_attempts = {}
_locked_users = set()


def login_user(username, password, path=None):
    if not isinstance(username, str):
        logging.warning("Login failed: invalid username or password.")
        return False

    if username in _locked_users:
        logging.warning("Login rejected: account is locked.")
        return False

    users = load_users(path)
    stored_hash = users.get(username)

    if stored_hash is None:
        # Don't track unknown names; that could let arbitrary input grow
        # the in-memory tracking data without limit.
        logging.warning("Login failed: invalid username or password.")
        return False

    if verify_password(password, stored_hash):
        _failed_login_attempts.pop(username, None)
        return True

    attempts = _failed_login_attempts.get(username, 0) + 1
    _failed_login_attempts[username] = attempts
    logging.warning("Login failed: invalid username or password.")

    if attempts >= MAX_FAILED_LOGIN_ATTEMPTS:
        _locked_users.add(username)
        logging.warning("Account locked after %d failed login attempts.", attempts)

    return False

    def main():
    while True:
        print("\n1) Register\n2) Login\n3) Exit")
        choice = input("Choose an option: ").strip()

        if choice == "1":
            username = input("Username: ")
            password = getpass.getpass("Password: ")
            if register_user(username, password):
                print("Registration successful.")
            else:
                print("Registration failed. Check the username/password requirements or whether the username already exists.")
        elif choice == "2":
            username = input("Username: ")
            password = getpass.getpass("Password: ")
            if login_user(username, password):
                print("Login successful.")
            else:
                print("Login failed.")
        elif choice == "3":
            print("Goodbye.")
            break
        else:
            print("Invalid option. Please choose 1, 2, or 3.")
