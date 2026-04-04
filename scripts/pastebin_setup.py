#!/usr/bin/env python3
"""Interactive Pastebin API setup helper.

Walks the user through obtaining and verifying the three Pastebin
environment variables required by the field-agent feature:

    PASTEBIN_API_DEV_KEY        – Unique Developer API Key
    PASTEBIN_API_USER_NAME      – Pastebin account username
    PASTEBIN_API_USER_PASSWORD  – Pastebin account password

At the end, the script optionally appends the exports to ``~/.bashrc``
so they persist across terminal sessions.

Reference: https://pastebin.com/doc_api
"""

import os
import shlex
import sys
import textwrap

try:
    import requests
except ImportError:
    sys.exit(
        "The 'requests' library is required.  Install it with:\n"
        "  pip install requests"
    )


PASTEBIN_LOGIN_URL = "https://pastebin.com/api/api_login.php"


def _prompt(label, *, secret=False):
    """Prompt the user for a value, stripping whitespace."""
    if secret:
        try:
            import getpass
            value = getpass.getpass(f"{label}: ")
        except Exception:
            value = input(f"{label}: ")
    else:
        value = input(f"{label}: ")
    return value.strip()


def _test_login(dev_key, username, password):
    """Attempt a Pastebin API login and return the user key or an error."""
    payload = {
        "api_dev_key": dev_key,
        "api_user_name": username,
        "api_user_password": password,
    }
    try:
        resp = requests.post(PASTEBIN_LOGIN_URL, data=payload, timeout=15)
    except requests.RequestException as exc:
        return None, f"Network error: {exc}"

    text = resp.text.strip()
    if resp.status_code == 200 and not text.startswith("Bad API request"):
        return text, None
    return None, text


def main():
    print(textwrap.dedent("""\
        ╔══════════════════════════════════════════════════╗
        ║       Pastebin API Setup Helper for Kamerka      ║
        ╚══════════════════════════════════════════════════╝

        This helper walks you through configuring the Pastebin API
        environment variables needed for the field-agent sync feature.

        You will need a Pastebin account (PRO is recommended for
        private pastes).  Full API documentation is at:

            https://pastebin.com/doc_api
    """))

    # Step 1 — Developer API Key
    print("─── Step 1: Unique Developer API Key ───")
    print(
        "Log in at https://pastebin.com, then visit:\n"
        "  https://pastebin.com/doc_api#1\n"
        "Your Unique Developer API Key is displayed on that page.\n"
    )
    dev_key = _prompt("Paste your Developer API Key here")
    if not dev_key:
        sys.exit("No key entered.  Aborting.")

    # Step 2 — Username & password
    print("\n─── Step 2: Pastebin Account Credentials ───")
    print("Enter the username and password for your Pastebin account.\n")
    username = _prompt("Pastebin username")
    password = _prompt("Pastebin password", secret=True)
    if not username or not password:
        sys.exit("Username and password are required.  Aborting.")

    # Step 3 — Test
    print("\n─── Step 3: Verifying credentials ───")
    user_key, error = _test_login(dev_key, username, password)
    if error:
        print(f"\n✗ Login failed: {error}")
        print(
            "  Double-check your Developer API Key, username, and password,\n"
            "  then re-run this script."
        )
        sys.exit(1)

    print("✓ Login successful!  Credentials verified.")

    # Step 4 — Export snippet
    print("\n─── Step 4: Environment Variables ───")

    # Reject values containing newlines to prevent shell injection.
    for label, val in [("Developer API Key", dev_key), ("Username", username)]:
        if "\n" in val or "\r" in val:
            sys.exit(f"✗ {label} contains newline characters — aborting for safety.")

    snippet = (
        f"export PASTEBIN_API_DEV_KEY={shlex.quote(dev_key)}\n"
        f"export PASTEBIN_API_USER_NAME={shlex.quote(username)}\n"
        'export PASTEBIN_API_USER_PASSWORD="<your_password_here>"\n'
    )
    print("Add the following to your shell profile (e.g. ~/.bashrc):\n")
    print(snippet)
    print(
        "⚠  Replace <your_password_here> with your actual password.\n"
        "   Storing passwords in plaintext shell profiles is convenient but\n"
        "   carries risk.  Consider using a secrets manager or encrypted\n"
        "   credential store for production deployments.\n"
    )

    answer = input("Append API key and username (without password) to ~/.bashrc? [y/n] ").strip().lower()
    if answer == "y":
        home = os.path.expanduser("~")
        bashrc = os.path.join(home, ".bashrc")
        real_bashrc = os.path.realpath(bashrc)
        real_home = os.path.realpath(home)
        if not real_bashrc.startswith(real_home + os.sep):
            print(f"✗ Resolved path {real_bashrc} is outside your home directory.  Skipping.")
        else:
            safe_snippet = (
                f"export PASTEBIN_API_DEV_KEY={shlex.quote(dev_key)}\n"
                f"export PASTEBIN_API_USER_NAME={shlex.quote(username)}\n"
                "# export PASTEBIN_API_USER_PASSWORD=  # set this manually — avoid storing passwords in plaintext\n"
            )
            with open(real_bashrc, "a", encoding="utf-8") as fh:
                fh.write("\n# Pastebin API keys for Kamerka field-agent sync\n")
                fh.write(safe_snippet)
            print(f"✓ Appended to {real_bashrc}.  Run 'source ~/.bashrc' to apply.")
            print("  Remember to set PASTEBIN_API_USER_PASSWORD manually before using the field-agent feature.")
    else:
        print("Skipped.  Copy the exports above and add them manually.")

    print("\nDone!  Restart the Django server and Celery worker to pick up the new variables.")


if __name__ == "__main__":
    main()
