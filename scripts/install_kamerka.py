#!/usr/bin/env python3
"""
Interactive Kamerka Plus GUI installer.

Walks new operators through:
  - Python environment and dependencies
  - Secure .env configuration (API keys, Redis, Django secret)
  - Database migrations and optional seed data
  - Admin superuser creation (strong passwords, best practices)
  - Optional integrations (HexStrike, Ollama)
  - Post-install run instructions

Usage:
  ./scripts/install_kamerka.py
  ./scripts/install_kamerka.py --yes          # non-interactive defaults
  ./scripts/install_kamerka.py --venv       # create .venv and use it

Never commit .env or print API keys to shared logs.
"""

from __future__ import annotations

import argparse
import os
import re
import secrets
import shutil
import string
import subprocess
import sys
import textwrap
from pathlib import Path
from typing import Dict, List, Optional, Tuple

try:
    import getpass
except ImportError:
    getpass = None  # type: ignore

PROJECT_ROOT = Path(__file__).resolve().parent.parent
ENV_EXAMPLE = PROJECT_ROOT / ".env.example"
ENV_FILE = PROJECT_ROOT / ".env"
REQUIREMENTS = PROJECT_ROOT / "requirements.txt"
GEOLITE_CITY = PROJECT_ROOT / "GeoLite2-City.mmdb"

MANAGED_ENV_KEYS = (
    "DJANGO_SECRET_KEY",
    "DEBUG",
    "ALLOWED_HOSTS",
    "SHODAN_API_KEY",
    "NVD_API_KEY",
    "REDIS_URL",
    "HEXSTRIKE_SERVER_URL",
    "OLLAMA_HOST",
    "OLLAMA_MODEL",
    "DB_NAME",
    "DB_USER",
    "DB_PASSWORD",
    "DB_HOST",
    "DB_PORT",
)


def _banner(title: str) -> None:
    line = "═" * max(len(title) + 4, 52)
    print(f"\n╔{line}╗")
    print(f"║  {title}")
    print(f"╚{line}╝\n")


def _step(num: int, total: int, title: str) -> None:
    print(f"\n── Step {num}/{total}: {title} " + "─" * max(0, 40 - len(title)))


def _prompt(label: str, default: str = "", *, secret: bool = False) -> str:
    hint = f" [{default}]" if default else ""
    if secret and getpass:
        raw = getpass.getpass(f"{label}{hint}: ")
    else:
        raw = input(f"{label}{hint}: ")
    raw = raw.strip()
    return raw if raw else default


def _yes_no(question: str, default: bool = True) -> bool:
    suffix = "Y/n" if default else "y/N"
    answer = input(f"{question} [{suffix}] ").strip().lower()
    if not answer:
        return default
    return answer in ("y", "yes")


def _safe_env_value(value: str, field: str) -> str:
    if "\n" in value or "\r" in value:
        raise ValueError(f"{field} must not contain newlines")
    if value != value.strip():
        raise ValueError(f"{field} must not have leading/trailing whitespace")
    return value


def generate_django_secret_key() -> str:
    try:
        from django.core.management.utils import get_random_secret_key

        return get_random_secret_key()
    except Exception:
        alphabet = string.ascii_letters + string.digits + "!@#$%^&*(-_=+)"
        return "".join(secrets.choice(alphabet) for _ in range(50))


def generate_password(length: int = 20) -> str:
    alphabet = string.ascii_letters + string.digits
    parts = [
        secrets.choice(string.ascii_lowercase),
        secrets.choice(string.ascii_uppercase),
        secrets.choice(string.digits),
    ]
    parts += [secrets.choice(alphabet) for _ in range(length - len(parts))]
    rng = secrets.SystemRandom()
    for i in range(len(parts) - 1, 0, -1):
        j = rng.randint(0, i)
        parts[i], parts[j] = parts[j], parts[i]
    return "".join(parts)


def password_strength_issues(password: str) -> List[str]:
    issues = []
    if len(password) < 12:
        issues.append("Use at least 12 characters.")
    if not re.search(r"[a-z]", password):
        issues.append("Add a lowercase letter.")
    if not re.search(r"[A-Z]", password):
        issues.append("Add an uppercase letter.")
    if not re.search(r"\d", password):
        issues.append("Add a digit.")
    if password.lower() in ("admin", "password", "kamerka", "changeme", "123456789012"):
        issues.append("Avoid common or default passwords.")
    return issues


def read_env_file(path: Path) -> Dict[str, str]:
    if not path.is_file():
        return {}
    out: Dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, _, val = stripped.partition("=")
        out[key.strip()] = val.strip()
    return out


def write_env_file(path: Path, values: Dict[str, str]) -> None:
    existing_lines: List[str] = []
    if path.is_file():
        existing_lines = path.read_text(encoding="utf-8").splitlines()

    known = set(values.keys())
    kept: List[str] = []
    seen = set()

    for line in existing_lines:
        stripped = line.strip()
        if stripped and not stripped.startswith("#") and "=" in stripped:
            key = stripped.split("=", 1)[0].strip()
            if key in known:
                if key not in seen:
                    kept.append(f"{key}={values[key]}")
                    seen.add(key)
                continue
        kept.append(line)

    for key in MANAGED_ENV_KEYS:
        if key in values and key not in seen:
            kept.append(f"{key}={values[key]}")
            seen.add(key)

    for key, val in values.items():
        if key not in seen:
            kept.append(f"{key}={val}")

    body = "\n".join(kept).rstrip() + "\n"
    path.write_text(body, encoding="utf-8")
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def choose_python(use_venv: bool) -> Path:
    venv_py = PROJECT_ROOT / ".venv" / "bin" / "python"
    if use_venv and venv_py.is_file():
        return venv_py
    return Path(sys.executable)


def run_cmd(
    args: List[str],
    *,
    python: Path,
    env: Optional[Dict[str, str]] = None,
    cwd: Path = PROJECT_ROOT,
) -> subprocess.CompletedProcess:
    full_env = os.environ.copy()
    if env:
        full_env.update(env)
    dotenv = read_env_file(ENV_FILE)
    for key, val in dotenv.items():
        if val and not val.startswith("your_") and val != "change-me-in-production":
            full_env.setdefault(key, val)
    return subprocess.run(
        [str(python)] + args,
        cwd=str(cwd),
        env=full_env,
        text=True,
        capture_output=True,
    )


def check_redis(url: str) -> Tuple[bool, str]:
    try:
        import redis

        client = redis.from_url(url, socket_connect_timeout=2)
        client.ping()
        return True, "Redis responded to PING"
    except Exception as exc:
        return False, str(exc)


def check_shodan_key(api_key: str) -> Tuple[bool, str]:
    if not api_key or api_key.startswith("your_"):
        return False, "No key configured"
    try:
        import shodan

        api = shodan.Shodan(api_key)
        info = api.info()
        credits = info.get("query_credits", "?")
        return True, f"Shodan API OK (query credits: {credits})"
    except Exception as exc:
        return False, str(exc)


def check_hexstrike(url: str) -> Tuple[bool, str]:
    try:
        import requests

        resp = requests.get(f"{url.rstrip('/')}/health", timeout=3)
        if resp.status_code == 200:
            data = resp.json()
            return True, f"HexStrike v{data.get('version', '?')} online"
        return False, f"HTTP {resp.status_code}"
    except Exception as exc:
        return False, str(exc)


def collect_api_keys(interactive: bool, env: Dict[str, str]) -> Dict[str, str]:
    print(
        textwrap.dedent(
            """
            API key best practices:
              • Never commit keys to git — use .env only (chmod 600).
              • Use separate keys per environment (lab vs production).
              • Rotate keys if they appear in logs or chat.
              • Shodan is required for searches; NVD is optional but recommended.
            """
        ).strip()
    )

    shodan = env.get("SHODAN_API_KEY", "")
    if interactive:
        print("\nShodan: https://account.shodan.io/ (paid plan required for searches)")
        shodan = _prompt("SHODAN_API_KEY", shodan, secret=True) or shodan
        if shodan and _yes_no("Verify Shodan key now?", default=True):
            ok, msg = check_shodan_key(shodan)
            print(f"  {'✓' if ok else '✗'} {msg}")
            if not ok and not _yes_no("Continue anyway?", default=False):
                shodan = _prompt("SHODAN_API_KEY (re-enter)", secret=True)

        if _yes_no("Configure NVD_API_KEY (optional, higher rate limits)?", default=False):
            nvd = _prompt("NVD_API_KEY", env.get("NVD_API_KEY", ""), secret=True)
            if nvd:
                env["NVD_API_KEY"] = _safe_env_value(nvd, "NVD_API_KEY")
    else:
        shodan = os.environ.get("SHODAN_API_KEY", shodan)

    if shodan:
        env["SHODAN_API_KEY"] = _safe_env_value(shodan, "SHODAN_API_KEY")

    return env


def collect_admin(interactive: bool, python: Path) -> None:
    print(
        textwrap.dedent(
            """
            Admin account best practices:
              • Do not use password 'admin' or leave the default from docs.
              • Prefer a unique username in production (not 'admin').
              • Store the password in a password manager — not in shell history.
              • Django admin: /admin/ — restrict network access in production.
            """
        ).strip()
    )

    result = run_cmd(
        [
            "manage.py",
            "shell",
            "-c",
            "from django.contrib.auth import get_user_model; "
            "print(get_user_model().objects.filter(is_superuser=True).exists())",
        ],
        python=python,
    )
    if result.returncode == 0 and result.stdout.strip() == "True":
        print("✓ A superuser already exists — skipping creation.")
        if interactive and _yes_no("Reset admin password via changepassword?", default=False):
            username = _prompt("Username to reset", "admin")
            subprocess.run(
                [str(python), "manage.py", "changepassword", username],
                cwd=PROJECT_ROOT,
            )
        return

    username = os.environ.get("DJANGO_SUPERUSER_USERNAME", "admin")
    email = os.environ.get("DJANGO_SUPERUSER_EMAIL", "admin@example.com")
    password = os.environ.get("DJANGO_SUPERUSER_PASSWORD", "")

    if interactive:
        username = _prompt("Admin username", username)
        email = _prompt("Admin email", email)
        if _yes_no("Generate a strong random password?", default=True):
            password = generate_password(20)
            print("✓ Generated a 20-character password (shown once below).")
            print(f"\n  ┌{'─' * 38}┐")
            print(f"  │  {password}")
            print(f"  └{'─' * 38}┘\n")
            print("  Save this in a password manager now. It will not be shown again.\n")
        else:
            while True:
                password = _prompt("Admin password", secret=True)
                confirm = _prompt("Confirm password", secret=True)
                if password != confirm:
                    print("✗ Passwords do not match.")
                    continue
                issues = password_strength_issues(password)
                if issues:
                    print("✗ Password policy:")
                    for issue in issues:
                        print(f"    • {issue}")
                    if not _yes_no("Use this password anyway?", default=False):
                        continue
                break
    elif not password:
        password = generate_password(20)
        print("✓ Non-interactive mode: generated admin password.")
        print(f"  Password: {password}\n")

    if not password:
        sys.exit("No admin password configured.")

    proc = run_cmd(
        ["manage.py", "create_default_superuser"],
        python=python,
        env={
            "DJANGO_SUPERUSER_USERNAME": username,
            "DJANGO_SUPERUSER_EMAIL": email,
            "DJANGO_SUPERUSER_PASSWORD": password,
        },
    )
    if proc.returncode != 0:
        print(proc.stderr or proc.stdout)
        sys.exit("Failed to create superuser.")
    print(proc.stdout)


def setup_venv() -> None:
    venv_python = PROJECT_ROOT / ".venv" / "bin" / "python"
    if venv_python.is_file():
        print("✓ Virtual environment already exists at .venv/")
        return
    subprocess.run([sys.executable, "-m", "venv", str(PROJECT_ROOT / ".venv")], check=True)
    print("✓ Created .venv")


def install_requirements(python: Path) -> None:
    if not REQUIREMENTS.is_file():
        sys.exit(f"Missing {REQUIREMENTS}")
    print("Installing Python dependencies (may take a few minutes)…")
    proc = subprocess.run(
        [str(python), "-m", "pip", "install", "-r", str(REQUIREMENTS)],
        cwd=PROJECT_ROOT,
    )
    if proc.returncode != 0:
        sys.exit("pip install failed.")


def main() -> None:
    parser = argparse.ArgumentParser(description="Kamerka Plus GUI interactive installer")
    parser.add_argument("--yes", "-y", action="store_true", help="Non-interactive; use env vars and defaults")
    parser.add_argument("--venv", action="store_true", help="Create and use .venv")
    parser.add_argument("--no-seed", action="store_true", help="Skip seed_layers and import_feeds_opml")
    args = parser.parse_args()
    interactive = not args.yes

    _banner("ꓘamerka Plus GUI — Installation Wizard")
    print(
        "This wizard configures a local ICS/IoT OSINT lab instance.\n"
        "Use only on systems and targets you are authorized to assess."
    )

    if not (PROJECT_ROOT / "manage.py").is_file():
        sys.exit(f"Expected manage.py in {PROJECT_ROOT}")

    total_steps = 8
    use_venv = args.venv or (PROJECT_ROOT / ".venv").exists()

    _step(1, total_steps, "Python environment")
    if args.venv or (interactive and _yes_no("Create .venv virtual environment?", default=True)):
        setup_venv()
        use_venv = True
    python = choose_python(use_venv)

    _step(2, total_steps, "Dependencies")
    if interactive and not _yes_no("Install requirements.txt now?", default=True):
        print("Skipped pip install.")
    else:
        install_requirements(python)

    _step(3, total_steps, "Environment file (.env)")
    env = read_env_file(ENV_FILE)
    if not ENV_FILE.is_file() and ENV_EXAMPLE.is_file():
        shutil.copy(ENV_EXAMPLE, ENV_FILE)
        env = read_env_file(ENV_FILE)
        print(f"✓ Created {ENV_FILE} from .env.example")

    if not env.get("DJANGO_SECRET_KEY") or env.get("DJANGO_SECRET_KEY") == "change-me-in-production":
        env["DJANGO_SECRET_KEY"] = generate_django_secret_key()
        print("✓ Generated DJANGO_SECRET_KEY")

    if interactive:
        env["DEBUG"] = "True" if _yes_no("Enable DEBUG for local development?", default=True) else "False"
        hosts = _prompt("ALLOWED_HOSTS (comma-separated)", env.get("ALLOWED_HOSTS", "localhost,127.0.0.1"))
        env["ALLOWED_HOSTS"] = _safe_env_value(hosts, "ALLOWED_HOSTS")
        redis = _prompt("REDIS_URL", env.get("REDIS_URL", "redis://localhost:6379"))
        env["REDIS_URL"] = _safe_env_value(redis, "REDIS_URL")
        print("\nPostgreSQL connection:")
        env["DB_NAME"] = _safe_env_value(
            _prompt("DB_NAME", env.get("DB_NAME", "kamerka")), "DB_NAME"
        )
        env["DB_USER"] = _safe_env_value(
            _prompt("DB_USER", env.get("DB_USER", "kamerka")), "DB_USER"
        )
        env["DB_PASSWORD"] = _safe_env_value(
            _prompt("DB_PASSWORD", env.get("DB_PASSWORD", ""), secret=True), "DB_PASSWORD"
        )
        env["DB_HOST"] = _safe_env_value(
            _prompt("DB_HOST", env.get("DB_HOST", "localhost")), "DB_HOST"
        )
        env["DB_PORT"] = _safe_env_value(
            _prompt("DB_PORT", env.get("DB_PORT", "5432")), "DB_PORT"
        )
    else:
        env.setdefault("DEBUG", "False")
        env.setdefault("ALLOWED_HOSTS", "localhost,127.0.0.1")
        env.setdefault("REDIS_URL", "redis://localhost:6379")
        env.setdefault("DB_NAME", "kamerka")
        env.setdefault("DB_USER", "kamerka")
        env.setdefault("DB_PASSWORD", "")
        env.setdefault("DB_HOST", "localhost")
        env.setdefault("DB_PORT", "5432")

    env = collect_api_keys(interactive, env)

    if interactive and _yes_no("Configure HexStrike server URL (HexSploit C2 page)?", default=False):
        hs = _prompt("HEXSTRIKE_SERVER_URL", env.get("HEXSTRIKE_SERVER_URL", "http://127.0.0.1:8888"))
        env["HEXSTRIKE_SERVER_URL"] = _safe_env_value(hs, "HEXSTRIKE_SERVER_URL")
        ok, msg = check_hexstrike(env["HEXSTRIKE_SERVER_URL"])
        print(f"  {'✓' if ok else '○'} HexStrike: {msg}")

    write_env_file(ENV_FILE, env)
    print(f"✓ Wrote {ENV_FILE} (mode 600). Do not commit this file.")

    _step(4, total_steps, "Infrastructure checks")
    redis_ok, redis_msg = check_redis(env.get("REDIS_URL", "redis://localhost:6379"))
    print(f"  {'✓' if redis_ok else '○'} Redis: {redis_msg}")
    if not redis_ok:
        print("    Start Redis: redis-server   (or: sudo systemctl start redis)")

    if env.get("SHODAN_API_KEY"):
        ok, msg = check_shodan_key(env["SHODAN_API_KEY"])
        print(f"  {'✓' if ok else '○'} Shodan: {msg}")

    for binary in ("nmap", "nuclei", "naabu", "wappalyzer"):
        path = shutil.which(binary)
        print(f"  {'✓' if path else '○'} {binary}: {path or 'not in PATH'}")

    if not GEOLITE_CITY.is_file():
        print("  ○ GeoLite2-City.mmdb: missing (see docs/INSTALL.md)")

    _step(5, total_steps, "Database migrations")
    proc = run_cmd(["manage.py", "migrate", "--noinput"], python=python)
    if proc.returncode != 0:
        print(proc.stderr or proc.stdout)
        sys.exit("migrate failed.")
    print("✓ Migrations applied.")

    _step(6, total_steps, "Admin superuser")
    collect_admin(interactive, python)

    if not args.no_seed:
        _step(7, total_steps, "Seed data (layers & intel feeds)")
        if not interactive or _yes_no("Run seed_layers and import_feeds_opml?", default=True):
            for cmd in (["manage.py", "seed_layers"], ["manage.py", "import_feeds_opml"]):
                proc = run_cmd(cmd, python=python)
                if proc.returncode != 0:
                    print(f"○ {' '.join(cmd[1:])} failed (optional): {proc.stderr or proc.stdout}")
                else:
                    print(f"✓ {' '.join(cmd[1:])} completed.")
        else:
            print("Skipped seed commands.")

    _step(8, total_steps, "Next steps")
    print(
        textwrap.dedent(
            f"""
            Installation complete. Start services in separate terminals (from {PROJECT_ROOT}):

              set -a && source .env && set +a
              {python} manage.py runserver
              celery --app kamerka worker --beat --loglevel=info

            Optional HexStrike: cd ~/hexstrike-ai && python3 hexstrike_server.py

            • App:      http://127.0.0.1:8000/
            • Setup:    http://127.0.0.1:8000/healthz/setup/
            • HexSploit: http://127.0.0.1:8000/hexsploit/
            • Admin:    http://127.0.0.1:8000/admin/

            """
        ).strip()
    )


if __name__ == "__main__":
    main()