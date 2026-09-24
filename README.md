# ꓘamerka Plus GUI for Android

Android-focused guide for running Kamerka Plus GUI on Android devices via Termux.

## Scope

This README is intentionally scoped to Android usage only.
For non-Android environments, use the detailed documentation under [`docs/`](docs/).

## Requirements (Android / Termux)

- Android device with [Termux](https://termux.dev/)
- Python 3
- Git
- Redis
- PostgreSQL (Termux package)
- Shodan API key

## Quick start (Termux)

```bash
pkg update && pkg upgrade
pkg install python git redis postgresql

git clone https://github.com/webmaster-exit-1/Kamerka_Plus_GUI.git
cd Kamerka_Plus_GUI

python -m pip install -r requirements.txt
```

This guide uses `python -m pip install -r requirements.txt` directly on Termux (a virtual environment is optional).

Initialize PostgreSQL in Termux:

```bash
mkdir -p $PREFIX/var/lib/postgresql
initdb $PREFIX/var/lib/postgresql
pg_ctl -D $PREFIX/var/lib/postgresql start
createuser --createdb kamerka
createdb -O kamerka kamerka
psql -d postgres -c "ALTER USER kamerka WITH PASSWORD 'CHANGE_ME';"
```

Set required environment variables:

```bash
export SHODAN_API_KEY=your_key_here
export DJANGO_SECRET_KEY=your_long_random_secret

export DB_NAME=kamerka
export DB_USER=kamerka
export DB_PASSWORD=CHANGE_ME
export DB_HOST=localhost
export DB_PORT=5432
export REDIS_URL=redis://127.0.0.1:6379/0
```

Save these variables into a local `.env` file so each Termux session can load the same runtime configuration:

```bash
cat > .env <<'EOF'
SHODAN_API_KEY=your_key_here
DJANGO_SECRET_KEY=your_long_random_secret
DB_NAME=kamerka
DB_USER=kamerka
DB_PASSWORD=CHANGE_ME
DB_HOST=localhost
DB_PORT=5432
REDIS_URL=redis://127.0.0.1:6379/0
EOF
```

If any value contains spaces, `#`, or shell-significant characters, wrap it in single quotes in `.env`.

Run the app:

```bash
cd Kamerka_Plus_GUI
pg_ctl -D $PREFIX/var/lib/postgresql start
set -a && . ./.env && set +a
python manage.py migrate
python manage.py create_default_superuser
```

In a second Termux session:

```bash
redis-server
```

In a third Termux session:

```bash
cd Kamerka_Plus_GUI
set -a && . ./.env && set +a
celery --app kamerka worker --beat --loglevel=info
```

In a fourth Termux session:

```bash
cd Kamerka_Plus_GUI
set -a && . ./.env && set +a
python manage.py runserver 127.0.0.1:8000
```

Open:

- `http://127.0.0.1:8000/`

## Android limitations

- Raw packet scan modes (for example Nmap `-sS`) require elevated capabilities not available in standard Termux setups.
- The application falls back to non-raw scan paths where supported, which are slower but work without root.

## Android documentation

Non-Android setup and broader project guidance now live in the main documentation set:

- [docs/INSTALL.md](docs/INSTALL.md) — full installation details for non-Android/advanced environments
- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) — service architecture and component behavior
- [docs/DATABASE.md](docs/DATABASE.md) — PostgreSQL requirements
- [docs/docker.md](docs/docker.md) — Docker-based setup
- [docs/WORLDMONITOR_INTEGRATION.md](docs/WORLDMONITOR_INTEGRATION.md) — feed/layer intelligence integration

## License

MIT License — see [LICENSE.md](LICENSE.md).
