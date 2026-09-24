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
export KAMERKA_HOME="$(pwd)"
```

This guide uses `python -m pip install -r requirements.txt` on Termux. Recommended: create and activate a virtual environment first (`python -m venv .venv && . .venv/bin/activate`) to avoid cross-project package conflicts.

Initialize PostgreSQL in Termux:

```bash
mkdir -p $PREFIX/var/lib/postgresql
initdb $PREFIX/var/lib/postgresql
pg_ctl -D $PREFIX/var/lib/postgresql start
until pg_isready -h localhost -p 5432 >/dev/null 2>&1; do sleep 1; done
createuser --login --createdb kamerka
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

Save these variables into a reusable shell env file so each session can load the same runtime configuration:

```bash
cat > kamerka_env.sh <<'EOF'
export SHODAN_API_KEY='your_key_here'
export DJANGO_SECRET_KEY='your_long_random_secret'
export KAMERKA_HOME="$HOME/Kamerka_Plus_GUI"
export DB_NAME='kamerka'
export DB_USER='kamerka'
export DB_PASSWORD='CHANGE_ME'
export DB_HOST='localhost'
export DB_PORT='5432'
export REDIS_URL='redis://127.0.0.1:6379/0'
EOF
```

Keep values single-quoted in `kamerka_env.sh` (especially secrets containing `#`, spaces, or shell-significant characters).
If your repository is not in the default location, update `KAMERKA_HOME` to your checkout path before running session commands.

Run the app:

The next commands explicitly invoke `bash` so they work even if your interactive shell is different.

In a first Termux session:

```bash
redis-server
```

In a second Termux session:

```bash
bash -lc '
cd "$KAMERKA_HOME"
pg_ctl -D $PREFIX/var/lib/postgresql status || pg_ctl -D $PREFIX/var/lib/postgresql start
. ./kamerka_env.sh
python manage.py migrate
python manage.py createsuperuser
python manage.py runserver 127.0.0.1:8000
'
```

In a third Termux session:

```bash
bash -lc '
cd "$KAMERKA_HOME"
. ./kamerka_env.sh
celery --app kamerka worker --beat --loglevel=info
'
```

Open:

- `http://127.0.0.1:8000/`

## Build Android APK client

This repository now includes a native Android Gradle project under [`android/`](android/).
The APK is a WebView client for the same Kamerka Plus GUI interface.

Build locally:

```bash
cd android
./gradlew assembleDebug
```

Debug APK output:

- `android/app/build/outputs/apk/debug/app-debug.apk`

CI artifact:

- Workflow: `.github/workflows/android-apk.yml`
- Artifact name: `kamerka-plus-gui-debug-apk`

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
