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

pip install -r requirements.txt
```

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
```

Run the app:

```bash
python manage.py migrate
python manage.py create_default_superuser
python manage.py runserver 127.0.0.1:8000
```

In a second Termux session:

```bash
redis-server
```

In a third Termux session:

```bash
cd Kamerka_Plus_GUI
celery --app kamerka worker --beat --loglevel=info
```

Open:

- `http://127.0.0.1:8000/`

## Android limitations

- Raw packet scan modes (for example Nmap `-sS`) require elevated capabilities not available in standard Termux setups.
- The application falls back to non-raw scan paths where supported, which are slower but work without root.

## Android documentation

- [docs/INSTALL.md](docs/INSTALL.md) — full installation details including Android/Termux notes
- [docs/DATABASE.md](docs/DATABASE.md) — PostgreSQL requirements

## License

MIT License — see [LICENSE.md](LICENSE.md).
