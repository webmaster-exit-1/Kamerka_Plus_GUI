# Installation Guide

## Requirements

- Python 3
- Django (3.2 – 4.x)
- Celery (5.2+)
- Redis (4.0+)
- Shodan paid account
- Pastebin PRO (Optional)
- [Wappalyzer CLI](https://github.com/AliasIO/wappalyzer) (Optional, for tech detection)
- [Nuclei](https://github.com/projectdiscovery/nuclei) (Optional, for vulnerability scanning)
- [Naabu](https://github.com/projectdiscovery/naabu) (Optional, for tiered liveness verification)
- **PyVista / PyQt6** (Optional, for the native 3D globe viewer — see below)

> **Note:** Google Maps API is no longer required. Maps are rendered with Leaflet.js and OpenStreetMap tiles.

## Environment Variables

**API keys are read from environment variables — never from a file committed to git.**

Export the required variables in your shell before starting the server:

```bash
export SHODAN_API_KEY=your_shodan_api_key_here
# optional:
# export PASTEBIN_USER=your_pastebin_username
# export PASTEBIN_PASSWORD=your_pastebin_password
# export PASTEBIN_DEV_KEY=your_pastebin_developer_key
```

**Making environment variables persistent (so you don't have to re-export in every new terminal)**

Add the exports to your shell profile so they are set automatically for every session:

```bash
# Append to ~/.bashrc  (bash) or ~/.zshrc (zsh)
echo 'export SHODAN_API_KEY=your_shodan_api_key_here' >> ~/.bashrc
source ~/.bashrc          # apply to the current shell immediately
```

For **systemd** service units, add an `Environment=` line in the `[Service]` section:

```ini
[Service]
Environment="SHODAN_API_KEY=your_shodan_api_key_here"
```

For **Docker**, pass the variable with `-e` or an `--env-file`:

```bash
docker run -e SHODAN_API_KEY=your_key ...
```

> **Important:** Django and the Celery worker are separate processes.  Both must
> be started with `SHODAN_API_KEY` set in their environment.  If you add the
> export to `~/.bashrc`, open a *new* terminal (or run `source ~/.bashrc`) before
> starting each process.

| Variable | Required | Description |
|---|---|---|
| `SHODAN_API_KEY` | ✅ | Shodan paid-account API key |
| `PASTEBIN_USER` | optional | Pastebin username (field-agent sync) |
| `PASTEBIN_PASSWORD` | optional | Pastebin password |
| `PASTEBIN_DEV_KEY` | optional | Pastebin developer key |
| `DJANGO_SECRET_KEY` | optional | Override the auto-generated Django secret key |

## GeoLite2 Database (Required for NMAP scan)

NMAP XML uploads require MaxMind's GeoLite2 City database for IP geolocation.
The `.mmdb` file is not bundled in this repository — download it for free:

1. Register for a free MaxMind account at https://www.maxmind.com/en/geolite2/signup
2. After logging in, go to **Download Databases** → **GeoLite2 City** → **Download (mmdb)**
3. Extract the archive and place **`GeoLite2-City.mmdb`** in the project root (`Kamerka_Plus_GUI/`)

## Default Superuser

A default superuser is created automatically when you run the `create_default_superuser` management command.

| Setting | Default value |
|---------|---------------|
| Username | `admin` |
| Email | `admin@example.com` |
| Password | Randomly generated (20 characters) |

**The generated password is not printed to the console by default** (to prevent credential leakage in logs).

To display the generated password during creation:
```bash
DJANGO_SUPERUSER_PRINT_PASSWORD=true python3 manage.py create_default_superuser
```

To set your own password instead of using a generated one:
```bash
DJANGO_SUPERUSER_PASSWORD=your_password python3 manage.py create_default_superuser
```

**To change the admin password after creation**, run:
```bash
python3 manage.py changepassword admin
```

Or log in to the Django admin panel at `http://localhost:8000/admin/` and change it there.

## Run

```bash
git clone https://github.com/webmaster-exit-1/Kamerka_Plus_GUI.git
cd Kamerka_Plus_GUI
pip3 install -r requirements.txt
python3 manage.py makemigrations
python3 manage.py migrate
python3 manage.py create_default_superuser
python3 manage.py runserver
```

In a new window (in the main directory) run the Celery worker:

```bash
celery --app kamerka worker --loglevel=info
```

In a new window start Redis:

```bash
pacman -S redis
redis-server
```

The server should be available at `http://localhost:8000/`

## Running Tests

```bash
python3 manage.py test app_kamerka -v2
```

<details>
<summary>Running on Android (Termux, no root)</summary>

Kamerka Plus GUI runs fully on Android via Termux without root privileges.
Tested on OnePlus CPH2583 (Android 14, Snapdragon 8 Gen 3).

### Install dependencies

```
pkg update && pkg upgrade
pkg install python redis git
pip install -r requirements.txt
```

### Export environment variables

```
export SHODAN_API_KEY=your_key_here
export DJANGO_SECRET_KEY=your_secret_key_here
```

### Run

```
redis-server --daemonize yes
python manage.py migrate
python manage.py create_default_superuser
python manage.py runserver &
celery --app kamerka worker --loglevel=info
```

Access at `http://127.0.0.1:8000` in your mobile browser.

### Limitations without root

Naabu SYN scans and Nmap raw-packet probes require `CAP_NET_RAW` (root).
Without root, port discovery falls back to TCP connect-scan mode, which
works but is slower and less stealthy. Nuclei HTTP-based templates work
fully without root.

</details>
