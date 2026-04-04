# Installation Guide

## Requirements

- Python 3
- Django (3.2 – 4.x)
- Celery (5.2+)
- Redis (4.0+)
- Shodan paid account
- [Nmap](https://nmap.org/) (Required for NMAP scans and RTSP probes)
- Pastebin PRO (Optional — see [Pastebin API setup](#pastebin-api-setup) below)
- [NVD API key](https://nvd.nist.gov/developers/request-an-api-key) (Optional — raises NVD rate limit from 5 to 50 req/30 s)
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

# Optional – NVD vulnerability enrichment (request a key at
# https://nvd.nist.gov/developers/request-an-api-key):
# export NVD_API_KEY=your_nvd_api_key_here

# Optional – Pastebin field-agent sync (see "Pastebin API setup" section below
# and https://pastebin.com/doc_api for full details):
# export PASTEBIN_API_DEV_KEY=your_unique_developer_api_key
# export PASTEBIN_API_USER_NAME=your_pastebin_username
# export PASTEBIN_API_USER_PASSWORD=your_pastebin_password
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

### API Keys

| Variable | Required | Description |
|---|---|---|
| `SHODAN_API_KEY` | ✅ | Shodan paid-account API key |
| `NVD_API_KEY` | optional | NIST NVD API key — raises rate limit from 5 to 50 req/30 s ([request one here](https://nvd.nist.gov/developers/request-an-api-key)) |
| `PASTEBIN_API_DEV_KEY` | optional | Pastebin *Unique Developer API Key* — find it at <https://pastebin.com/doc_api#1> after signing up |
| `PASTEBIN_API_USER_NAME` | optional | Pastebin account username (for field-agent sync) |
| `PASTEBIN_API_USER_PASSWORD` | optional | Pastebin account password |
| `DJANGO_SECRET_KEY` | optional | Override the auto-generated Django secret key |

### External Tool Paths

These are only needed if the tools are not on your `$PATH`.  See [docs/ARCHITECTURE.md](ARCHITECTURE.md) for full details.

| Variable | Default | Description |
|---|---|---|
| `KAMERKA_NAABU_BIN` | `naabu` | Path to the [Naabu](https://github.com/projectdiscovery/naabu) binary |
| `KAMERKA_NUCLEI_BIN` | `nuclei` | Path to the [Nuclei](https://github.com/projectdiscovery/nuclei) binary |
| `KAMERKA_WAPPALYZER_BIN` | `wappalyzer` | Path to the [Wappalyzer](https://github.com/AliasIO/wappalyzer) binary |
| `KAMERKA_NAABU_PORTS` | `top-100` | Default port spec for Naabu liveness checks |
| `KAMERKA_NAABU_TIMEOUT` | `60` | Naabu subprocess timeout (seconds) |
| `KAMERKA_NAABU_DISCOVERY_PORTS` | `1-65535` | Port range for on-demand device port discovery |
| `KAMERKA_NAABU_DISCOVERY_TIMEOUT` | `120` | Timeout for full-range discovery scans (seconds) |
| `KAMERKA_NUCLEI_TIMEOUT` | `300` | Nuclei subprocess timeout (seconds) |
| `NMAP_MAX_RUNTIME` | `300` | Maximum seconds an Nmap scan may run before being killed |

> **Nmap** is resolved from `$PATH` automatically.  Raw-socket scan types
> (`-sS`, `-O`) require root / `CAP_NET_RAW`.  The Celery worker must be
> started as root so Nmap inherits the required permissions.

## GeoLite2 / GeoIP Databases

NMAP XML uploads and IP geolocation require MaxMind GeoLite2 `.mmdb` database files.
These files are **not** bundled in this repository.

### Option A — Download from MaxMind (official)

1. Register for a free MaxMind account at <https://www.maxmind.com/en/geolite2/signup>
2. After logging in, go to **Download Databases** → **GeoLite2 City** → **Download (mmdb)**
3. Extract the archive and place **`GeoLite2-City.mmdb`** in the project root (`Kamerka_Plus_GUI/`)

### Option B — Download from GitHub mirrors

The three GeoLite2 `.mmdb` files (City, Country, ASN) are also available on GitHub:

- <https://github.com/P3TERX/GeoLite.mmdb> (auto-updated mirror of all three databases)
- <https://github.com/GitSquared/node-geolite2-redist> (npm-oriented redistribution)

Download **GeoLite2-City.mmdb** and place it in the project root.
The other two files (GeoLite2-Country.mmdb, GeoLite2-ASN.mmdb) are not
currently used but may be useful for custom enrichment.

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

## Database — PostgreSQL (Recommended for Production)

The default database is SQLite, which works well for single-user setups.
For multi-worker Celery deployments or heavy concurrent usage, switch to **PostgreSQL**.
See [docs/DATABASE.md](DATABASE.md) for a detailed discussion of SQLite concurrency
limitations and the full migration guide.

### Quick PostgreSQL setup

1. Install PostgreSQL (or run via Docker):

```bash
# Docker (fastest)
docker run -d --name kamerka-pg \
  -e POSTGRES_DB=kamerka \
  -e POSTGRES_USER=kamerka \
  -e POSTGRES_PASSWORD=secret \
  -p 5432:5432 postgres:16

# Or install natively (Debian/Ubuntu)
sudo apt install postgresql postgresql-contrib
sudo -u postgres createuser --createdb kamerka
sudo -u postgres createdb -O kamerka kamerka
```

2. Install the Python PostgreSQL adapter:

```bash
pip3 install psycopg2-binary
```

3. Export the database environment variables before starting Django and Celery:

```bash
export DB_NAME=kamerka
export DB_USER=kamerka
export DB_PASSWORD=secret
export DB_HOST=localhost
export DB_PORT=5432
```

4. Update `kamerka/settings.py` `DATABASES` to use PostgreSQL (or see [DATABASE.md](DATABASE.md) for the snippet).

5. Run migrations:

```bash
python3 manage.py migrate
```

## Pastebin API Setup

The Pastebin integration lets you sync device notes with a Pastebin PRO account
(the "field-agent" feature).  The Pastebin API is documented at
<https://pastebin.com/doc_api>.

### 1. Get your Unique Developer API Key

Sign up or log in at <https://pastebin.com>, then visit
<https://pastebin.com/doc_api#1>.  Your **Unique Developer API Key** is displayed
on that page.  Export it as:

```bash
export PASTEBIN_API_DEV_KEY=your_unique_developer_api_key
```

### 2. Set your Pastebin credentials

```bash
export PASTEBIN_API_USER_NAME=your_pastebin_username
export PASTEBIN_API_USER_PASSWORD=your_pastebin_password
```

These are used at runtime to obtain a short-lived **`api_user_key`** via the
Pastebin login endpoint (`api_login.php`).  The user key is never stored on disk.

### 3. Verify (optional)

You can verify your credentials work by running the interactive setup helper:

```bash
python3 scripts/pastebin_setup.py
```

The helper walks you through obtaining and testing your API keys step by step.

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
