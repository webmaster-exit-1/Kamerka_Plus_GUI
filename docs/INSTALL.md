# Installation Guide

## Requirements

- Python 3
- Django (4.2+)
- Celery (5.2+)
- Redis (4.0+)
- Shodan paid account
- [Nmap](https://nmap.org/) (Required for NMAP scans and RTSP probes)
- [NVD API key](https://nvd.nist.gov/developers/request-an-api-key) (Optional — raises NVD rate limit from 5 to 50 req/30 s)
- [Wappalyzer CLI](https://github.com/AliasIO/wappalyzer) (Optional, for tech detection — see [Wappalyzer install](#wappalyzer-cli-install) below)
- [Nuclei](https://github.com/projectdiscovery/nuclei) (Optional, for vulnerability scanning)
- [Naabu](https://github.com/projectdiscovery/naabu) (Optional, for tiered liveness verification)
- **PyVista / PyQt6** (Optional, for the native 3D globe viewer — see below)

> **Note:** Google Maps API is no longer required. Maps are rendered with Leaflet.js and OpenStreetMap tiles.

## Interactive installer (recommended for new setups)

From the project root, run the guided wizard. It creates or updates `.env` (file mode `600`), generates a `DJANGO_SECRET_KEY`, walks through API keys with verification hints, creates a Django superuser with password best practices, runs migrations, and optionally seeds map layers and bundled intel feeds.

```bash
chmod +x scripts/install_kamerka.py   # once
./scripts/install_kamerka.py
```

| Flag | Purpose |
| ------ | --------- |
| `--venv` | Create `.venv` and install dependencies into it |
| `--yes` | Non-interactive (CI/lab automation): uses `SHODAN_API_KEY`, `DJANGO_SUPERUSER_*` from the environment |
| `--no-seed` | Skip `seed_layers` and `import_feeds_opml` |

**API keys:** enter Shodan (required for searches) when prompted; optional NVD key for higher CVE rate limits. Keys are stored only in `.env` — never commit that file. Use separate keys per environment and rotate if a key is pasted into chat or logs.

**Admin account:** the wizard can generate a 20-character password (shown once) or accept your own (minimum 12 characters with mixed case and digits). Avoid the default `admin` / `admin` pair in production. For automation, set `DJANGO_SUPERUSER_USERNAME`, `DJANGO_SUPERUSER_EMAIL`, and `DJANGO_SUPERUSER_PASSWORD` before `--yes`.

**After the wizard:** start Redis, then `source .env`, `manage.py runserver`, and `celery --app kamerka worker --beat`. Optional: HexStrike for the HexSploit page (`HEXSTRIKE_SERVER_URL` in `.env`).

## Environment Variables

**API keys are read from environment variables — never from a file committed to git.**

Export the required variables in your shell before starting the server:

```bash
export SHODAN_API_KEY=your_shodan_api_key_here

# Optional – NVD vulnerability enrichment (request a key at
# https://nvd.nist.gov/developers/request-an-api-key):
# export NVD_API_KEY=your_nvd_api_key_here

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
| --- |---|---|
| `SHODAN_API_KEY` | ✅ | Shodan paid-account API key |
| `NVD_API_KEY` | optional | NIST NVD API key — raises rate limit from 5 to 50 req/30 s ([request one here](https://nvd.nist.gov/developers/request-an-api-key)) |
| `DJANGO_SECRET_KEY` | optional | Override the auto-generated Django secret key |

### External Tool Paths

These are only needed if the tools are not on your `$PATH`.  See [docs/ARCHITECTURE.md](ARCHITECTURE.md) for full details.

| Variable | Default | Description |
| --- | --- | --- |
| `KAMERKA_NAABU_BIN` | `naabu` | Path to the [Naabu](https://github.com/projectdiscovery/naabu) binary |
| `KAMERKA_NUCLEI_BIN` | `nuclei` | Path to the [Nuclei](https://github.com/projectdiscovery/nuclei) binary |
| `KAMERKA_WAPPALYZER_BIN` | `wappalyzer` | Path to the [Wappalyzer](https://github.com/AliasIO/wappalyzer) binary |
| `KAMERKA_NAABU_PORTS` | `top-100` | Default port spec for Naabu liveness checks |
| `KAMERKA_NAABU_TIMEOUT` | `60` | Naabu subprocess timeout (seconds) |
| `KAMERKA_NAABU_DISCOVERY_PORTS` | `1-65535` | Port range for on-demand device port discovery |
| `KAMERKA_NAABU_DISCOVERY_TIMEOUT` | `120` | Timeout for full-range discovery scans (seconds) |
| `KAMERKA_NUCLEI_TIMEOUT` | `300` | Nuclei subprocess timeout (seconds) |
| `NMAP_MAX_RUNTIME` | `300` | Maximum seconds an Nmap scan may run before being killed |

> **Nmap** is resolved from `$PATH` automatically. Raw-socket scan types
> such as `-sS` and `-O` require additional privileges (`CAP_NET_RAW` /
> `CAP_NET_ADMIN`). The recommended approach is to grant `nmap` the required
> Linux capabilities so **no root is needed**:
>
> ```bash
> sudo setcap cap_net_raw,cap_net_admin+eip $(which nmap)
> ```
>
> Apply the same for Naabu if you use SYN scanning:
>
> ```bash
> sudo setcap cap_net_raw,cap_net_admin+eip $(which naabu)
> ```
>
> On Android / Termux (where `setcap` is unavailable) scans automatically
> fall back to TCP connect mode, which works without root but is slower.

### Exploit / scan tasks failing

Kamerka does **not** invoke `sudo` from Python. Tasks run in whatever user starts the **Celery worker**:

1. **Nmap / Naabu permission errors** — prefer `setcap` on the binaries (above) so the worker can stay unprivileged.
2. **Device exploit checks still fail** (timeouts, permission denied, empty results) — restart the Celery worker under elevated privileges on **your** host (e.g. `sudo -E` with `venv` activated and `.env` loaded). That is an operator workaround, not something the repo automates.
3. Keep **`manage.py runserver`** on your normal user; only the worker process needs elevation when (2) applies.

## Wappalyzer CLI Install

Wappalyzer is an optional tool for web technology fingerprinting. Install it
via npm (Node.js ≥ 18 required):

```bash
npm install -g wappalyzer
```

Verify the install:

```bash
wappalyzer --version
```

The binary path can be overridden with the `KAMERKA_WAPPALYZER_BIN` env var
if `wappalyzer` is not on your `$PATH`.

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
| --------- | --------------- |
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

To also run periodic tasks (feed ingestion, layer refresh), start Celery with beat:

```bash
celery --app kamerka worker --beat --loglevel=info
```

> See [Exploit / scan tasks failing](#exploit--scan-tasks-failing) if tasks error out — you may need an elevated worker; the app never calls `sudo` itself.

In a new window start Redis:

```bash
pacman -S redis
redis-server
```

The server should be available at `http://localhost:8000/`

## Database — PostgreSQL (Required)

PostgreSQL is required because the application runs Django, Celery workers, and
Celery beat concurrently. See [docs/DATABASE.md](DATABASE.md) for the connection
configuration.

### Quick PostgreSQL setup

1. Install PostgreSQL (or run via Docker):

```bash
# Docker (fastest)
docker run -d --name kamerka-pg \
  -e POSTGRES_DB=kamerka \
  -e POSTGRES_USER=kamerka \
  -e POSTGRES_PASSWORD=CHANGE_ME \
  -p 5432:5432 postgres:16

# Or install natively on Debian/Ubuntu/Kali (not for Termux — see below)
sudo apt install postgresql postgresql-contrib
sudo systemctl start postgresql
bash scripts/setup_postgres.sh

# Termux (Android) — no sudo; postgres runs as your user
pkg install postgresql tmux bash redis
mkdir -p "$PREFIX/var/lib/postgresql"
# Only initialize a new cluster; never reinitialize an existing one.
test -s "$PREFIX/var/lib/postgresql/PG_VERSION" || initdb "$PREFIX/var/lib/postgresql"
pg_ctl -D "$PREFIX/var/lib/postgresql" start
bash scripts/setup_postgres.sh
```

The setup script creates the local `kamerka` login and database if missing,
prompts for the new login's password, and leaves existing databases/passwords
untouched. It connects as the current local PostgreSQL administrator on Termux,
or uses `sudo -u postgres` when needed on Linux. It does **not** install or start
PostgreSQL. If you use different names, pass them explicitly:
`DB_USER=your_user DB_NAME=your_database bash scripts/setup_postgres.sh`.
This administrative helper does not read `.env`; match the names and password
you configure there. Remote/Docker databases must be provisioned on their server.

1. Ensure Python dependencies are installed (includes PostgreSQL adapter):

```bash
pip3 install -r requirements.txt
```

1. Export the database environment variables before starting Django and Celery:

```bash
export DB_NAME=kamerka
export DB_USER=kamerka
export DB_PASSWORD=CHANGE_ME
export DB_HOST=localhost
export DB_PORT=5432
```

2. Run migrations before starting Django/Celery:

```bash
python3 manage.py migrate
```

3. Start Django/Celery with those environment variables set.

### Bash scripts: missing database tables

An error such as `relation "app_kamerka_search" does not exist` means the
configured PostgreSQL database has not had the application migrations applied.
Check the `DB_*` values in `.env` and any exported environment variables (exported
variables take precedence), make sure PostgreSQL is running, then run:

```bash
bash scripts/kamerka.sh manage migrate --noinput
```

Restart Django and Celery afterward. Both `start_stack.sh` and
`tmux_kamerka_stack.sh` now apply migrations before starting services, and
`kamerka.sh runserver` (including `manage runserver`) does so for standalone
development. Standalone worker/beat commands check for pending migrations and
stop with recovery instructions instead of processing tasks against missing tables.
Migration failures stop stack startup before existing services are interrupted.
The Bash helpers replace the former `.fish` scripts. Put API keys and database
settings in the project `.env` file or export them in your environment; the helpers
do not read Fish configuration.
These commands use the existing database; do not delete it or fake migrations.
If Django reports no pending migrations but the table is still missing, check
that you selected the correct database and restore a backup if its schema was damaged.

Errors such as `role "kamerka" does not exist` or `database "kamerka" does not
exist happen **before** migrations can run. Complete the local PostgreSQL setup
above first, then put the same `DB_NAME`, `DB_USER`, and `DB_PASSWORD` in `.env`.
`connection refused` means PostgreSQL is not running at the configured host/port;
it is not a missing-table error.

### Bash tmux startup

Start PostgreSQL and Redis first (`redis-server` in another terminal), install
the Python requirements in `.venv`, and configure `.env`. Then:

```bash
bash scripts/tmux_kamerka_stack.sh
tmux attach -t kamerka
```

An existing session is not silently restarted. Replace a stale/empty session with
`bash scripts/tmux_kamerka_stack.sh --restart`. Database preparation happens before
the old session is removed. The launcher uses actual pane IDs instead of assuming
zero-based pane numbering and launches Bash commands directly, independently of
your default shell. Failed processes remain visible in their panes for diagnosis.

## Runtime Validation

```bash
python3 manage.py check
python3 manage.py test
```

### Python versions and missing modules

Use Python 3.10–3.14 and install dependencies with the same interpreter that
runs Django/Celery. The requirements now select Django 5.2 LTS with Python 3.14
support; the former Django 4.2 constraint was incompatible with Python 3.14.
From the project root, create a fresh environment when changing Python versions
(keep a backup of the old environment rather than reusing its binary packages):

```bash
python3 -m venv .venv
.venv/bin/python -m pip install --upgrade pip
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python -m pip check
```

`playwright` is explicitly included for `scripts/gui_e2e_playwright.py`. Its
browser download is separate: `.venv/bin/python -m playwright install chromium`.
On Termux, native dependencies may need to compile because Linux wheels do not
target Android; install the corresponding Termux development packages or use
distribution-provided builds. Playwright's bundled browsers do not support
Android/Termux; run browser automation on a supported desktop/Linux environment.
The Django/Celery app does not need a Playwright browser to start.
The optional native 3D desktop viewer still needs `requirements-3d.txt` and Qt/VTK;
those are not required for the web application.

---

## WorldMonitor Integration Features

After completing the base installation, seed the new data layers and feed sources:

```bash
# Apply migrations (includes new app_layers and app_feeds tables)
python3 manage.py migrate

# Seed default data layers (earthquakes, cables, ICS clusters …)
python3 manage.py seed_layers

# Seed ~50 curated RSS/news feed sources (CISA, Krebs, Dragos …)
python3 manage.py import_feeds_opml
# or legacy curated list: python3 manage.py seed_feeds
```

### Optional: Ollama AI Briefs

Set `OLLAMA_HOST` to enable AI-synthesised intelligence briefs:

```bash
export OLLAMA_HOST=http://localhost:11434
export OLLAMA_MODEL=llama3   # or any model you have pulled
```

When `OLLAMA_HOST` is unset, Kamerka falls back to an extractive summariser
that requires no additional dependencies.

### Celery Beat (required for real-time layer/feed refresh)

The WorldMonitor-integration features use Celery Beat for scheduled tasks:

```bash
# Start worker + beat scheduler in a single process (development)
celery --app kamerka worker --beat --loglevel=info

# Or run beat as a separate process (recommended for production)
celery --app kamerka beat --loglevel=info &
celery --app kamerka worker --loglevel=info &
celery --app kamerka beat --loglevel=info &
```

### Environment variables for integration features

| Variable | Default | Description |
|---|---|---|
| `OLLAMA_HOST` | *(unset)* | Ollama API base URL for AI brief generation |
| `OLLAMA_MODEL` | `llama3` | Ollama model name |
| `OLLAMA_TIMEOUT` | `60` | Timeout (seconds) for Ollama `/api/generate` calls |
| `LAYER_REFRESH_INTERVAL_MINUTES` | `60` | How often layers are refreshed by Celery Beat |
| `FEED_MAX_ENTRIES` | `500` | Maximum RSS entries to retain (oldest pruned) |

### New API endpoints

| Endpoint | Description |
| --- | --- |
| `GET /api/layers/` | List all enabled data layers (shared metadata for map/globe) |
| `GET /api/layers/?view=map|globe` | Filter shared layer catalog by frontend view |
| `GET /api/layers/<slug>/features.json` | GeoJSON features for a layer (`?bbox=min_lon,min_lat,max_lon,max_lat` and `?limit=N` optional filters) |
| `GET /api/layers/<slug>/refresh/` | Manually trigger a layer refresh |
| `POST /api/layers/import/` | Import a GeoJSON FeatureCollection as a layer |
| `GET /api/feeds/entries/` | Recent news feed entries (filterable by country) |
| `GET /api/feeds/entries/sse/` | SSE stream for live feed/layer updates |
| `GET /api/feeds/brief/<region>/` | Latest AI/extractive brief for a region |
| `POST /api/feeds/brief/<region>/generate/` | Force-regenerate a brief |
| `GET /api/export/geojson/<search_id>` | Enhanced GeoJSON export (risk_score, layer_context) |

### Dashboard live intelligence panel (Phase 3 vertical slice)

The dashboard (`/index`) now includes a **Live Intelligence Feed** panel and a
**Region Brief** panel:

- Select a region (ISO-2 code) to filter recent ingested feed entries.
- The brief panel calls `GET /api/feeds/brief/<region>/` and automatically
  shows pending generation until a brief is ready.
- Feed updates arrive live via SSE (`/api/feeds/entries/sse/`) and refresh the
  panel without a full page reload.

To use this effectively:

1. Seed feed sources:

   ```bash
   python3 manage.py import_feeds_opml

# or legacy curated list: python3 manage.py seed_feeds

   ```
2. Run worker + beat so feeds are ingested periodically:
   ```bash
   celery --app kamerka worker --beat --loglevel=info
   ```

3. Open `/index` and monitor the live panel.

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

For Termux, set up PostgreSQL first (see the PostgreSQL section above) and export:

```
export DB_NAME=kamerka
export DB_USER=kamerka
export DB_PASSWORD=CHANGE_ME
export DB_HOST=localhost
export DB_PORT=5432
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
