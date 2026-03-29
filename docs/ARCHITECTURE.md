# Architecture

## 3D Globe Launcher

The standalone 3D globe viewer is a **PyQt6 desktop application** that loads device records directly from the local Django database and renders them as colour-coded spikes on a textured Earth sphere.

### Install the extra dependencies

```bash
pip3 install -r requirements-3d.txt
```

### Launch

```bash
python3 -m gui.launch
```

The window opens with two panes:

| Pane | Contents |
|------|----------|
| **Left – Details** | IP, organisation, city, banner, Nuclei vulnerability findings, notes |
| **Right – Globe** | Textured 3D Earth; scroll to zoom, click-drag to rotate |

Click **Load Devices** in the toolbar to fetch all device records from the database.  Click any spike to populate the Details panel for that device or cluster.

> **First run:** the globe downloads a high-resolution Earth texture from the PyVista asset server and caches it at `assets/earth_surface.jpg`.  All subsequent runs are fully offline.  See `assets/README.md` for air-gapped / manual texture setup.

---

## Tool Path Configuration

Naabu and Nuclei are resolved via `$PATH` by default.  To point them at a custom binary (e.g. a Go workspace install), edit **`kamerka/tool_settings.py`** directly:

```python
# kamerka/tool_settings.py
NAABU_DEFAULT  = "/home/user/go/bin/naabu"   # ← change this
NUCLEI_DEFAULT = "/home/user/go/bin/nuclei"  # ← change this
```

Or use environment variables (recommended for CI / containers):

```bash
export KAMERKA_NAABU_BIN=/opt/tools/naabu
export KAMERKA_NUCLEI_BIN=/opt/tools/nuclei
```

Additional tunables in `kamerka/tool_settings.py`:

| Variable | Env override | Default | Description |
|----------|-------------|---------|-------------|
| `NAABU_BIN` | `KAMERKA_NAABU_BIN` | `naabu` | Naabu binary path |
| `NUCLEI_BIN` | `KAMERKA_NUCLEI_BIN` | `nuclei` | Nuclei binary path |
| `NAABU_DEFAULT_PORTS` | `KAMERKA_NAABU_PORTS` | `top-100` | Port spec for liveness checks |
| `NAABU_DEFAULT_TIMEOUT` | `KAMERKA_NAABU_TIMEOUT` | `60` | Naabu subprocess timeout (s) |
| `NUCLEI_DEFAULT_TIMEOUT` | `KAMERKA_NUCLEI_TIMEOUT` | `300` | Nuclei subprocess timeout (s) |
| `NMAP_USE_SUDO` | `KAMERKA_NMAP_SUDO` | `false` | Run Nmap under sudo (see below) |

### Nmap and sudo

Some Nmap scan types (SYN scans `-sS`, OS detection `-O`, raw-packet probes) require
`CAP_NET_RAW` / root privileges.  There are two ways to grant them:

**Option A — run the Celery worker as root**

This is the simplest approach.  All environment variables (including
`SHODAN_API_KEY`) are naturally available because root inherits the environment
you set before starting the worker.

```bash
sudo -E celery --app kamerka worker --loglevel=info
# -E preserves the calling user's environment including SHODAN_API_KEY
```

**Option B — enable the `KAMERKA_NMAP_SUDO` flag**

```bash
export KAMERKA_NMAP_SUDO=true
```

With this flag set, every `NmapProcess` call is wrapped with `sudo`.
**Important:** `sudo` strips the user's environment by default, so `SHODAN_API_KEY`
(and other variables) will **not** be visible to the Celery task unless you
configure sudoers to preserve them:

```bash
sudo visudo
# Add inside the Defaults block (one line per variable, or use a list):
Defaults env_keep += "SHODAN_API_KEY REDIS_URL CELERY_BROKER_URL CELERY_RESULT_BACKEND"
```

Alternatively, use `sudo -E` (preserve entire environment) by starting the worker with:

```bash
sudo -E celery --app kamerka worker --loglevel=info
```

and leave `KAMERKA_NMAP_SUDO` unset (Nmap will already run as root).

---

## Verification Pipeline

- **Count-before-commit** — `shodan.count()` / `shodan.stats()` are always called first; a "Credit Cost vs Result Density" report is presented before any paid download
- **Tiered liveness check** — InternetDB (free, no key) → Naabu port scan (FOSS) → only verified-live targets are rendered as spikes
- **Deduplication** — `Device.last_scanned` timestamp prevents redundant Shodan API calls for assets checked within the last 24 hours (configurable)
- **Honeypot filtering** — clusters of ≥ 500 devices sharing an identical banner in the same /24 subnet are automatically flagged and excluded from the 3D render

---

## Celery / Redis Architecture

- **Broker**: Redis (default `redis://localhost:6379/0`)
- **Result backend**: Redis
- **Task queue**: All scanning tasks (Shodan search, Nmap, Nuclei, Wappalyzer, RTSP, exports) are dispatched as Celery tasks
- **Progress tracking**: `celery_progress` library provides real-time task progress in the browser UI
- **Rate limiting**: `_rate_limit_check(ip)` enforces 10 scans/60 s per IP via Django cache (Redis backend)

Configure via environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `CELERY_BROKER_URL` | `redis://localhost:6379/0` | Celery broker |
| `CELERY_RESULT_BACKEND` | `redis://localhost:6379/0` | Task result storage |
| `REDIS_URL` | `redis://localhost:6379/1` | Django cache backend |
