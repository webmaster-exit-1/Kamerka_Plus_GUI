# Changelog

All notable changes from the **Map3D / intel / HexSploit** development pass are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

_Nothing yet._

## [2026-06-02] — `b7e5c98`

Large feature and reliability release: web 3D mapping without a paid basemap, RSS-driven regional briefs, HexStrike bridge, task hygiene, and UI fixes from hands-on testing.

### Added

#### 3D map (`/map3d`)

- **MapLibre GL JS** viewer with **OpenFreeMap** as the default basemap (no API key, no usage bill).
- Optional **`MAPBOX_ACCESS_TOKEN`** for richer 3D building meshes when you want Mapbox.
- Device visualization: heatmap layer, 3D columns, buildings overlay.
- **Exports:** GeoJSON, KML, and CSV for external tools (QGIS, Kepler.gl, SandDance, etc.).
- **Vendored** MapLibre under `app_kamerka/static/vendor/maplibre-gl/` so CSP does not depend on a CDN (fixes “3D map could not load”).
- **`/globe`** now redirects to **`/map3d`**; nav label **3D Map**.

#### RSS & regional intelligence (`app_feeds`)

- **OPML import:** `python manage.py import_feeds_opml [path]` with bundled `app_feeds/data/feeder-export.opml` (97 feeds) and support for custom Feeder exports (`--deactivate-missing`, `--dry-run`).
- **`FeedSource.folder`** field + migration `0002_feedsource_folder`.
- Hourly Celery tasks: **`refresh_feeds`** (feedparser), **`geo_tag_entries`** (country codes in article text).
- **Launch page — Feed Intel:** live entry list with country filter and SSE refresh (`/api/feeds/entries/sse/`).
- **Launch page — Region Brief:** per–ISO-2 brief via `/api/feeds/brief/<region>/` with UI polling until ready.
- Brief generation: **Ollama** when `OLLAMA_HOST` is set, else **extractive** summariser (`app_feeds/ai_briefs.py`).
- **`html_to_plain()`** (`app_feeds/text_utils.py`) — strips RSS HTML from summaries, briefs, and API responses (no more raw `<h3>` in the panel).
- Empty/orphan brief handling: always persists a `Brief` row; clear messages when feeds are not ingested.

#### HexSploit (`/hexsploit/`)

- **`hexstrike_client.py`** — HTTP client for a local HexStrike server (`HEXSTRIKE_SERVER_URL`, default `http://127.0.0.1:8888`).
- **`hexsploit.html`** — health, tool catalog, smart scan, attack-chain planner UI.
- **CSRF-safe** POSTs to `/api/hexstrike/action/` (`@ensure_csrf_cookie`, `X-CSRFToken` in JS).
- Tests in `app_kamerka/tests_hexstrike.py`.
- **`scripts/start_hexstrike.fish`** — helper to start HexStrike with PATH shims.

#### Task runs & Celery hygiene

- **`sync_task_run()`** improvements: detect **orphaned** jobs (Celery `PENDING` + no Redis result meta for ~10 minutes) and **stale** jobs (default 90 minutes).
- Mark orphans/stale as **`failure`** with an explanatory error instead of leaving hundreds of **pending** forever.
- **`reconcile_open_task_runs()`** + management command **`reconcile_task_runs`**.
- Beat schedule: **`kamerka.tasks.reconcile_stale_task_runs`** every 15 minutes.
- **`/tasks`** page reconciles all open runs on load and shows status summary counts.
- Settings: `TASK_RUN_STALE_MINUTES`, `TASK_RUN_ORPHAN_MINUTES` (via env / `settings.py`).

#### Shell UX & navigation

- **`kamerka-shell.css`**, **`kamerka-shell.js`** — shared layout polish.
- **`sidebar_nav.html`**, **`breadcrumbs.html`**, **`case_toolbar.html`**, **`export_drawer.html`**.
- **`context_processors.py`** — active nav highlighting (including HexSploit).

#### Install & operations scripts

- **`scripts/install_kamerka.py`** — interactive wizard (`.env`, `DJANGO_SECRET_KEY`, Shodan/NVD/HexStrike, superuser, migrations, `seed_layers`, `import_feeds_opml`).
- **`scripts/kamerka.fish`** — run Django/Celery/tests with venv + Fish env.
- **`scripts/start_stack.fish`**, **`scripts/tmux_kamerka_stack.fish`** — stack launcher.
- **`scripts/poll_shodan_case.py`**, **`scripts/run_device_osint.py`**, **`scripts/run_rest_suite.py`**, **`scripts/gui_e2e_playwright.py`**, **`scripts/test_launch_flow.py`**, **`scripts/test_install_kamerka.py`**.

#### Other

- **`app_kamerka/shodan_presets.py`** — country/ICS preset helpers for Shodan launch.
- **`app_kamerka/test_compat.py`** — compatibility checks.
- **`feedparser`** added to `requirements.txt` (required for RSS ingestion).
- Tests: `app_feeds` (OPML, briefs, HTML strip), `app_kamerka/tests_task_runs.py`.

### Changed

- **README.md** — rewritten for current stack: Map3D, feeds, HexSploit, install wizard, key URLs, env table.
- **docs/INSTALL.md** — install wizard, `import_feeds_opml`, HexStrike note; Pastebin references removed where obsolete.
- **`.env.example`** — Mapbox (optional), Ollama, layer/feed limits, HexStrike URL documented.
- **`kamerka/settings.py`** — CSP `connect-src` / `worker-src` for OpenFreeMap (and Mapbox); feed beat tasks; task stale settings.
- **`/devices`** — server-side pagination (100/page), IP search filter, safer indicator parsing; DataTables only on `#devices-table` (avoids freezing on thousands of rows).
- **Device / results / search templates** — shell includes, export drawer, nav updates.
- **`app_kamerka/views.py`** — `map3d_view`, GeoJSON/KML export endpoints; `intel_regions` from devices, searches, and feed geo tags; **fixed overview `countries` dict** (loop variable no longer shadows the world-map data).
- **`app_kamerka/middleware.py`** — CSP updates for 3D map tiles and workers.
- **`kamerka/tasks.py`** — `reconcile_stale_task_runs` task; `enrich_device_context` retained.
- **`verification/naabu_scanner.py`** — adjustments aligned with tool settings.
- **`app_kamerka/task_utils.py`** — expanded tool map and reconciliation helpers.

### Fixed

- **Overview dashboard** — PORTS, CATEGORIES, and WORLD COVERAGE charts blank because `countries` was overwritten by the feed geo-tag loop (invalid `drawcharts()` JS).
- **Region Brief** stuck on “Generating…” when `feedparser` was missing (no `FeedEntry` rows, no `Brief` saved); added polling, pending dedup, and always-create brief logic.
- **Region Brief / Feed Intel** showing literal HTML tags from RSS summaries.
- **All devices page** errors when rendering very large device lists.
- **3D map load failure** from CSP blocking external MapLibre CDN (vendored assets + template `{% static %}`).
- **HexSploit** CSRF failures on tool actions from the browser.
- **Tasks page** wall of **pending** — orphaned Celery IDs after worker downtime / expired Redis results; bogus `finished_at` on pending rows no longer blocks cleanup.

### Removed

- **`scripts/pastebin_setup.py`** — Pastebin workflow dropped from the tree.

### Security & configuration

- API keys remain **environment-only** (no `keys.json`).
- HexStrike / smart scan: intended for **authorised** lab targets; bridge is optional.

### Developer notes

- After pull: `pip install -r requirements.txt`, restart **Celery worker + beat**, run `python manage.py migrate`, optionally `import_feeds_opml` for your OPML.
- If Tasks still show old pending rows: `python manage.py reconcile_task_runs`.
- CI: GitHub Actions on `master` / `main` (tests + Redis service).

---

## Prior baseline

Commits before this release include the **Plus Edition** fork work (Leaflet/OSM, Nuclei, WHOIS, Celery progress, verification pipeline, PyVista desktop globe, etc.) — see git history before `24c183d3`.

---

_Built with apprecation for the ꓘamerka analyst rig. Thanks for shipping it._