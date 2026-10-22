# Docker Quickstart

Kamerka Plus GUI can run with one command using Docker Compose:

```bash
docker compose --profile dev up --build
```

## Services

- `web`: Django + Gunicorn
- `redis`: broker/backend cache
- `celery`: worker
- `celery-beat`: scheduler
- `postgres`: PostgreSQL database used by Django and Celery

## Persistent volumes

- `postgres_data`: PostgreSQL data directory
- `media_data`: `/app/scans` uploads and generated scan media
- `downloads_data`: `/app/downloads` generated export/download artifacts

## Environment variables

Use `.env` (copy from `.env.example`) and adjust values:

| Variable | Required | Purpose |
|---|---|---|
| `DJANGO_SECRET_KEY` | yes | Django signing key |
| `DEBUG` | no | Dev flag |
| `ALLOWED_HOSTS` | yes (prod) | Allowed hosts |
| `SHODAN_API_KEY` | yes | Shodan integration |
| `NVD_API_KEY` | no | NVD API quota boost |
| `REDIS_URL` | yes | Redis URL |
| `CELERY_BROKER_URL` | no | Celery broker |
| `CELERY_RESULT_BACKEND` | no | Celery result backend |
| `DB_NAME`, `DB_USER`, `DB_PASSWORD`, `DB_HOST`, `DB_PORT` | yes | PostgreSQL connection settings |

PostgreSQL is the only supported backend. With Compose, set `DB_HOST=postgres`;
for a host-installed server, use `DB_HOST=localhost`.

### HexSploit connections

Compose passes `.env` to web, celery and celery-beat without overriding HexSploit
endpoints or the Ollama model. Native loopback defaults refer to the **container**
in Docker, not your laptop, Docker host, or browser. Configure reachable URLs:

```dotenv
HEXSTRIKE_SERVER_URL=http://host.docker.internal:8888
HEXSPLOIT_OLLAMA_SERVER_URL=http://host.docker.internal:11434
```

The Compose services already map `host.docker.internal` to the host gateway.
Host backends must listen on a reachable interface, with firewall restrictions to
trusted containers. For backends in the same Docker network use their service DNS
names instead; for remote backends use their trusted HTTPS endpoints. No HexStrike
or Ollama service is started by this Compose file. Restart/recreate web and workers
after changing settings. The displayed HexStrike URL and health/actions use the
same configured address; the browser itself never connects to that backend.

Feed map tiles, unlike backend connections, are fetched by the **browser**.
Configure a browser-reachable HTTPS tile URL and provider attribution in `.env`;
see [basemap requirements](INSTALL.md#feeds-briefing-basemap). Any tile key will be
public to browsers and must be restricted accordingly.

## Migrations and upgrades

Containers run migrations at startup for the `web` service. For manual control:

```bash
docker compose run --rm web python manage.py migrate --run-syncdb
docker compose run --rm web python manage.py collectstatic --noinput
```

## Initial seed (optional)

```bash
docker compose run --rm web python manage.py seed_layers
docker compose run --rm web python manage.py seed_feeds
docker compose run --rm web python manage.py create_default_superuser
```
