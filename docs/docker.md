# Docker Quickstart

Kamerka Plus GUI can run with one command using Docker Compose:

```bash
docker compose --profile postgres up --build
```

## Services

- `web`: Django + Gunicorn
- `redis`: broker/backend cache
- `celery`: worker
- `celery-beat`: scheduler
- `postgres`: optional (enabled with `--profile postgres`)

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
| `DB_NAME`, `DB_USER`, `DB_PASSWORD`, `DB_HOST`, `DB_PORT` | for Postgres | Database settings |

## SQLite dev mode (default)

Run without Postgres profile:

```bash
docker compose up --build
```

This keeps SQLite for local development (default branch in Django settings when `DB_NAME` is not set).

## Postgres mode

```bash
docker compose --profile postgres up --build
```

Set `DB_HOST=postgres` in `.env` so Django can resolve the database service inside Compose.

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
