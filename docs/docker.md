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
