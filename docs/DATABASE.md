# Database

## PostgreSQL

PostgreSQL is the only supported database backend. The application runs Django,
Celery workers, and Celery beat concurrently, so a client/server database is
required for reliable writes and task progress updates.
The effective configuration is:

```python
DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": os.environ.get("DB_NAME", "kamerka"),
        "USER": os.environ.get("DB_USER", "kamerka"),
      "PASSWORD": os.environ.get("DB_PASSWORD", "kamerka"),
        "HOST": os.environ.get("DB_HOST", "localhost"),
        "PORT": os.environ.get("DB_PORT", "5432"),
    }
}
```

A local Postgres instance can be started quickly with Docker:

```bash
docker run -d --name kamerka-pg \
  -e POSTGRES_DB=kamerka \
  -e POSTGRES_USER=kamerka \
  -e POSTGRES_PASSWORD=secret \
  -p 5432:5432 postgres:16
```

Then export the matching environment variables before running Django and Celery.
Do not start the application until PostgreSQL is accepting connections.
