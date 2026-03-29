# Database

## SQLite Concurrency and Database Locking

### Why "database is locked" happens

SQLite allows only **one writer at a time**.  When Django web workers and Celery
background tasks both try to write to the database simultaneously, SQLite returns
`OperationalError: database is locked`.  This is especially likely with
`celery_progress` polling `/results/<id>` while a task is actively writing scan
results.

### Mitigations applied in this project

1. **WAL journal mode** (`PRAGMA journal_mode=WAL`) — Write-Ahead Logging lets
   readers and a single writer operate concurrently without blocking each other,
   greatly reducing lock collisions compared to the default rollback journal.
2. **Higher busy timeout** — Both the Django connection (`OPTIONS.timeout = 30`
   seconds) and the SQLite pragma (`PRAGMA busy_timeout=30000` ms) tell SQLite
   to *wait* before raising an error instead of failing immediately.
3. **`synchronous=NORMAL`** — Safe with WAL mode and avoids the extra fsync
   overhead of `FULL`, keeping write performance reasonable.

The WAL and timeout pragmas are applied automatically on every new connection
via a `connection_created` signal handler in `app_kamerka/sqlite_wal.py`.

---

## Recommendation for Production / Heavy Concurrency

SQLite is not designed for multi-process concurrent writes.  If you run multiple
Celery workers or a multi-threaded/multi-process WSGI server, consider switching
to **PostgreSQL**:

```python
DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": os.environ.get("DB_NAME", "kamerka"),
        "USER": os.environ.get("DB_USER", "kamerka"),
        "PASSWORD": os.environ.get("DB_PASSWORD", ""),
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
