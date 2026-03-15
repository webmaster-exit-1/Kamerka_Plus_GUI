"""
SQLite connection tuning for reduced lock contention.

Registers a ``connection_created`` signal handler that enables WAL journal mode
and raises the busy timeout for every new SQLite connection.  This significantly
reduces ``OperationalError: database is locked`` errors when Django web workers
and Celery tasks access the database concurrently.

The handler is wired up in :class:`app_kamerka.apps.AppKamerkaConfig.ready`.
"""

from django.db.backends.signals import connection_created


def enable_sqlite_wal(sender, connection, **kwargs):
    """Set WAL mode and a generous busy timeout on every new SQLite connection."""
    if connection.vendor != "sqlite":
        return
    with connection.cursor() as cursor:
        # WAL allows concurrent readers alongside a single writer, greatly
        # reducing lock contention compared to the default rollback journal.
        cursor.execute("PRAGMA journal_mode=WAL;")
        # NORMAL is safe with WAL and avoids the extra fsync overhead of FULL.
        cursor.execute("PRAGMA synchronous=NORMAL;")
        # Wait up to 30 seconds before raising "database is locked" instead of
        # failing immediately.  Mirrors the 'timeout' set in DATABASES OPTIONS.
        cursor.execute("PRAGMA busy_timeout=30000;")
