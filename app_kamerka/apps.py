from django.apps import AppConfig


class AppKamerkaConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'app_kamerka'

    def ready(self):
        from .sqlite_wal import enable_sqlite_wal, connection_created
        connection_created.connect(enable_sqlite_wal)
