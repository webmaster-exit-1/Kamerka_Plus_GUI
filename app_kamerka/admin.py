from django.contrib import admin
from app_kamerka.models import TaskRun, Watchlist


@admin.register(TaskRun)
class TaskRunAdmin(admin.ModelAdmin):
    list_display = (
        "id",
        "tool",
        "status",
        "task_id",
        "triggered_by",
        "device",
        "search",
        "started_at",
        "finished_at",
    )
    list_filter = ("tool", "status")
    search_fields = ("task_id", "celery_task_name", "output", "error")


@admin.register(Watchlist)
class WatchlistAdmin(admin.ModelAdmin):
    list_display = (
        "id",
        "name",
        "query_type",
        "category",
        "enabled",
        "refresh_interval_minutes",
        "last_run_at",
        "next_run_at",
    )
    list_filter = ("enabled", "query_type", "category", "healthcare")
    search_fields = ("name", "country", "coordinates")
