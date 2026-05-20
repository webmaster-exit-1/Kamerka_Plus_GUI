from django.contrib import admin
from app_kamerka.models import TaskRun


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
