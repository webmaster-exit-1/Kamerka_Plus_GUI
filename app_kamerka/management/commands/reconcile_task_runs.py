"""Reconcile TaskRun rows against Celery (mark stale pending tasks as failed)."""
from django.core.management.base import BaseCommand

from app_kamerka.task_utils import reconcile_open_task_runs


class Command(BaseCommand):
    help = "Sync open TaskRun records with Celery and mark stale pending tasks as failed"

    def add_arguments(self, parser):
        parser.add_argument(
            "--limit",
            type=int,
            default=None,
            help="Max number of open runs to check (default: all)",
        )

    def handle(self, *args, **options):
        stats = reconcile_open_task_runs(limit=options["limit"])
        self.stdout.write(
            self.style.SUCCESS(
                "Checked {checked} open task(s); {updated} status change(s) {detail}".format(
                    checked=stats["checked"],
                    updated=stats["updated"],
                    detail=stats.get("by_new_status") or "",
                )
            )
        )