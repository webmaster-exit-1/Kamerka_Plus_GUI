from datetime import timedelta
from unittest.mock import MagicMock, patch

from django.test import TestCase, override_settings
from django.utils import timezone

from app_kamerka.models import TaskRun
from app_kamerka.task_utils import reconcile_open_task_runs, sync_task_run


class TaskRunSyncTests(TestCase):
    def test_stale_pending_marked_failure(self):
        run = TaskRun.objects.create(
            task_id="00000000-0000-0000-0000-000000000099",
            tool=TaskRun.TOOL_INTEL,
            celery_task_name="kamerka.tasks.shodan_intel_scan",
            status=TaskRun.STATUS_PENDING,
        )
        TaskRun.objects.filter(pk=run.pk).update(
            started_at=timezone.now() - timedelta(hours=3)
        )
        run.refresh_from_db()

        mock_result = MagicMock()
        mock_result.state = "PENDING"
        mock_result.result = None

        with patch("app_kamerka.task_utils.AsyncResult", return_value=mock_result):
            sync_task_run(run)

        run.refresh_from_db()
        self.assertEqual(run.status, TaskRun.STATUS_FAILURE)
        self.assertIn("did not complete", run.error)
        self.assertIsNotNone(run.finished_at)

    @override_settings(TASK_RUN_STALE_MINUTES=90)
    def test_recent_pending_stays_pending(self):
        run = TaskRun.objects.create(
            task_id="00000000-0000-0000-0000-000000000098",
            tool=TaskRun.TOOL_NMAP,
            celery_task_name="kamerka.tasks.nmap_device_scan",
            status=TaskRun.STATUS_PENDING,
        )

        mock_result = MagicMock()
        mock_result.state = "PENDING"
        mock_result.result = None

        with patch("app_kamerka.task_utils.AsyncResult", return_value=mock_result), patch(
            "app_kamerka.task_utils._celery_has_result_record", return_value=True
        ):
            sync_task_run(run)

        run.refresh_from_db()
        self.assertEqual(run.status, TaskRun.STATUS_PENDING)

    def test_orphan_without_redis_meta_marked_failure(self):
        run = TaskRun.objects.create(
            task_id="00000000-0000-0000-0000-000000000096",
            tool=TaskRun.TOOL_PORT_SCAN,
            celery_task_name="kamerka.tasks.port_scan_task",
            status=TaskRun.STATUS_PENDING,
        )
        TaskRun.objects.filter(pk=run.pk).update(
            started_at=timezone.now() - timedelta(minutes=15)
        )
        run.refresh_from_db()

        mock_result = MagicMock()
        mock_result.state = "PENDING"
        mock_result.result = None

        with patch("app_kamerka.task_utils.AsyncResult", return_value=mock_result), patch(
            "app_kamerka.task_utils._celery_has_result_record", return_value=False
        ):
            sync_task_run(run)

        run.refresh_from_db()
        self.assertEqual(run.status, TaskRun.STATUS_FAILURE)

    def test_reconcile_open_task_runs_updates_stale_rows(self):
        run = TaskRun.objects.create(
            task_id="00000000-0000-0000-0000-000000000097",
            tool=TaskRun.TOOL_SCREENSHOT,
            celery_task_name="kamerka.tasks.capture_screenshot",
            status=TaskRun.STATUS_PENDING,
        )
        TaskRun.objects.filter(pk=run.pk).update(
            started_at=timezone.now() - timedelta(hours=5)
        )

        mock_result = MagicMock()
        mock_result.state = "PENDING"
        mock_result.result = None

        with patch("app_kamerka.task_utils.AsyncResult", return_value=mock_result):
            stats = reconcile_open_task_runs()

        self.assertGreaterEqual(stats["checked"], 1)
        self.assertGreaterEqual(stats["updated"], 1)
        run.refresh_from_db()
        self.assertEqual(run.status, TaskRun.STATUS_FAILURE)