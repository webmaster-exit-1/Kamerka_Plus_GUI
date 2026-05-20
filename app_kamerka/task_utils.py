import json
from datetime import datetime, timezone

from celery.result import AsyncResult
from django.contrib.auth import get_user_model

from app_kamerka.models import Device, Search, TaskRun


_TASK_TOOL_MAP = {
    "kamerka.tasks.wappalyzer_scan": TaskRun.TOOL_WAPPALYZER,
    "kamerka.tasks.nuclei_scan": TaskRun.TOOL_NUCLEI,
    "kamerka.tasks.nmap_device_scan": TaskRun.TOOL_NMAP,
    "kamerka.tasks.nmap_scan": TaskRun.TOOL_NMAP,
    "kamerka.tasks.port_scan_task": TaskRun.TOOL_PORT_SCAN,
    "kamerka.tasks.capture_screenshot": TaskRun.TOOL_SCREENSHOT,
    "kamerka.tasks.nmap_rtsp_scan": TaskRun.TOOL_RTSP,
    "kamerka.tasks.shodan_scan_task": TaskRun.TOOL_SHODAN_SCAN,
    "kamerka.tasks.whoisxml": TaskRun.TOOL_WHOIS,
    "kamerka.tasks.devices_nearby": TaskRun.TOOL_NEARBY,
    "kamerka.tasks.deep_protocol_scan": TaskRun.TOOL_DEEP_SCAN,
    "kamerka.tasks.nvd_lookup": TaskRun.TOOL_NVD,
    "kamerka.tasks.nrich_lookup": TaskRun.TOOL_NRICH,
    "kamerka.tasks.cvedb_enrich": TaskRun.TOOL_CVEDB,
    "kamerka.tasks.shodan_intel_scan": TaskRun.TOOL_INTEL,
    "kamerka.tasks.honeypot_check": TaskRun.TOOL_HONEYPOT,
    "kamerka.tasks.sbom_lookup": TaskRun.TOOL_SBOM,
    "kamerka.tasks.gfw_check": TaskRun.TOOL_GFW,
    "kamerka.tasks.exploitdb_search": TaskRun.TOOL_EXPLOITDB,
}


def infer_tool(celery_task_name: str, fallback: str | None = None) -> str:
    if fallback:
        return fallback
    return _TASK_TOOL_MAP.get(celery_task_name or "") or TaskRun.TOOL_OTHER


def _resolve_user(user_id=None, user=None):
    if user is not None and getattr(user, "is_authenticated", False):
        return user
    if not user_id:
        return None
    return get_user_model().objects.filter(pk=user_id).first()


def _resolve_device(device=None, device_id=None):
    if device is not None:
        return device
    if not device_id:
        return None
    return Device.objects.filter(pk=device_id).first()


def _resolve_search(search=None, search_id=None):
    if search is not None:
        return search
    if not search_id:
        return None
    return Search.objects.filter(pk=search_id).first()


def record_task_run(
    *,
    task_id,
    celery_task_name,
    tool=None,
    user=None,
    user_id=None,
    device=None,
    device_id=None,
    search=None,
    search_id=None,
):
    task_id = str(task_id or "")
    celery_task_name = str(celery_task_name or "")
    if not task_id:
        return None
    return TaskRun.objects.create(
        task_id=task_id,
        tool=infer_tool(celery_task_name, tool),
        celery_task_name=celery_task_name,
        triggered_by=_resolve_user(user=user, user_id=user_id),
        device=_resolve_device(device=device, device_id=device_id),
        search=_resolve_search(search=search, search_id=search_id),
    )


def _result_to_text(result):
    if result is None:
        return ""
    if isinstance(result, (str, int, float, bool)):
        return str(result)
    try:
        return json.dumps(result, ensure_ascii=False)[:10000]
    except Exception:
        return str(result)[:10000]


def sync_task_run(task_run: TaskRun):
    task = AsyncResult(task_run.task_id)
    state = task.state

    if state in {"PENDING", "RECEIVED"}:
        status = TaskRun.STATUS_PENDING
    elif state in {"STARTED", "RETRY", "PROGRESS"}:
        status = TaskRun.STATUS_RUNNING
    elif state == "SUCCESS":
        status = TaskRun.STATUS_SUCCESS
    else:
        status = TaskRun.STATUS_FAILURE

    changed = False
    if task_run.status != status:
        task_run.status = status
        changed = True

    result_text = _result_to_text(task.result)
    if status == TaskRun.STATUS_FAILURE:
        if task_run.error != result_text:
            task_run.error = result_text
            changed = True
    elif result_text and task_run.output != result_text:
        task_run.output = result_text
        changed = True

    if status in {TaskRun.STATUS_SUCCESS, TaskRun.STATUS_FAILURE} and task_run.finished_at is None:
        task_run.finished_at = datetime.now(timezone.utc)
        changed = True

    if changed:
        task_run.save(update_fields=["status", "output", "error", "finished_at"])
    return task_run


def sync_task_run_by_task_id(task_id: str):
    task_run = TaskRun.objects.filter(task_id=task_id).first()
    if task_run:
        return sync_task_run(task_run)
    return None
