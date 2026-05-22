"""
Tool Dispatcher
===============
A single entry point that accepts a registry tool name + device ID,
looks up the ToolPlugin, checks it is enabled, then enqueues the
matching Celery task via the existing ``_enqueue_tracked_task`` helper.

Usage
-----
::

    from app_kamerka.dispatcher import dispatch_tool

    async_result, task_run = dispatch_tool(
        request, "screenshot", device_id=device.id
    )

The function returns a ``(AsyncResult, TaskRun)`` pair exactly like
``_enqueue_tracked_task`` so all existing callers can be migrated
incrementally.

Raising on disabled tools
--------------------------
If the requested tool is disabled via ``KAMERKA_TOOL_<NAME>_ENABLED=false``
a ``ToolDisabledError`` is raised.  Views should catch this and return a
400-level JSON response.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

from app_kamerka.tool_registry import get_tool

if TYPE_CHECKING:
    from django.http import HttpRequest
    from celery.result import AsyncResult
    from app_kamerka.models import TaskRun


class ToolNotFoundError(ValueError):
    pass


class ToolDisabledError(PermissionError):
    pass


def dispatch_tool(
    request: "HttpRequest",
    tool_name: str,
    *,
    device_id: int | str | None = None,
    search_id: int | None = None,
    extra_kwargs: dict | None = None,
) -> tuple["AsyncResult", "TaskRun"]:
    """Enqueue the Celery task registered under *tool_name*.

    Parameters
    ----------
    request:
        The Django HttpRequest; used to record the triggering user on TaskRun.
    tool_name:
        Registry key (e.g. ``"screenshot"``).
    device_id:
        Primary key of the target Device record.
    search_id:
        Primary key of the parent Search record (optional, for context).
    extra_kwargs:
        Additional keyword arguments forwarded to the Celery task.  Use this
        to pass optional parameters like ``severity`` to nuclei_scan.

    Returns
    -------
    (AsyncResult, TaskRun)
        The Celery async result and the persisted TaskRun record.

    Raises
    ------
    ToolNotFoundError
        When *tool_name* is not in the registry.
    ToolDisabledError
        When the tool is disabled via environment variable.
    """
    # Avoid circular import with views.py
    from app_kamerka.views import _enqueue_tracked_task  # noqa: PLC0415

    plugin = get_tool(tool_name)
    if plugin is None:
        raise ToolNotFoundError("Unknown tool: {!r}".format(tool_name))
    if not plugin.enabled:
        raise ToolDisabledError("Tool {!r} is disabled".format(tool_name))

    # Resolve the Celery callable from the dotted task name
    task_callable = _resolve_celery_task(plugin.celery_task_name)

    # Build positional / keyword arguments from the call_mode
    device_id = int(device_id) if device_id is not None else None
    task_args: list = []
    task_kwargs: dict = dict(extra_kwargs or {})

    if plugin.call_mode == "args":
        if device_id is not None:
            task_args = [device_id]
    elif plugin.call_mode == "kwargs_id":
        if device_id is not None:
            task_kwargs["id"] = device_id
    elif plugin.call_mode == "kwargs_device_id":
        if device_id is not None:
            task_kwargs["device_id"] = device_id

    return _enqueue_tracked_task(
        request,
        task_callable,
        task_args=task_args,
        task_kwargs=task_kwargs,
        device_id=device_id,
        search_id=search_id,
        tool=tool_name,
    )


def _resolve_celery_task(dotted_name: str):
    """Import and return the Celery task object for *dotted_name*.

    The dotted name is expected to be ``"module.submodule.task_function"``.
    """
    parts = dotted_name.rsplit(".", 1)
    if len(parts) != 2:
        raise ToolNotFoundError(
            "Invalid celery_task_name {!r}: expected 'module.function'".format(dotted_name)
        )
    module_path, func_name = parts
    import importlib
    module = importlib.import_module(module_path)
    task = getattr(module, func_name, None)
    if task is None:
        raise ToolNotFoundError(
            "Cannot find {!r} in module {!r}".format(func_name, module_path)
        )
    return task
