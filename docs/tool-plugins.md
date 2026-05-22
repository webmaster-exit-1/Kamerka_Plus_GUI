# How to Add a Tool Plugin

This guide explains how to register a new Kamerka tool so it appears
automatically in the bulk-run UI, the system-status page, the API discovery
endpoint, and playbooks.

---

## 1. Understand what a ToolPlugin is

A `ToolPlugin` is a Python dataclass defined in
`app_kamerka/tool_registry.py`.  It carries:

| Field | Type | Purpose |
|---|---|---|
| `name` | `str` | Registry key (must match `TaskRun.TOOL_*` constant) |
| `label` | `str` | Human-readable name shown in UI |
| `description` | `str` | One-line description |
| `celery_task_name` | `str` | Dotted Celery task path, e.g. `kamerka.tasks.my_task` |
| `call_mode` | `str` | How the device ID is passed (`args`, `kwargs_id`, `kwargs_device_id`) |
| `required_binaries` | `list[str]` | External binaries that must be on PATH |
| `required_secrets` | `list[str]` | Env-var names that must be non-empty |
| `bulk_supported` | `bool` | Whether the tool appears in bulk-run (default `True`) |
| `enabled_by_default` | `bool` | Default enabled state (default `True`) |

### Call modes

| `call_mode` | Celery call signature |
|---|---|
| `"args"` | `my_task.delay(device_id)` |
| `"kwargs_id"` | `my_task.delay(id=device_id)` |
| `"kwargs_device_id"` | `my_task.delay(device_id=device_id)` |

---

## 2. Write the Celery task

Add your task to `kamerka/tasks.py` (or a new module).

```python
from celery import shared_task

@shared_task(name="kamerka.tasks.my_new_tool")
def my_new_tool(device_id):
    from app_kamerka.models import Device
    device = Device.objects.get(pk=device_id)
    # ... do work ...
    return {"status": "ok", "result": "..."}
```

**Return a JSON-serialisable dict** (never raw HTML or non-serialisable objects).

---

## 3. Add a TaskRun constant (for backwards-compatibility)

Open `app_kamerka/models.py` and add a constant to `TaskRun`:

```python
TOOL_MY_NEW_TOOL = "my_new_tool"
```

Then add it to `TOOL_CHOICES`:

```python
(TOOL_MY_NEW_TOOL, "My New Tool"),
```

Also register the task-name → tool mapping in `app_kamerka/task_utils.py`:

```python
"kamerka.tasks.my_new_tool": TaskRun.TOOL_MY_NEW_TOOL,
```

---

## 4. Register the plugin

Open `app_kamerka/tool_registry.py` and add a `register()` call at module level:

```python
register(ToolPlugin(
    name="my_new_tool",
    label="My New Tool",
    description="Short description of what this tool does.",
    celery_task_name="kamerka.tasks.my_new_tool",
    call_mode="kwargs_device_id",   # or "args" / "kwargs_id"
    required_binaries=["my-binary"],
    required_secrets=["MY_API_KEY"],
    bulk_supported=True,
))
```

That is all.  No other wiring is needed — the tool will automatically:

- Appear in `GET /api/tools/` and `GET /api/tools/applicable/<device_id>/`
- Show up in the bulk-run dropdown in `/devices`
- Show a health entry on `/healthz/setup/`
- Be usable as a playbook step

---

## 5. Optional: add a device-page view

If you want a dedicated per-device button, add a view in `app_kamerka/views.py`:

```python
def my_new_tool_view(request, id):
    if (request.method == "GET"
            and request.headers.get("X-Requested-With") == "XMLHttpRequest"):
        task, task_run = _enqueue_tracked_task(
            request,
            my_new_tool,              # Celery task callable
            task_kwargs={"device_id": id},
            device_id=id,
            tool=TaskRun.TOOL_MY_NEW_TOOL,
        )
        return HttpResponse(
            json.dumps({"task_id": task.id, "task_run_id": task_run.id}),
            content_type="application/json",
        )
    return HttpResponse(json.dumps({"task_id": None}), content_type="application/json")
```

Add a URL in `app_kamerka/urls.py`:

```python
path("<id>/my_new_tool", views.my_new_tool_view, name="my_new_tool"),
```

---

## 6. Globally disable the tool

Set the environment variable:

```
KAMERKA_TOOL_MY_NEW_TOOL_ENABLED=false
```

The dispatcher will refuse to enqueue the tool and the API will return
`"enabled": false` for it.

---

## 7. Write a test

Add a test in `tests/test_tool_registry.py`:

```python
def test_my_new_tool_registered(self):
    from app_kamerka.tool_registry import get_tool
    plugin = get_tool("my_new_tool")
    self.assertIsNotNone(plugin)
    self.assertEqual(plugin.label, "My New Tool")
```

---

## Expected output shape

Every tool should return a JSON-serialisable dict.  The recommended structure:

```json
{
  "status": "ok",
  "device_id": 42,
  "result": { ... }
}
```

Results are stored in `TaskRun.output` (truncated to 10 000 characters).
