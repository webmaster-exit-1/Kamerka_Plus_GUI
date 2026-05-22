# How to Add a Playbook

A **Playbook** is a named, ordered sequence of tool-plugin steps that can
be run against one or more devices in a single API call.  Playbooks are
stored in the database (`Playbook` model) and every execution is tracked
as a `PlaybookRun` record.

---

## What a Playbook looks like

```json
{
  "name": "Full Recon",
  "description": "Screenshot, port scan, Nuclei, SBOM",
  "steps": [
    {"tool": "screenshot", "order": 1, "exec_type": "chain"},
    {"tool": "port_scan",  "order": 2, "exec_type": "chain"},
    {"tool": "nuclei",     "order": 3, "exec_type": "chain"},
    {"tool": "sbom",       "order": 4, "exec_type": "chain"}
  ]
}
```

Each step references a **tool name** that must be in the tool registry
(see `docs/tool-plugins.md`).  The `exec_type` field is reserved for
future chain/group semantics; currently all steps run independently per
device.

---

## Creating a playbook via the UI

1. Navigate to **Playbooks** in the hamburger menu.
2. Enter a name (required) and optional description.
3. Select a tool from the dropdown and click **+ Add Step** for each step.
4. Click **Create Playbook**.

---

## Creating a playbook via the API

```
POST /api/playbooks/create/
Content-Type: application/json
X-CSRFToken: <token>

{
  "name": "My Playbook",
  "description": "Optional",
  "steps": [
    {"tool": "screenshot", "order": 1, "exec_type": "chain"},
    {"tool": "nuclei",     "order": 2, "exec_type": "chain"}
  ]
}
```

Successful response (HTTP 201):

```json
{"id": 1, "name": "My Playbook", "steps": [...]}
```

---

## Running a playbook against devices

```
POST /api/playbooks/<id>/run/
Content-Type: application/json
X-CSRFToken: <token>

{"device_ids": [1, 2, 3]}
```

Response (HTTP 200):

```json
{
  "playbook_run_id": 7,
  "runs": [
    {"device_id": 1, "tool": "screenshot", "task_id": "abc...", "task_run_id": 10},
    {"device_id": 1, "tool": "nuclei",     "task_id": "def...", "task_run_id": 11},
    ...
  ],
  "errors": []
}
```

Poll each `task_id` at `GET /get-task-info/?task_id=<id>` for results.

---

## Execution model

- Steps are dispatched in `order` (ascending) but all dispatched
  asynchronously to Celery — there is no built-in step-to-step chaining yet.
- Each (device × step) combination creates one `TaskRun` record.
- The `PlaybookRun` record stores all `task_run_id` values in the
  `task_runs` JSON field.
- Disabled or unknown tools in a step are skipped; the skips are reported
  in `errors`.

---

## Viewing run history

Open the playbook detail page (`/playbooks/<id>/`) to see the 20 most recent
`PlaybookRun` records with their status, device count, task count, and any
errors.

---

## Programmatic creation

```python
from app_kamerka.models import Playbook

Playbook.objects.create(
    name="My Programmatic Playbook",
    description="Created from a management command or fixture",
    steps=[
        {"tool": "screenshot", "order": 1, "exec_type": "chain"},
        {"tool": "honeypot",   "order": 2, "exec_type": "chain"},
    ],
)
```

---

## Target types

Currently playbooks target individual device IDs.  Future extension points:

- **Search**: run against all devices in a Search result.
- **Watchlist**: run against all devices matching a Watchlist query.
- **Queue**: run against a manually curated list stored in the session or DB.

These can be added by passing the relevant `device_ids` list to the run API
— the caller is responsible for resolving Search / Watchlist → device IDs
for now.
