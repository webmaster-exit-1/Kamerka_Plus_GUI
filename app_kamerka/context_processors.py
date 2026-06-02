"""Template context for Kamerka shell navigation."""


def kamerka_shell(request):
    path = (request.path or "").rstrip("/") or "/"
    nav_active = ""
    if path == "/":
        nav_active = "launch"
    elif path == "/index":
        nav_active = "overview"
    elif path.startswith("/history"):
        nav_active = "cases"
    elif path.startswith("/results"):
        nav_active = "case" if path.count("/") <= 2 else "target"
    elif path.startswith("/tasks"):
        nav_active = "tasks"
    elif path.startswith("/playbooks"):
        nav_active = "playbooks"
    elif path.startswith("/watchlists"):
        nav_active = "watchlists"
    elif path.startswith("/hexsploit"):
        nav_active = "hexsploit"
    elif path.startswith("/map3d") or path.startswith("/globe"):
        nav_active = "map3d"
    elif path.startswith("/map"):
        nav_active = "map"
    elif path.startswith("/camera-wall"):
        nav_active = "camera"
    elif path.startswith("/gallery"):
        nav_active = "gallery"
    elif path.startswith("/devices"):
        nav_active = "devices"
    elif path.startswith("/healthz/setup"):
        nav_active = "setup"
    elif path.startswith("/sources"):
        nav_active = "sources"

    active_case_id = None
    if hasattr(request, "session"):
        try:
            active_case_id = request.session.get("km_active_case_id")
        except Exception:
            active_case_id = None
    active_target_url = getattr(request, "km_active_target_url", None)

    return {
        "nav_active": nav_active,
        "active_case_id": active_case_id,
        "active_target_url": active_target_url,
    }