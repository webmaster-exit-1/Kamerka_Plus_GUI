"""Template context for Kamerka shell navigation."""


def kamerka_shell(request):
    path = (request.path or "").rstrip("/") or "/"
    nav_active = ""
    if path == "/":
        nav_active = "launch"
    elif path == "/index":
        nav_active = "overview"
    elif path.startswith("/feeds-briefing"):
        nav_active = "briefing"
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

    groups = [
        ("Investigate", [
            ("launch", "/", "New search", "search"),
            ("overview", "/index", "Overview", "desktop"),
            ("cases", "/history", "Cases", "folder-open"),
            ("devices", "/devices", "Device inventory", "th-list"),
        ]),
        ("Visualize", [
            ("map", "/map", "World map", "globe"),
            ("map3d", "/map3d", "3D map", "map"),
            ("camera", "/camera-wall", "Camera wall", "video-camera"),
            ("gallery", "/gallery", "Screenshots", "camera"),
            ("briefing", "/feeds-briefing", "Intelligence feeds", "rss"),
        ]),
        ("Operate", [
            ("tasks", "/tasks", "Task queue", "tasks"),
            ("playbooks", "/playbooks/", "Playbooks", "list-alt"),
            ("watchlists", "/watchlists", "Watchlists", "eye"),
            ("hexsploit", "/hexsploit/", "HexSploit", "bolt"),
        ]),
        ("System", [
            ("setup", "/healthz/setup/", "Setup checks", "check-circle"),
            ("sources", "/sources", "Intel sources", "book"),
        ]),
    ]
    navigation = [
        {"label": label, "items": [
            {"key": key, "url": url, "label": title, "icon": icon}
            for key, url, title, icon in items
        ]}
        for label, items in groups
    ]
    if active_case_id:
        for group in navigation:
            for item in group["items"]:
                if item["key"] == "map3d":
                    item["url"] += f"?search={active_case_id}"
    titles = {key: title for _, items in groups for key, _, title, _ in items}
    titles.update({"case": "Case workspace", "target": "Target workbench"})

    return {
        "nav_active": nav_active,
        "nav_title": titles.get(nav_active, "Investigation"),
        "navigation": navigation,
        "active_case_id": active_case_id,
        "active_target_url": active_target_url,
    }