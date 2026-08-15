from django.urls import path, include
from app_kamerka import views
from app_kamerka import hexstrike_views

urlpatterns = [
    path("", views.search_main, name="search_main"),
    path("index", views.index, name="index"),
    path("feeds-briefing", views.feeds_briefing, name="feeds_briefing"),
    path("history", views.history, name="history"),
    path("watchlists", views.watchlists, name="watchlists"),
    path("watchlists/<int:watchlist_id>/toggle", views.watchlist_toggle, name="watchlist_toggle"),
    path("watchlists/<int:watchlist_id>/delete", views.watchlist_delete, name="watchlist_delete"),
    path("watchlists/<int:watchlist_id>/run", views.watchlist_run_now, name="watchlist_run_now"),
    path("map", views.map, name="map"),
    path("gallery", views.gallery, name="gallery"),
    path("camera-wall", views.camera_wall, name="camera_wall"),
    path("search/<int:id>/camera-wall", views.camera_wall_search, name="camera_wall_search"),
    path("devices", views.devices, name="devices"),
    path("tasks", views.tasks_list, name="tasks_list"),
    path("tasks/<int:pk>", views.task_detail, name="task_detail"),
    path("bulk/run", views.bulk_run, name="bulk_run"),
    path("api/worker_status", views.worker_status_view, name="worker_status"),
    path("healthz/setup/", views.setup_check_view, name="setup_check"),
    path("sources", views.sources, name="sources"),
    path("results/<id>", views.results, name="results"),
    path("results/<id>/<device_id>/<ip>", views.device, name="device"),
    path("celery-progress/", include("celery_progress.urls")),
    path("<id>/nearby/<query>", views.nearby, name="nearby"),
    path(
        "<id>/update_coordinates/<coordinates>",
        views.update_coordinates,
        name="update_coordinates",
    ),
    path("<id>/wappalyzer/scan", views.wappalyzer_scan_view, name="wappalyzer_scan"),
    path("<id>/nuclei/scan", views.nuclei_scan_view, name="nuclei_scan"),
    path(
        "get_wappalyzer_results/<id>",
        views.get_wappalyzer_results,
        name="get_wappalyzer_results",
    ),
    path(
        "get_nuclei_results/<id>", views.get_nuclei_results, name="get_nuclei_results"
    ),
    path("<id>/rtsp/scan", views.rtsp_scan_view, name="rtsp_scan"),
    path("<id>/shodan/scan", views.shodan_scan, name="shodan_scan"),
    path("get-task-info/", views.get_task_info, name="get_task_info"),
    path(
        "get_shodan_scan_results/<id>",
        views.get_shodan_scan_results,
        name="get_shodan_scan_results",
    ),
    path(
        "get_nearby_devices/<id>", views.get_nearby_devices, name="get_nearby_devices"
    ),
    path(
        "get_nearby_devices_coordinates/<id>",
        views.get_nearby_devices_coordinates,
        name="get_nearby_devices_coordinates",
    ),
    path("whois/<id>", views.whois, name="whois"),
    path("get_whois/<id>", views.get_whois, name="get_whois"),
    path("scan/<id>", views.scan_dev, name="scan"),
    path("manual_nmap/<id>", views.manual_nmap_view, name="manual_nmap"),
    path("exploit/<id>", views.exploit_dev, name="exploit"),
    path("exploit/<device_id>/cve/<cve_id>", views.exploit_cve_view, name="exploit_cve"),
    path("exploit/<device_id>/cve/<cve_id>/info", views.exploit_info_view, name="exploit_info"),
    path("port_scan/<id>", views.port_scan_view, name="port_scan"),
    path("port_scan/ip/<target_ip>", views.port_scan_ip_view, name="port_scan_ip"),
    path("export/csv/<id>", views.export_csv, name="export_csv"),
    path("export/kml/<id>", views.export_kml, name="export_kml"),
    path("export/json/<id>", views.export_json, name="export_json"),
    path("map3d", views.map3d, name="map3d"),
    path("map3d/devices.geojson", views.map3d_devices_geojson, name="map3d_devices_geojson"),
    path("globe", views.globe, name="globe"),
    path("globe/devices.json", views.globe_devices_json, name="globe_devices_json"),
    # Deep Protocol Scan
    path("<id>/deep_scan", views.deep_scan_view, name="deep_scan"),
    path(
        "get_fingerprint_results/<id>",
        views.get_fingerprint_results,
        name="get_fingerprint_results",
    ),
    # Vulnerability Intelligence
    path("<id>/nvd/scan", views.nvd_scan_view, name="nvd_scan"),
    path("<id>/nrich/scan", views.nrich_scan_view, name="nrich_scan"),
    path("<id>/cvedb/enrich", views.cvedb_enrich_view, name="cvedb_enrich"),
    path("<id>/shodan/intel", views.shodan_intel_view, name="shodan_intel"),
    path("get_vuln_intel/<id>", views.get_vuln_intel, name="get_vuln_intel"),
    # Honeypot Analysis
    path("<id>/honeypot/scan", views.honeypot_scan_view, name="honeypot_scan"),
    path(
        "get_honeypot_result/<id>",
        views.get_honeypot_result,
        name="get_honeypot_result",
    ),
    # SBOM
    path("<id>/sbom/scan", views.sbom_scan_view, name="sbom_scan"),
    path("get_sbom_results/<id>", views.get_sbom_results, name="get_sbom_results"),
    # GFW Check
    path("<id>/gfw/check", views.gfw_check_view, name="gfw_check"),
    path("get_gfw_status/<id>", views.get_gfw_status, name="get_gfw_status"),
    # Device report export
    path("report/device/<id>", views.device_report_view, name="device_report"),
    # Screenshot Capture
    path("<id>/screenshot", views.screenshot_view, name="screenshot"),
    # ExploitDB Search
    path("<id>/exploitdb/search", views.exploitdb_search_view, name="exploitdb_search"),
    # Search Cost Estimate
    path("search_cost", views.search_cost_view, name="search_cost"),
    # Enhanced Globe Data
    path(
        "globe/devices_epss.json",
        views.globe_devices_epss_json,
        name="globe_devices_epss_json",
    ),
    # Metasploit & Recon-ng script generation
    path("<id>/msf/resource",    views.msf_resource_view,    name="msf_resource"),
    path("<id>/recon-ng/script", views.recon_ng_script_view, name="recon_ng_script"),
    # Shodan Trends
    path("<id>/shodan/trends",   views.shodan_trends_view,   name="shodan_trends"),
    # Shodan Credits
    path("shodan/credits",       views.shodan_credits_view,  name="shodan_credits"),
    # Enhanced GeoJSON export (Phase 7)
    path("api/export/geojson/<id>", views.export_geojson_enhanced, name="export_geojson_enhanced"),
    # Tool Plugin Registry API
    path("api/tools/", views.api_tools_list, name="api_tools_list"),
    path("api/tools/applicable/<int:device_id>/", views.api_tools_applicable, name="api_tools_applicable"),
    # Playbook CRUD + execution
    path("hexsploit/", hexstrike_views.hexsploit_view, name="hexsploit"),
    path("api/hexstrike/health/", hexstrike_views.hexstrike_health_api, name="hexstrike_health"),
    path("api/hexstrike/action/", hexstrike_views.hexstrike_action_api, name="hexstrike_action"),
    path("playbooks/", views.playbooks_list, name="playbooks_list"),
    path("playbooks/<int:pk>/", views.playbook_detail, name="playbook_detail"),
    path("api/playbooks/create/", views.playbook_create, name="playbook_create"),
    path("api/playbooks/<int:pk>/run/", views.playbook_run_view, name="playbook_run"),
]
