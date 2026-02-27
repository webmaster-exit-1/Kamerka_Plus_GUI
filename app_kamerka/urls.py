from django.urls import path, include
from app_kamerka import views

urlpatterns = [
    path('', views.search_main, name='search_main'),
    path('index', views.index, name='index'),
    path('history', views.history, name='history'),
    path('map', views.map, name='map'),
    path('gallery', views.gallery, name='gallery'),

    path('devices', views.devices, name='devices'),
    path('sources', views.sources, name='sources'),

    path("results/<id>", views.results, name='results'),

    path("results/<id>/<device_id>/<ip>", views.device, name='device'),
    path('celery-progress/', include('celery_progress.urls')),
    path("<id>/nearby/<query>", views.nearby, name='nearby'),
    path("<id>/update_coordinates/<coordinates>", views.update_coordinates, name='update_coordinates'),

    path("<id>/wappalyzer/scan", views.wappalyzer_scan_view, name='wappalyzer_scan'),
    path("<id>/nuclei/scan", views.nuclei_scan_view, name='nuclei_scan'),
    path("get_wappalyzer_results/<id>", views.get_wappalyzer_results, name="get_wappalyzer_results"),
    path("get_nuclei_results/<id>", views.get_nuclei_results, name="get_nuclei_results"),
    path("<id>/rtsp/scan", views.rtsp_scan_view, name='rtsp_scan'),

    path("<id>/shodan/scan", views.shodan_scan, name='shodan_scan'),
    path('get-task-info/', views.get_task_info, name="get_task_info"),
    path('get_shodan_scan_results/<id>', views.get_shodan_scan_results, name="get_shodan_scan_results"),
    path('get_nearby_devices/<id>', views.get_nearby_devices, name="get_nearby_devices"),

    path('get_nearby_devices_coordinates/<id>', views.get_nearby_devices_coordinates,
         name="get_nearby_devices_coordinates"),
    path('get_binaryedge_score/<id>', views.get_binaryedge_score, name="get_binaryedge_score"),
    path('send_to_field_agent/<id>/<notes>', views.send_to_field_agent, name="send_to_field_agent"),
    path('get_binaryedge_score_results/<id>', views.get_binaryedge_score_results, name="get_binaryedge_score_results"),
    path('whois/<id>', views.whois, name="whois"),
    path('get_whois/<id>', views.get_whois, name="get_whois"),
    path('scan/<id>', views.scan_dev, name="scan"),
    path('exploit/<id>', views.exploit_dev, name="exploit"),

    path('export/csv/<id>', views.export_csv, name="export_csv"),
    path('export/kml/<id>', views.export_kml, name="export_kml"),
]
