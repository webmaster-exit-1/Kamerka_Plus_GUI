import itertools
import json
import logging
import math
import re
import shutil
import socket
import subprocess

import maxminddb
from libnmap.parser import NmapParser
import os
from time import sleep
import requests
from celery import shared_task, current_task
from celery_progress.backend import ProgressRecorder
from shodan import Shodan
import shodan.helpers as shodan_helpers
import time
from bs4 import BeautifulSoup
import pynmea2
import base64
import xmltodict

from libnmap.process import NmapProcess

import urllib.parse
import urllib.request
import xml.etree.ElementTree as et

from app_kamerka import exploits

from app_kamerka.models import (
    Device,
    DeviceNearby,
    Search,
    ShodanScan,
    Whois,
    Bosch,
    WappalyzerResult,
    NucleiResult,
    ProtocolFingerprint,
    VulnIntelligence,
    HoneypotAnalysis,
    SBOMComponent,
    GFWStatus,
)
from django.conf import settings

logger = logging.getLogger(__name__)

healthcare_queries = {
    "zoll": "http.favicon.hash:-236942626",
    "dicom": "dicom",
    "perioperative": "HoF Perioperative",
    "wall_of_analytics": "title:'Wall of Analytics'",
    "viztek_exa": "X-Super-Powered-By: VIZTEK EXA",
    "medweb": "html:'DBA Medweb. All rights reserved.'",
    "intuitim": "http.favicon.hash:159662640",
    "medcon_archiving_system": "http.favicon.hash:-897903496",
    "orthanc_explorer": "title:'Orthanc Explorer'",
    "Marco Pacs": "title:'Marco pacs'",
    "osirix": "title:OsiriX",
    "clari_pacs": "title:ClariPACS",
    "siste_lab": "http.html:SisteLAB",
    "opalweb": "html:opalweb",
    "neuropro": "title:'EEG Laboratory'",
    "tmw_document_imaging": "title:'TMW Document Imaging'",
    "erez": "title:'eRez Imaging'",
    "gluco_care": "html:'GlucoCare igc'",
    "glucose_guide": "title:'glucose guide'",
    "grandmed_glucose": "title:'Grandmed Glucose'",
    "philips_digital_pathology": "title:'Philips Digital Pathology'",
    "tricore_pathology": "title:'TriCore Pathology'",
    "appsmart_ophthalmology": "title:'Appsmart Ophthalmology'",
    "chs_ophthalmology": "title:'CHS Ophthalmology'",
    "ram_soft": "html:powerreader",
    "xnat": "http.favicon.hash:-230640598",
    "iris_emr": "title:'Iris EMR'",
    "eclinicalworks_emr": "title:'Web EMR Login Page'",
    "open_emr": "http.favicon.hash:1971268439",
    "oscar_emr": "title:'OSCAR EMR'",
    "wm_emr": "http.favicon.hash:1617804812",
    "doctors_partner_emr": "title:'DoctorsPartner'",
    "mckesson_radiology": "title:'McKesson Radiology'",
    "kodak_carestream": "title:'Carestream PACS'",
    "meded": "title:meded",
    "centricity_radiology": "http.favicon.hash:-458315012",
    "openeyes": "http.favicon.hash:-885931907",
    "orthanc": "orthanc",
    "horos": "http.favicon.hash:398467600",
    "open_mrs": "title:openmrs",
    "mirth_connect": "http.favicon.hash:1502215759",
    "acuity_logic": "title:AcuityLogic",
    "optical_coherence_tomography": "title:'OCT Webview'",
    "philips_intellispace": "title:INTELLISPACE",
    "vitrea_intelligence": "title:'Vitrea intelligence'",
    "phenom_electron_microscope": "title:'Phenom-World'",
    "meddream_dicom_viewer": "html:Softneta",
    "merge_pacs": "http.favicon.hash:-74870968",
    "synapse_3d": "http.favicon.hash:394706326",
    "navify": "title:navify",
    "telemis_tmp": "http.favicon.hash:220883165",
    "brainlab": "title:'Brainlab Origin Server'",
    "nexus360": "http.favicon.hash:125825464",
    "brain_scope": "title:BrainScope",
    "omero_microscopy": "http.favicon.hash:2140687598",
    "meditech": "Meditech",
    "cynetics": "cynetics",
    "promed": "Promed",
    "carestream": "Carestream",
    "carestream_web": "title:Carestream",
    "vet_rocket": "http.html:'Vet Rocket'",
    "planmeca": "Planmeca",
    "vet_view": "http.favicon.hash:1758472204",
    "lumed": "http.html:'LUMED'",
    "infinitt": "http.favicon.hash:-255936262",
    "labtech": "labtech",
    "progetti": "http.html:'Progetti S.r.l.'",
    "qt_medical": "http.html:'QT Medical'",
    "aspel": "ASPEL",
    "huvitz_optometric": "http.html:'Huvitz'",
    "optovue": "Optovue",
    "optos_advance": "http.title:'OptosAdvance'",
    "asthma_monitoring_adamm": "http.title:'HCO Telemedicine'",
    "pregnabit": "http.html:'Pregnabit'",
    "prime_clinical_systems": "http.html:'Prime Clinical Systems'",
    "omni_explorer": "http.title:OmniExplorer",
    "avizia": "http.html:'Avizia'",
    "operamed": "Operamed",
    "early_sense": "http.favicon.hash:-639764351",
    "tunstall": "http.html:'Tunstall'",
    "clini_net": "http.html:'CliniNet®'",
    "intelesens": "title:'zensoronline)) - online monitoring'",
    "kb_port": "http.html:'KbPort'",
    "nursecall_message_service": "http.title:'N.M.S. - Nursecall Message Service'",
    "image_information_systems": "http.html:'IMAGE Information Systems'",
    "agilent_technologies": "Agilent Technologies port:5025",
    "praxis_portal2": "http.html:'Medigration'",
    "xero_viewer": "http.title:'XERO Viewer'",
    "dicom_port_104": '"DICOM Server Response" port:104',
    "hl7_fhir": 'title:"FHIR"',
    "ge_healthcare": '"GE Healthcare"',
    "philips_healthcare": '"Philips Healthcare"',
    "siemens_healthineers": '"Healthineers"',
    "dental_imaging": 'title:"Dental"',
    "radiant_dicom": 'title:"RadiAnt"',
    "baxter_infusion": '"Baxter"',
    "draeger_medical": '"Draeger"',
    "planmeca_romexis": 'title:"Romexis"',
}

ics_queries = {
    "niagara": "port:1911,4911 product:Niagara",
    "bacnet": '"Instance ID:" "Object Name:"',
    "modbus": "Unit ID: 0",
    "siemens": "Original Siemens Equipment Basic Firmware:",
    "dnp3": "port:20000 source address",
    "ethernetip": '"Product name:" "Vendor ID:"',
    "gestrip": 'port:18245,18246 product:"general electric"',
    "hart": "port:5094 hart-ip",
    "pcworx": "port:1962 PLC",
    "mitsubishi": "port:5006,5007 product:mitsubishi",
    "omron": "port:9600 response code",
    "redlion": 'port:789 product:"Red Lion Controls"',
    "codesys": 'product:"3S-Smart Software Solutions"',
    "iec": "port:2404 asdu address",
    "proconos": "port:20547 PLC",
    "plantvisor": "Server: CarelDataServer",
    "iologik": "iologik",
    "moxa": "Moxa",
    "akcp": "Server: AKCP Embedded Web Server",
    "spidercontrol": "powered by SpiderControl TM",
    "tank": "port:10001 tank",
    "iq3": "Server: IQ3",
    "is2": "IS2 Web Server",
    "vtscada": "Server: VTScada",
    "zworld": "Z-World Rabbit 200 OK",
    "nordex": "html:nordex",
    "sailor": "title:Sailor title:VSAT",
    "nmea": "$GPGGA",
    "axc": "PLC Type: AXC",
    "modicon": "modicon",
    "xp277": "HMI, XP277",
    "vxworks": "vxworks",
    "eig": "EIG Embedded Web Server",
    "digi": "TransPort WR21",
    "windweb": "server: WindWeb",
    "moxahttp": "MoxaHttp",
    "lantronix": "lantronix",
    "entelitouch": "Server: DELTA enteliTOUCH",
    "energyict_rtu": "EnergyICT RTU",
    "crestron": "crestron",
    "saphir": 'Server: "Microsoft-WinCE" "Content-Length: 12581"',
    "ipc@chip": "IPC@CHIP",
    "addup": "addUPI",
    "anybus": '"anybus-s"',
    "windriver": "WindRiver-WebServer",
    "wago": "wago",
    "niagara_audit": "niagara_audit",
    "niagara_web_server": "Niagara Web Server",
    "trendnet": "trendnet",
    "stulz_klimatechnik": "Stulz GmbH Klimatechnik",
    "somfy": "title:Somfy",
    "scalance": "scalance",
    "simatic": "simatic",
    "simatic_s7": "Portal0000",
    "schneider_electric": "Schneider Electric",
    "power_measurement": "Power Measurement Ltd",
    "power_logic": "title:PowerLogic",
    "telemecanique_bxm": "TELEMECANIQUE BMX",
    "schneider_web": "Schneider-WEB",
    "fujitsu_serverview": "serverview",
    "eiportal": "eiPortal",
    "ilon": "i.LON",
    "webvisu": "Webvisu",
    "total_access": "ta gen3 port:2000",
    "vantage_infusion": "http.html:'InFusion Controller'",
    "sensoteq": "title:'sensoteq'",
    "sicon-8": "sicon-8",
    "automation_direct_hmi": "Server: EA-HTTP/1.0",
    "flotrac": "FloTrac",
    "innotech_bms": "http.title:'Innotech BMS'",
    "skylog": "http.title:skylog",
    "miele@home": "title:Miele@home",
    "alphacom": "http.title:Alphacom",
    "simplex_grinnell": "http.html:SimplexGrinnell title:login",
    "bosch_security": "http.html:'Bosch Security'",
    "other_hmi": "html:hmiBody",
    "fronius": "title:fronius",
    "webview": "http.favicon.hash:207964650",
    "Siemens Sm@rtClient": "title:'Siemens Sm@rtClient'",
    "WAGO": "title:'wago ethernet'",
    "sensatronics": "html:sensatronics",
    "extron": "Extron Electronics",
    "mikrotik_streetlighs": "mikrotik streetlight",
    "kesseltronics": "Kesseltronics",
    "unitronics": "title:'Unitronics PLC'",
    "atvise": "Server: atvise",
    "clearSCADA": "ClearSCADA",
    "youless": "title:YouLess",
    "DLILPC": "DLILPC",
    "intelliSlot": "title:IntelliSlot",
    "temperature_monitor": "title:'Temperature Monitor' !title:avtech",
    "CirCarLife": "CirCarLife -ASUSTeK",
    "web_scada": "title:'web scada'",
    "kaco": "kaco",
    "indect_parkway": "title:indect",
    "intuitive_Controller": "http.favicon.hash:1434282111",
    "intuitive_controller_2": "http.favicon.hash:-1011909571",
    "homeLYnk": "homeLYnk",
    "APC": "Location: home.htm Content-Length: 0 WebServer",
    "netio": "title:netio",
    "asi_controls": "title:'ASI Controls'",
    "myscada": "title:myscada",
    "iB-COM": "title:iB-COM",
    "building_operation_webstation": "title:'building operation'",
    "ftp_scada": "scada login",
    "apc_ftp": "APC FTP server",
    "network_management_card": "Network Management Card",
    "wemo_insight": "Belkin WeMo",
    "connect_ups": "title:ConnectUPS",
    "upshttpd": "Server: upshttpd",
    "poweragent": "PowerAgent",
    "CS121": "title:'CS121 SNMP/Web Adapter'",
    "ab_ethernet": "cspv4",
    "climatix": "Siemens Building Technologies Climatix",
    "bas_scada": "BAS SCADA Service",
    "watt_router": "SOLAR controls product server",
    "doors": '"HID VertX" port:4070',
    "saferoads": "Saferoads VMS",
    "xzeres": 'title:"XZERES Wind"',
    "doorbird": "html:DoorBird",
    "jeedom": 'title:"Jeedom"',
    "pwrctrl": '"NET-PwrCtrl"',
    "heatmiser_thermostat": 'title:"Heatmiser Wifi Thermostat"',
    "xpanel": "title:xpanel",
    "c4_max": "[1m[35mWelcome on console",
    "universal_devices": "ucos",
    "dasdec": "dasdec",
    "brightsign": 'title:"BrightSign&reg;"',
    "leica": "title:leica title:interface",
    "hughesnet": "html:hughesnet",
    "skyline": "'server: skyline'",
    "beward_door": "'DS06A(P) SIP Door Station'",
    "wallbox": "title:wallbox",
    "acadia": "acadia",
    "walchem": "html:walchem",
    "gnss": "'NTRIP' 'SOURCETABLE'",
    "traccar": "title:traccar",
    "trimble": 'html:"trimble Navigation"',
    "spacelynk": "title:spaceLYnk",
    # --- ABB ---
    "abb_ac800m": 'title:"ABB AC 800M"',
    "abb_rtu560": '"ABB RTU560"',
    "abb_srea": '"SREA-01"',
    # --- Rockwell / Allen-Bradley ---
    "rockwell_micrologix": '"Rockwell Automation" "MicroLogix"',
    "allen_bradley": '"Allen-Bradley"',
    # --- GE Industrial ---
    "ge_cimplicity": 'title:"CIMPLICITY"',
    "ge_proficy": '"Proficy HMI/SCADA"',
    # --- Siemens models ---
    "siemens_s7_200": '"S7-200"',
    "siemens_s7_300": '"S7-300"',
    "siemens_s7_1200": '"S7-1200"',
    "siemens_s7_1500": '"S7-1500"',
    # --- Schneider models ---
    "schneider_citectscada": '"CitectSCADA"',
    "schneider_modicon_m340": '"Modicon M340"',
    "schneider_egx300": '"EGX300"',
    "schneider_tsxety": '"TSXETY"',
    # --- Honeywell ---
    "honeywell_xl_web": '"Honeywell" "XL Web"',
    "honeywell_falcon": '"Honeywell" "Falcon"',
    # --- Phoenix Contact ---
    "phoenix_ilc": '"ILC 150"',
    # --- Mitsubishi ---
    "mitsubishi_melsec": '"MELSEC-Q"',
    # --- Moxa ---
    "moxa_oncell": '"OnCell"',
    "moxa_nport": '"NPort" "Moxa"',
    # --- Other ICS vendors ---
    "cimetrics": '"Cimetrics Eplus Web Server"',
    "delta_controls": '"Delta Controls"',
    "carel_pcoweb": '"pCOWeb"',
    "veeder_root_tls": '"Veeder-Root" port:10001',
    "adcon_telemetry": '"adcon Telemetry"',
    # --- Energy ---
    "sma_solar_inverter": 'title:"SMA Solar Inverter"',
    "enercon_wind": 'title:"ENERCON"',
    # --- Transportation / Smart City ---
    "samsung_billboard": '"Server: Prismview Player"',
    "gas_station_pump": '"in-tank inventory" port:10001',
    "anpr_alpr": 'P372 "ANPR enabled"',
    "tesla_powerpack": 'http.title:"Tesla PowerPack System"',
    "ev_charger": '"Server: gSOAP/2.8" "Content-Length: 583"',
    "railroad_management": 'title:"Railroad Management"',
    # --- BMS / HVAC ---
    "tridium_niagara4": '"Niagara 4"',
    "carrier_i_vu": 'title:"Carrier i-Vu"',
    "automated_logic": 'title:"Automated Logic WebCTRL"',
    "tracer_sc": 'title:"Tracer SC"',
    # --- MQTT ---
    "mqtt_1883": "product:MQTT port:1883",
    "mqtt_8883": "product:MQTT port:8883",
}

coordinates_queries = {
    "videoiq": 'title:"VideoIQ Camera Login"',
    "hikvision": 'product:"Hikvision IP Camera"',
    "webcam": "device:webcam",
    "webcamxp": "webcamxp",
    "vivotek": "vivotek",
    "netwave": 'product:"Netwave IP camera http config"',
    "techwin": "techwin",
    "lutron": "html:<h1>LUTRON</h1>",
    "mobotix": "mobotix",
    "iqinvision": "iqinvision",
    "grandstream": 'ssl:"Grandstream" "Set-Cookie: TRACKID"',
    "amcrest": 'html:"@WebVersion@" html:amcrest',
    "contec": '"content/smarthome.php"',
    "printer": "device:printer",
    "mqtt": "product:mqtt",
    "rtsp": "port:'554'",
    "ipcamera": "IPCamera_Logo",
    "yawcam": "yawcam",
    "blueiris": "http.favicon.hash:-520888198",
    "ubnt": "UBNT Streaming Server",
    "go1984": "go1984",
    "dlink": "Server: Camera Web Server",
    "avtech": "linux upnp avtech",
    "adh": "ADH-web",
    "axis": 'http.title:"axis" http.html:live',
    "rdp": "has_screenshot:true port:3389",
    "vnc": "has_screenshot:true port:5901",
    "screenshot": "has_screenshot:true !port:3389 !port:3388 !port:5900",
    "bbvs": "Server: BBVS",
    "baudisch": "http.favicon.hash:746882768",
    "loxone_intercom": "title:'Loxone Intercom Video'",
    "idss": "Intelligent Digital Security System",
    "webiopi": "webiopi 200 ok",
    "iobroker": "ioBroker.admin",
    "comelit": "html:comelit",
    "niagara": "port:1911,4911 product:Niagara",
    "bacnet": '"Instance ID:" "Object Name:"',
    "modbus": "Unit ID: 0",
    "siemens": "Original Siemens Equipment Basic Firmware:",
    "dnp3": "port:20000 source address",
    "ethernetip": '"Product name:" "Vendor ID:"',
    "gestrip": 'port:18245,18246 product:"general electric"',
    "hart": "port:5094 hart-ip",
    "pcworx": "port:1962 PLC",
    "mitsubishi": "port:5006,5007 product:mitsubishi",
    "omron": "port:9600 response code",
    "redlion": 'port:789 product:"Red Lion Controls"',
    "codesys": "port:2455 operating system",
    "iec": "port:2404 asdu address",
    "proconos": "port:20547 PLC",
    "plantvisor": "Server: CarelDataServer",
    "iologik": "iologik",
    "moxa": "Moxa",
    "akcp": "Server: AKCP Embedded Web Server",
    "spidercontrol": "powered by SpiderControl TM",
    "tank": "port:10001 tank",
    "iq3": "Server: IQ3",
    "is2": "IS2 Web Server",
    "vtscada": "Server: VTScada",
    "zworld": "Z-World Rabbit",
    "nordex": "html:nordex",
    "axc": "PLC Type: AXC",
    "modicon": "modicon",
    "xp277": "HMI, XP277",
    "vxworks": "vxworks",
    "eig": "EIG Embedded Web Server",
    "digi": "TransPort WR21",
    "windweb": "server: WindWeb",
    "moxahttp": "MoxaHttp",
    "lantronix": "lantronix",
    "entelitouch": "Server: DELTA enteliTOUCH",
    "energyict_rtu": "EnergyICT RTU",
    "crestron": "crestron",
    "wince": 'Server: "Microsoft-WinCE"',
    "ipc@chip": "IPC@CHIP",
    "addup": "addUPI",
    "anybus": '"anybus-s"',
    "windriver": "WindRiver-WebServer",
    "wago": "wago",
    "niagara_audit": "niagara_audit",
    "niagara_web_server": "Niagara Web Server",
    "trendnet": "trendnet",
    "stulz_klimatechnik": "Stulz GmbH Klimatechnik",
    "somfy": "title:Somfy",
    "scalance": "scalance",
    "simatic": "simatic",
    "simatic_s7": "Portal0000",
    "schneider_electric": "Schneider Electric",
    "power_measurement": "Power Measurement Ltd",
    "power_logic": "title:PowerLogic",
    "telemecanique_bxm": "TELEMECANIQUE BMX",
    "schneider_web": "Schneider-WEB",
    "fujitsu_serverview": "serverview",
    "eiportal": "eiPortal",
    "ilon": "i.LON",
    "Webvisu": "Webvisu",
    "total_access": "ta gen3 port:2000",
    "vantage_infusion": "http.html:'InFusion Controller'",
    "sensoteq": "title:'sensoteq'",
    "sicon-8": "sicon-8",
    "automation_direct_hmi": "Server: EA-HTTP/1.0",
    "flotrac": "FloTrac",
    "innotech_bms": "http.title:'Innotech BMS'",
    "skylog": "http.title:skylog",
    "miele@home": "title:Miele@home",
    "alphacom": "http.title:Alphacom",
    "simplex_grinnell": "http.html:SimplexGrinnell title:login",
    "bosch_security": "http.html:'Bosch Security'",
    "fronius": "title:fronius",
    "webview": "http.favicon.hash:207964650",
    "siemens_Sm@rtClient": "title:'Siemens Sm@rtClient'",
    "WAGO": "title:'wago ethernet'",
    "sensatronics": "html:sensatronics",
    "extron": "Extron Electronics",
    "mikrotik_streetlighs": "mikrotik streetlight",
    "kesseltronics": "Kesseltronics",
    "unitronics": "title:'Unitronics PLC'",
    "atvise": "Server: atvise",
    "clearSCADA": "ClearSCADA",
    "youless": "title:YouLess",
    "DLILPC": "DLILPC",
    "intelliSlot": "title:IntelliSlot",
    "temperature_monitor": "title:'Temperature Monitor' !title:avtech",
    "CirCarLife": "CirCarLife",
    "web_scada": "title:'web scada'",
    "kaco": "kaco",
    "indect_parkway": "title:indect",
    "intuitive_Controller": "http.favicon.hash:1434282111",
    "intuitive_controller_2": "http.favicon.hash:-1011909571",
    "homeLYnk": "homeLYnk",
    "APC": "Location: home.htm Content-Length: 0 WebServer",
    "netio": "title:netio",
    "asi_controls": "title:'ASI Controls'",
    "myscada": "title:myscada",
    "iB-COM": "title:iB-COM",
    "building_operation_webstation": "title:'building operation'",
    "ftp_scada": "scada login",
    "apc_ftp": "APC FTP server",
    "network_management_card": "Network Management Card",
    "wemo_insight": "Belkin WeMo",
    "connect_ups": "title:ConnectUPS",
    "upshttpd": "Server: upshttpd",
    "poweragent": "PowerAgent",
    "CS121": "title:'CS121 SNMP/Web Adapter'",
    "ab_ethernet": "cspv4",
    "climatix": "Siemens Building Technologies Climatix",
    "bas_scada": "BAS SCADA Service",
    "watt_router": "SOLAR controls product server",
    "doors": '"HID VertX" port:4070',
    "saferoads": "Saferoads VMS",
    "xzeres": 'title:"XZERES Wind"',
    "doorbird": "html:DoorBird",
    "jeedom": 'title:"Jeedom"',
    "pwrctrl": "NET-PwrCtrl",
    "heatmiser_thermostat": 'title:"Heatmiser Wifi Thermostat"',
    "xpanel": "title:xpanel",
    "c4_max": "[1m[35mWelcome on console",
    "universal_devices": "ucos",
    "dasdec": "dasdec",
    "brightsign": 'title:"BrightSign&reg;"',
    "leica": "title:leica title:interface",
    "hughesnet": "html:hughesnet",
    "skyline": "server: skyline",
    "beward_door": "DS06A(P) SIP Door Station",
    "wallbox": "http.title:wallbox",
    "acadia": "acadia",
    "walchem": "html:walchem",
    "gnss": '"NTRIP" "SOURCETABLE"',
    "traccar": "title:traccar",
    "trimble": 'html:"trimble Navigation"',
    "spacelynk": "title:spaceLYnk",
    # --- Cameras / DVR ---
    "dahua": 'http.title:"Dahua"',
    "foscam": 'title:"Foscam"',
    "reolink": 'title:"Reolink"',
    "flir": 'title:"FLIR"',
    "android_ip_webcam": '"Server: IP Webcam Server"',
    "dvr_h264": 'html:"DVR_H264 ActiveX"',
    "geovision": 'title:"GeoVision"',
    "acti": 'title:"ACTi"',
    "tplink_cam": '"TP-LINK IP-Camera"',
    # --- NAS ---
    "synology_nas": 'http.title:"Synology DiskStation"',
    "qnap_nas": 'http.title:"QNAP"',
    "western_digital_nas": 'title:"My Cloud"',
    # --- Smart Home ---
    "chromecast": '"Chromecast" port:8008',
    "home_assistant": 'title:"Home Assistant"',
    "samsung_tv": '"Samsung AllShare" port:7676',
    "roku": '"Roku" port:8060',
    "sonos": '"Sonos" port:1400',
    # --- Network / IoT ---
    "docker_api": '"Docker Containers:" port:2375',
    "pi_hole": 'title:"Pi-hole Admin Console"',
    "unprotected_vnc": '"authentication disabled" "RFB 003.008"',
    "android_adb": '"Android Debug Bridge" port:5555',
    "elasticsearch": "product:Elastic port:9200",
    "mongodb": 'product:"MongoDB"',
    "couchdb": 'product:"CouchDB"',
    "redis": "product:Redis",
    "memcached": "product:Memcached port:11211",
    # --- ICS (mirror) ---
    "abb_ac800m": 'title:"ABB AC 800M"',
    "abb_rtu560": '"ABB RTU560"',
    "abb_srea": '"SREA-01"',
    "rockwell_micrologix": '"Rockwell Automation" "MicroLogix"',
    "allen_bradley": '"Allen-Bradley"',
    "ge_cimplicity": 'title:"CIMPLICITY"',
    "ge_proficy": '"Proficy HMI/SCADA"',
    "siemens_s7_200": '"S7-200"',
    "siemens_s7_300": '"S7-300"',
    "siemens_s7_1200": '"S7-1200"',
    "siemens_s7_1500": '"S7-1500"',
    "schneider_citectscada": '"CitectSCADA"',
    "schneider_modicon_m340": '"Modicon M340"',
    "schneider_egx300": '"EGX300"',
    "schneider_tsxety": '"TSXETY"',
    "honeywell_xl_web": '"Honeywell" "XL Web"',
    "honeywell_falcon": '"Honeywell" "Falcon"',
    "phoenix_ilc": '"ILC 150"',
    "mitsubishi_melsec": '"MELSEC-Q"',
    "moxa_oncell": '"OnCell"',
    "moxa_nport": '"NPort" "Moxa"',
    "cimetrics": '"Cimetrics Eplus Web Server"',
    "delta_controls": '"Delta Controls"',
    "carel_pcoweb": '"pCOWeb"',
    "veeder_root_tls": '"Veeder-Root" port:10001',
    "adcon_telemetry": '"adcon Telemetry"',
    "sma_solar_inverter": 'title:"SMA Solar Inverter"',
    "enercon_wind": 'title:"ENERCON"',
    "samsung_billboard": '"Server: Prismview Player"',
    "gas_station_pump": '"in-tank inventory" port:10001',
    "anpr_alpr": 'P372 "ANPR enabled"',
    "tesla_powerpack": 'http.title:"Tesla PowerPack System"',
    "ev_charger": '"Server: gSOAP/2.8" "Content-Length: 583"',
    "railroad_management": 'title:"Railroad Management"',
    "tridium_niagara4": '"Niagara 4"',
    "carrier_i_vu": 'title:"Carrier i-Vu"',
    "automated_logic": 'title:"Automated Logic WebCTRL"',
    "tracer_sc": 'title:"Tracer SC"',
    "mqtt_1883": "product:MQTT port:1883",
    "mqtt_8883": "product:MQTT port:8883",
}

attackers_infra_queries = {
    "cobaltstrike": 'product:"Cobalt Strike Beacon"',
    "msf": "ssl:MetasploitSelfSignedCA",
    "covenant": 'ssl:"Covenant" http.component:"Blazor"',
    "mythic": 'ssl:"Mythic" port:7443',
    "bruteratel": "http.html_hash:-1957161625",
    "sliver": "ssl:multiplayer ssl:operators",
    "havoc": "http.favicon.hash:2066823248",
    "posh_c2": 'ssl:"PoshC2"',
    "deimos_c2": 'ssl:"DeimosC2"',
    "merlin_c2": 'ssl:"Merlin" port:443',
    "nighthawk_c2": 'ssl:"nighthawk"',
    "nimplant": 'ssl:"NimPlant"',
    "villain_c2": 'ssl:"Villain"',
}


def _get_env_key(name, *, required=False):
    """Return an environment variable value.

    Checks ``os.environ`` first.  For ``SHODAN_API_KEY`` specifically, falls
    back to ``django.conf.settings.SHODAN_API_KEY`` so the value set at
    Django/Celery *startup* is reused without needing the variable to be
    re-exported in every new terminal.

    Logs a warning when a key that is marked *required* is missing so that
    operators know immediately which variable to set, without crashing the
    whole worker on startup.
    """
    from django.conf import settings as _django_settings

    value = os.environ.get(name, "")
    if not value:
        # Fall back to the value resolved when Django started
        value = getattr(_django_settings, name, "") or ""
    if required and not value:
        logger.warning(
            "Environment variable %s is not set. "
            "Features that depend on it will fail at runtime. "
            "Set it in your shell (e.g. 'export %s=...') and restart "
            "the Celery worker, or add it to ~/.bashrc for persistence.",
            name,
            name,
        )
    return value


@shared_task(bind=False)
def devices_nearby(lat, lon, id, query):
    SHODAN_API_KEY = _get_env_key("SHODAN_API_KEY", required=True)

    device = Device.objects.get(id=id)

    api = Shodan(SHODAN_API_KEY)
    fail = 0
    # Shodan sometimes fails with no reason, sleeping when it happens and it prevents rate limitation
    try:
        # Search Shodan
        results = api.search("geo:" + lat + "," + lon + ",15 " + query)
    except Exception as exc:
        fail = 1
        logger.warning("devices_nearby: Shodan search failed (attempt 1): %s", exc)

    if fail == 1:
        try:
            results = api.search("geo:" + lat + "," + lon + ",15 " + query)
        except Exception as e:
            logger.warning("devices_nearby: Shodan search failed (attempt 2): %s", e)

    try:  # Show the results
        total = len(results["matches"])
        for counter, result in enumerate(results["matches"]):
            if "product" in result:
                product = result["product"]
            else:
                product = ""
            current_task.update_state(
                state="PROGRESS",
                meta={
                    "current": counter,
                    "total": total,
                    "percent": int((float(counter) / total) * 100),
                },
            )
            device1 = DeviceNearby(
                device=device,
                ip=result["ip_str"],
                product=product,
                org=result["org"],
                port=str(result["port"]),
                lat=str(result["location"]["latitude"]),
                lon=str(result["location"]["longitude"]),
            )
            device1.save()

        return {"current": total, "total": total, "percent": 100}
    except Exception as e:
        logger.warning("%s", e)


@shared_task(bind=True)
def shodan_search(
    self,
    fk,
    country=None,
    coordinates=None,
    ics=None,
    healthcare=None,
    coordinates_search=None,
    all_results=False,
    infra=None,
):
    progress_recorder = ProgressRecorder(self)
    result = 0
    if country:
        total = len(ics)
        for c, i in enumerate(ics):
            if healthcare:
                if i in healthcare_queries:
                    print(i)
                    try:
                        result += c
                        shodan_search_worker(
                            country=country,
                            fk=fk,
                            query=healthcare_queries[i],
                            search_type=i,
                            category="healthcare",
                            all_results=all_results,
                        )
                        progress_recorder.set_progress(c + 1, total=total)
                    except Exception:
                        pass
            else:

                if i in ics_queries:
                    try:
                        result += c
                        shodan_search_worker(
                            country=country,
                            fk=fk,
                            query=ics_queries[i],
                            search_type=i,
                            category="ics",
                            all_results=all_results,
                        )
                        progress_recorder.set_progress(c + 1, total=total)
                    except Exception:
                        pass

                if i in attackers_infra_queries:
                    try:
                        result += c
                        shodan_search_worker(
                            country=country,
                            fk=fk,
                            query=attackers_infra_queries[i],
                            search_type=i,
                            category="infra",
                            all_results=all_results,
                        )
                        progress_recorder.set_progress(c + 1, total=total)
                    except Exception as e:
                        logger.warning("%s", e)

    if coordinates:
        total = len(coordinates_search)
        for c, i in enumerate(coordinates_search):
            # print(coordinates_search[i])
            if i in coordinates_queries:
                try:
                    result += c
                    shodan_search_worker(
                        fk=fk,
                        query=coordinates_queries[i],
                        search_type=i,
                        category="coordinates",
                        coordinates=coordinates,
                        all_results=all_results,
                    )
                    progress_recorder.set_progress(c + 1, total=total)
                except Exception:
                    pass
    return result


def check_credits():
    keys_list = []
    try:
        SHODAN_API_KEY = _get_env_key("SHODAN_API_KEY", required=True)
        if not SHODAN_API_KEY:
            logger.warning(
                "check_credits: SHODAN_API_KEY is empty — cannot check credits. "
                "Set it in your shell (e.g. 'export SHODAN_API_KEY=...')."
            )
            return keys_list

        api = Shodan(SHODAN_API_KEY)
        a = api.info()
        keys_list.append(a["query_credits"])
    except Exception as e:
        logger.warning("check_credits: Shodan API call failed: %s", e)

    return keys_list


def _shodan_download_path(search_id):
    """Return the path to the raw Shodan banner download file for a search.

    The file is a gzipped NDJSON (``.json.gz``) in the format written by
    ``shodan download`` and understood by ``shodan convert`` and all Shodan
    converter classes (CsvConverter, KmlConverter, GeoJsonConverter).

    The directory is created on first use so callers do not need to check.
    """
    from django.conf import settings

    downloads_dir = os.path.join(settings.BASE_DIR, "shodan_downloads")
    os.makedirs(downloads_dir, exist_ok=True)
    return os.path.join(downloads_dir, "{}.json.gz".format(search_id))


def shodan_search_worker(
    fk, query, search_type, category, country=None, coordinates=None, all_results=False
):
    results = True
    page = 1
    SHODAN_API_KEY = _get_env_key("SHODAN_API_KEY", required=True)
    screenshot = ""
    print(query)

    # ── Build the Shodan query string ──────────────────────────────────
    if coordinates:
        query_string = "geo:{},20 {}".format(coordinates, query)
    elif country == "XX":
        query_string = query
    else:
        query_string = "country:{} {}".format(country, query)

    search = Search.objects.get(id=fk)
    api = Shodan(SHODAN_API_KEY)

    # ── "shodan download" step ─────────────────────────────────────────
    # Use search_cursor (the Python equivalent of `shodan download`) which
    # handles paging automatically and respects Shodan's rate limits
    # internally (retries=5 by default).
    #
    # When all_results=False we mirror the old behaviour of only collecting
    # the first page (~100 results).  When True we stream everything.
    download_path = _shodan_download_path(fk)
    cursor = api.search_cursor(query_string, minify=False)
    if not all_results:
        cursor = itertools.islice(cursor, 100)

    try:
        fout = shodan_helpers.open_file(download_path)  # append to existing file
        for result in cursor:
            # ── "shodan download" — persist raw banner ─────────────────
            shodan_helpers.write_banner(fout, result)

            # ── Parse into Device record (existing app logic) ──────────
            lat = str(result["location"]["latitude"])
            lon = str(result["location"]["longitude"])
            city = ""
            indicator = []

            # product: use the dedicated field when present; fall back to
            # http.server (e.g. "GoAhead-Webs", "Apache", "nginx") so that
            # banners without an explicit product still get a meaningful name.
            try:
                product = result["product"]
            except Exception:
                product = result.get("http", {}).get("server", "") or ""

            if "vulns" in result:
                vulns = [*result["vulns"]]
            else:
                vulns = ""

            # isp: often differs from org (e.g. org="Aliyun" isp="Alibaba Ad Co")
            isp = result.get("isp", "") or ""

            # cpe: first CPE 2.3 string from the cpe23 list, e.g.
            # "cpe:2.3:a:embedthis:goahead" — useful for CVE correlation.
            cpe_list = result.get("cpe23") or result.get("cpe") or []
            cpe = cpe_list[0] if cpe_list else ""

            if result["location"]["city"] is not None:
                city = result["location"]["city"]

            hostnames = ""
            try:
                if "hostnames" in result:
                    hostnames = result["hostnames"][0]
            except Exception:
                pass

            try:
                if "SAILOR" in result["http"]["title"]:
                    html = result["http"]["html"]
                    soup = BeautifulSoup(html)
                    for gps in soup.find_all("span", {"id": "gnss_position"}):
                        _coord = gps.contents[0]
                        space = _coord.split(" ")
                        if "W" in space:
                            lon = "-" + space[2][:-1]
                        else:
                            lon = space[2][:-1]
                        lat = space[0][:-1]
            except Exception:
                pass

            if "opts" in result:
                try:
                    screenshot = result["opts"]["screenshot"]["data"]
                    with open(
                        "app_kamerka/static/images/screens/"
                        + result["ip_str"]
                        + ".jpg",
                        "wb",
                    ) as fh:
                        fh.write(base64.b64decode(screenshot))
                    for i in result["opts"]["screenshot"]["labels"]:
                        indicator.append(i)
                except Exception:
                    pass

            if query == "Niagara Web Server":
                try:
                    soup = BeautifulSoup(result["http"]["html"], features="html.parser")
                    nws = soup.find("div", {"class": "top"})
                    indicator.append(nws.contents[0])
                except Exception:
                    pass

            if "SOURCETABLE" in query:
                data = result["data"].split(";")
                try:
                    if re.match(r"^((\-?|\+?)?\d+(\.\d+)?)$", data[9]):
                        indicator.append(data[9] + "," + data[10])
                        lat = data[9]
                        lon = data[10]
                except Exception:
                    pass

            # get indicator from niagara fox
            if result["port"] == 1911 or result["port"] == 4911:
                try:
                    fox_data_splitted = result["data"].split("\n")
                    for i in fox_data_splitted:
                        if "station.name" in i:
                            splitted = i.split(":")
                            indicator.append(splitted[1])
                except Exception:
                    pass

            # get indicator from tank
            if result["port"] == 10001 and "Siemens" not in query:
                try:
                    tank_info = result["data"].split("\r\n\r\n")
                    indicator.append(tank_info[1])
                except Exception:
                    pass

            if result["port"] == 2000:
                try:
                    ta_data = result["data"].split("\\n")
                    indicator.append(ta_data[1][:-3])
                except Exception:
                    pass

            if result["port"] == 502:
                try:
                    sch_el = result["data"].split("\n")
                    if sch_el[4].startswith("-- Project"):
                        indicator.append(sch_el[4].split(": ")[1])
                except Exception:
                    pass

            if "GPGGA" in result["data"]:
                try:
                    splitted_data = result["data"].split("\n")
                    for i in splitted_data:
                        if "GPGGA" in i:
                            msg = pynmea2.parse(i)
                            lat = msg.latitude
                            lon = msg.longitude
                            break
                except Exception:
                    pass

            if result["port"] == 102:
                try:
                    s7_data = result["data"].split("\n")
                    for i in s7_data:
                        if i.startswith("Plant"):
                            indicator.append(i.split(":")[1])
                        if i.startswith("PLC"):
                            indicator.append(i.split(":")[1])
                        if i.startswith("Module name"):
                            indicator.append(i.split(":")[1])
                except Exception:
                    pass

            # get indicator from bacnet
            if result["port"] == 47808:
                try:
                    bacnet_data_splitted = result["data"].split("\n")
                    for i in bacnet_data_splitted:
                        if "Description" in i:
                            splitted1 = i.split(":")
                            indicator.append(splitted1[1])
                        if "Object Name" in i:
                            splitted2 = i.split(":")
                            indicator.append(splitted2[1])
                        if "Location" in i:
                            splitted3 = i.split(":")
                            indicator.append(splitted3[1])
                except Exception:
                    pass

            device = Device(
                search=search,
                ip=result["ip_str"],
                product=product,
                org=result["org"],
                data=result["data"],
                port=str(result["port"]),
                type=search_type,
                city=city,
                lat=lat,
                lon=lon,
                country_code=result["location"]["country_code"],
                query=search_type,
                category=category,
                vulns=vulns,
                indicator=indicator,
                hostnames=hostnames,
                screenshot=screenshot,
                isp=isp,
                cpe=cpe,
            )
            device.save()

        fout.close()
    except Exception as exc:
        logger.warning(
            "shodan_search_worker: error during search/download for '%s': %s",
            query_string,
            exc,
        )


def nmap_host_worker(host_arg, max_reader, search):
    ports_list = []
    hostname = host_arg.hostnames[0] if host_arg.hostnames else ""

    a = max_reader.get(host_arg.address)
    if a is None:
        logger.warning("MaxMind lookup returned no result for IP: %s", host_arg.address)
        a = {}
    location = a.get("location") or {}
    lat = location.get("latitude")
    lon = location.get("longitude")
    if lat is None or lon is None:
        logger.warning(
            "Missing latitude/longitude in MaxMind data for IP: %s", host_arg.address
        )
    country = a.get("country") or {}
    country_code = country.get("iso_code", "")
    logger.debug("lat=%s lon=%s", lat, lon)
    for ports in host_arg.services:
        if ports.state == "open":
            ports_list.append(ports.port)
        else:
            ports_list.append("None")

    ports_string = ", ".join(str(e) for e in ports_list)
    logger.debug("ports_string length=%d", len(ports_string))
    device = Device(
        search=search,
        ip=host_arg.address,
        product="",
        org="",
        data="",
        port=ports_string,
        type="NMAP",
        city="NMAP",
        lat=lat if lat is not None else "",
        lon=lon if lon is not None else "",
        country_code=country_code,
        query="NMAP SCAN",
        category="NMAP",
        vulns="",
        indicator="",
        hostnames=hostname,
        screenshot="",
    )
    device.save()


def validate_nmap(file):
    NmapParser.parse_fromfile(file)


def validate_maxmind():
    try:
        maxminddb.open_database("GeoLite2-City.mmdb")
    except FileNotFoundError:
        raise FileNotFoundError(
            "GeoLite2-City.mmdb not found in the project root. "
            "Download it for free from MaxMind: "
            "https://dev.maxmind.com/geoip/geolite2-free-geolocation-data "
            "and place GeoLite2-City.mmdb in the Kamerka_Plus_GUI root directory."
        )


@shared_task(bind=True)
def nmap_scan(self, file, fk):
    progress_recorder = ProgressRecorder(self)
    result = 0
    print(file)
    search = Search.objects.get(id=fk)
    max_reader = maxminddb.open_database("GeoLite2-City.mmdb")
    nmap_report = NmapParser.parse_fromfile(file)
    total = len(nmap_report.hosts)
    for c, i in enumerate(nmap_report.hosts):
        result += c
        nmap_host_worker(host_arg=i, max_reader=max_reader, search=search)
        progress_recorder.set_progress(c + 1, total=total)

    # Chain Shodan enrichment for each device discovered by the NMAP scan
    if _get_env_key("SHODAN_API_KEY"):
        for device in Device.objects.filter(search=search):
            shodan_scan_task.delay(device.id)

    return result


def _validate_target(ip, port):
    """Validate IP address and port to prevent SSRF and injection.

    Raises ``ValueError`` for any invalid input including an empty port.
    Callers that need port discovery for devices with no recorded port should
    call ``_resolve_open_ports()`` first.
    """
    import ipaddress

    try:
        ipaddress.ip_address(ip)
    except ValueError:
        raise ValueError("Invalid IP address: {}".format(ip))
    if not port or not str(port).strip():
        raise ValueError("Invalid port: (empty) — run a port scan first")
    try:
        port_int = int(port)
        if not (1 <= port_int <= 65535):
            raise ValueError("Port out of range: {}".format(port))
    except (ValueError, TypeError):
        raise ValueError("Invalid port: {}".format(port))
    return ip, str(port_int)


# ---------------------------------------------------------------------------
# Ports in this set are assumed to run TLS.  Any port NOT in this set is
# tried with http:// first; if a TLS handshake error is detected the caller
# retries with https://.  Well-known TLS ports are given https:// directly
# without the first-pass overhead.
# ---------------------------------------------------------------------------
_HTTPS_PORTS = frozenset({443, 8443, 4443, 9443})


def _build_target_urls(ip, ports):
    """Return a list of (url, is_tls) tuples for every open port.

    For well-known TLS ports (443, 8443 …) ``https://`` is used directly.
    For all other ports an HTTP URL is returned; callers should retry with
    ``https://`` if they receive a TLS/SSL connection error (two-pass probing).

    Parameters
    ----------
    ip : str
        Validated IPv4/IPv6 address.
    ports : list[int]
        Open port numbers from ``_resolve_open_ports()``.

    Returns
    -------
    list[tuple[str, bool]]
        Each element is ``(url, is_known_tls)``.
    """
    result = []
    for p in ports:
        if p in _HTTPS_PORTS:
            result.append(("https://{}:{}".format(ip, p), True))
        else:
            result.append(("http://{}:{}".format(ip, p), False))
    return result


def _rate_limit_check(ip, window_seconds=60, max_scans=10):
    """Enforce a per-IP scan rate limit using the Django cache (Redis).

    Uses a simple counter with a sliding TTL window.  If the number of scans
    initiated against *ip* in the last *window_seconds* seconds exceeds
    *max_scans* this function returns ``False`` and the caller should abort
    the scan to avoid inadvertent DoS.

    Falls back to ``True`` (allow) when the cache is unavailable so that a
    Redis outage never silently blocks legitimate scans.

    Parameters
    ----------
    ip : str             Target IP address (used as the cache key).
    window_seconds : int Sliding window size in seconds (default 60).
    max_scans : int      Maximum allowed scans per window (default 10).

    Returns
    -------
    bool  ``True`` if the scan is within the rate limit, ``False`` if it
          should be rejected.
    """
    from django.core.cache import cache

    cache_key = "ratelimit:scan:{}".format(ip)
    try:
        count = cache.get(cache_key, 0)
        if count >= max_scans:
            logger.warning(
                "_rate_limit_check: IP %s has exceeded %d scans in %ds — scan rejected",
                ip,
                max_scans,
                window_seconds,
            )
            return False
        # Increment; set TTL only on first write so the window resets naturally.
        if count == 0:
            cache.set(cache_key, 1, timeout=window_seconds)
        else:
            cache.incr(cache_key)
        return True
    except Exception as exc:
        logger.warning(
            "_rate_limit_check: cache unavailable (%s) — allowing scan for %s",
            exc,
            ip,
        )
        return True  # fail open to avoid blocking legitimate scans


def _resolve_open_ports(device):
    """Return a sorted list of open TCP port numbers for *device*.

    Resolution order
    ----------------
    1. If ``device.port`` already contains port data (a single number or a
       comma-separated list from an Nmap/Shodan scan), parse and return it.
    2. Otherwise run a full Naabu port scan against ``device.ip``.

    **Side effect (case 2 only):** when port discovery succeeds the
    discovered port list is persisted to ``device.port`` and saved to the
    database via ``device.save(update_fields=['port'])``.

    Returns
    -------
    list[int]
        Sorted open port numbers.  Empty list when the stored port field is
        blank *and* Naabu finds no open ports (or is not installed).
    """
    from verification.naabu_scanner import run_naabu, _get_naabu_bin
    from django.conf import settings as _s

    existing = str(device.port).strip() if device.port else ""
    if existing:
        ports = []
        for part in re.split(r"[,\s]+", existing):
            part = part.strip()
            if part.isdigit():
                p = int(part)
                if 1 <= p <= 65535:
                    ports.append(p)
        if ports:
            return sorted(set(ports))

    # No usable port data — discover ports with a full Naabu scan.
    # Distinguish "not installed" from "host has no open ports" for clearer logging.
    naabu_bin = _get_naabu_bin()
    if not os.path.isfile(naabu_bin) and naabu_bin != "naabu":
        logger.error(
            "_resolve_open_ports: Naabu binary '%s' not found. "
            "Install: go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest",
            naabu_bin,
        )
        return []

    discovery_ports = getattr(_s, "NAABU_DISCOVERY_PORTS", "1-65535")
    discovery_timeout = getattr(_s, "NAABU_DISCOVERY_TIMEOUT", 120)
    logger.info(
        "_resolve_open_ports: running Naabu discovery against %s (ports: %s)",
        device.ip,
        discovery_ports,
    )
    results = run_naabu(device.ip, ports=discovery_ports, timeout=discovery_timeout)
    if results:
        open_ports = sorted(set(r["port"] for r in results if r.get("port")))
        device.port = ", ".join(str(p) for p in open_ports)
        device.save(update_fields=["port"])
        logger.info(
            "_resolve_open_ports: discovered ports %s on %s",
            device.port,
            device.ip,
        )
        return open_ports

    logger.warning(
        "_resolve_open_ports: no open ports found on %s "
        "(host may be unreachable or all ports filtered)",
        device.ip,
    )
    return []


@shared_task(bind=True)
def port_scan_task(self, device_id):
    """Discover open TCP ports for a device using Naabu.

    This task is intended as the *first stage* of a two-stage Celery chain::

        chain(port_scan_task.s(device_id), nuclei_scan.s()).delay()
        chain(port_scan_task.s(device_id), wappalyzer_scan.s()).delay()

    Port resolution
    ---------------
    * If ``device.port`` is already populated (set by Shodan or Nmap) those
      ports are returned immediately — no Naabu call is made.  Shodan's port
      data is the *primary* source; Naabu is only the *fallback* for devices
      that arrive with an empty port field.
    * When Naabu runs the discovered ports are persisted to ``device.port``
      so subsequent tasks (nuclei_scan, wappalyzer_scan) can reuse them
      without running Naabu again.

    Progress
    --------
    Uses ``ProgressRecorder`` so the dashboard progress bar tracks the
    discovery phase before the scan phase begins.

    Returns
    -------
    dict
        ``{"device_id": int, "ports": list[int]}``
        The returned dict is passed as the first positional argument to the
        next task in the chain.  ``nuclei_scan`` / ``wappalyzer_scan``
        accept an optional ``discovered_ports`` kwarg and skip
        ``_resolve_open_ports`` when it is set.
    """
    progress_recorder = ProgressRecorder(self)
    progress_recorder.set_progress(0, 3, description="Resolving device…")

    device = Device.objects.get(id=device_id)
    progress_recorder.set_progress(1, 3, description="Running port scan…")

    ports = _resolve_open_ports(device)
    progress_recorder.set_progress(3, 3, description="Port scan complete")

    return {"device_id": device_id, "ports": ports}


@shared_task(bind=False)
def wappalyzer_scan(id, discovered_ports=None):
    """Run Wappalyzer CLI against all open ports of a device.

    When called as the second stage of a Celery chain the first argument
    (*id*) will be the dict returned by ``port_scan_task`` — in that case
    the ``device_id`` and ``ports`` keys are extracted automatically.

    Otherwise *id* must be the device's integer primary key and
    ``_resolve_open_ports()`` will be called to find open ports.

    Two-pass HTTP→HTTPS probing
    ---------------------------
    ``_build_target_urls()`` assigns ``http://`` to unknown ports and
    ``https://`` to well-known TLS ports (443, 8443, …).  When Wappalyzer
    returns an SSL/TLS error on an ``http://`` target the scan is retried
    automatically with ``https://``.
    """
    # Handle being called as the second stage of a port_scan_task chain.
    if isinstance(id, dict):
        discovered_ports = id.get("ports", discovered_ports)
        id = id["device_id"]

    device = Device.objects.get(id=id)

    try:
        ipaddress_mod = __import__("ipaddress")
        ipaddress_mod.ip_address(device.ip)  # basic SSRF guard
    except ValueError:
        return {"error": "Invalid IP address: {}".format(device.ip)}

    # Rate limiting — abort if this IP is being scanned too aggressively.
    if not _rate_limit_check(device.ip):
        return {
            "error": "Rate limit exceeded for {} — try again in 60 seconds".format(
                device.ip
            )
        }

    ports = (
        discovered_ports
        if discovered_ports is not None
        else _resolve_open_ports(device)
    )
    if not ports:
        return {
            "error": "No open ports discovered on {} — Naabu may not be installed "
            "(see KAMERKA_NAABU_BIN) or the host is unreachable".format(device.ip)
        }

    all_technologies = {}
    wapp_bin = settings.WAPPALYZER_BIN
    for url, is_known_tls in _build_target_urls(device.ip, ports):
        # Extract port number once for use in logging and dict keys.
        port = int(url.rsplit(":", 1)[-1])

        def _try_wappalyzer(target_url, _bin=wapp_bin):
            return subprocess.run(
                [_bin, target_url, "-oJ"],
                capture_output=True,
                text=True,
                timeout=60,
            )

        try:
            result = _try_wappalyzer(url)
            # Two-pass: if we used http:// and got an SSL error, retry with https://
            if (
                not is_known_tls
                and result.returncode != 0
                and ("ssl" in result.stderr.lower() or "tls" in result.stderr.lower())
            ):
                https_url = url.replace("http://", "https://", 1)
                logger.info("wappalyzer_scan: retrying %s with HTTPS", url)
                result = _try_wappalyzer(https_url)
            if result.returncode == 0 and result.stdout.strip():
                technologies = json.loads(result.stdout)
                wap_result = WappalyzerResult(
                    device=device,
                    technologies=technologies,
                    raw_output=result.stdout[:10000],
                )
                wap_result.save()
                all_technologies[str(port)] = technologies
        except FileNotFoundError:
            return {"error": "Wappalyzer CLI not installed"}
        except subprocess.TimeoutExpired:
            logger.warning("wappalyzer_scan: timed out on %s:%s", device.ip, port)
        except json.JSONDecodeError:
            logger.warning(
                "wappalyzer_scan: JSON parse error on %s:%s", device.ip, port
            )
        except Exception as exc:
            logger.warning("wappalyzer_scan: error on %s:%s — %s", device.ip, port, exc)

    return (
        all_technologies
        if all_technologies
        else {"error": "No output from Wappalyzer on any port"}
    )


@shared_task(bind=False)
def nuclei_scan(
    id, templates_dir=None, severity=None, rate_limit=150, discovered_ports=None
):
    """Run Nuclei against all open ports of a device.

    Chaining
    --------
    When called as the second stage of a ``port_scan_task`` chain the first
    argument (*id*) will be the dict returned by that task::

        from celery import chain
        chain(port_scan_task.s(device_id), nuclei_scan.s()).delay()

    Port resolution
    ---------------
    If ``device.port`` is already set (populated by a Shodan or Nmap scan)
    those ports are used directly — Naabu is NOT called.  Naabu is only the
    *fallback* for devices that arrive without any port data.

    Two-pass HTTP→HTTPS
    -------------------
    Target URLs are built with ``_build_target_urls()``.  Well-known TLS
    ports receive ``https://``; all others get ``http://``.  Nuclei handles
    TLS negotiation automatically so both schemas are included.

    The Nuclei binary path is read from ``settings.NUCLEI_BIN``.

    ``severity`` is validated against the Nuclei allowlist before use.
    ``rate_limit`` is clamped to [1, 500] to prevent accidental DoS.
    """
    import tempfile as _tmp

    # Handle being called as the second stage of a port_scan_task chain.
    if isinstance(id, dict):
        discovered_ports = id.get("ports", discovered_ports)
        id = id["device_id"]

    # ── Input validation ────────────────────────────────────────────────────
    _VALID_SEVERITIES = {"info", "low", "medium", "high", "critical"}
    if severity is not None:
        severity = str(severity).strip().lower()
        if severity not in _VALID_SEVERITIES:
            return {
                "error": "Invalid severity '{}'. Must be one of: {}".format(
                    severity, ", ".join(sorted(_VALID_SEVERITIES))
                )
            }

    try:
        rate_limit = int(rate_limit)
        if not (1 <= rate_limit <= 500):
            raise ValueError()
    except (ValueError, TypeError):
        return {"error": "rate_limit must be an integer between 1 and 500"}
    # ────────────────────────────────────────────────────────────────────────

    from django.conf import settings as django_settings

    nuclei_bin = getattr(django_settings, "NUCLEI_BIN", "nuclei")
    nuclei_timeout = getattr(django_settings, "NUCLEI_DEFAULT_TIMEOUT", 300)

    device = Device.objects.get(id=id)

    try:
        ipaddress_mod = __import__("ipaddress")
        ipaddress_mod.ip_address(device.ip)
    except ValueError:
        return {"error": "Invalid IP address: {}".format(device.ip)}

    # Rate limiting.
    if not _rate_limit_check(device.ip):
        return {
            "error": "Rate limit exceeded for {} — try again in 60 seconds".format(
                device.ip
            )
        }

    ports = (
        discovered_ports
        if discovered_ports is not None
        else _resolve_open_ports(device)
    )
    if not ports:
        return {
            "error": "No open ports discovered on {} — Naabu may not be installed "
            "(see KAMERKA_NAABU_BIN) or the host is unreachable".format(device.ip)
        }

    # Build target URLs — both http:// and https:// variants for non-TLS ports
    # so Nuclei can probe both.  Well-known TLS ports get https:// directly.
    target_urls = [url for url, _ in _build_target_urls(device.ip, ports)]
    # Also add https:// variant for every non-TLS port so Nuclei covers both.
    for url, is_tls in _build_target_urls(device.ip, ports):
        if not is_tls:
            target_urls.append(url.replace("http://", "https://", 1))

    targets_file = None
    try:
        fd, targets_file = _tmp.mkstemp(suffix=".txt", text=True)
        try:
            with os.fdopen(fd, "w") as tf:
                tf.write("\n".join(target_urls) + "\n")
        except Exception:
            os.close(fd)
            raise

        cmd = [nuclei_bin, "-l", targets_file, "-jsonl", "-silent"]

        if templates_dir:
            # Resolve relative paths (sent from the UI) to absolute so nuclei
            # can find them regardless of the working directory.
            if not os.path.isabs(templates_dir):
                templates_dir = os.path.join(django_settings.BASE_DIR, templates_dir)
            cmd.extend(["-t", templates_dir])
        else:
            cmd.append("-as")

        if severity:
            cmd.extend(["-severity", severity])

        cmd.extend(["-rate-limit", str(rate_limit)])

        findings = []
        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            import threading as _threading

            def _kill_after(proc, timeout):
                try:
                    proc.wait(timeout=timeout)
                except subprocess.TimeoutExpired:
                    logger.warning(
                        "nuclei_scan: timeout after %ds for %s — killing",
                        timeout,
                        device.ip,
                    )
                    proc.kill()

            timer = _threading.Thread(
                target=_kill_after, args=(proc, nuclei_timeout), daemon=True
            )
            timer.start()

            for line in proc.stdout:
                line = line.strip()
                if not line:
                    continue
                try:
                    finding = json.loads(line)
                    NucleiResult(
                        device=device,
                        template_id=finding.get("template-id", "")[:200],
                        name=finding.get("info", {}).get("name", "")[:500],
                        severity=finding.get("info", {}).get("severity", "")[:50],
                        matched_at=finding.get("matched-at", "")[:500],
                        description=finding.get("info", {}).get("description", ""),
                        raw_output=line[:10000],
                    ).save()
                    findings.append(finding)
                except json.JSONDecodeError:
                    continue

            proc.wait()
            stderr_out = proc.stderr.read().strip() if proc.stderr else ""
            if stderr_out:
                logger.warning("nuclei_scan stderr for %s: %s", device.ip, stderr_out)
        except FileNotFoundError:
            return {"error": "Nuclei binary not installed"}
        except Exception as exc:
            logger.error("nuclei_scan failed for %s: %s", device.ip, exc)
            return {"error": str(exc)}

        return {"findings_count": len(findings), "findings": findings}
    except Exception as exc:
        return {"error": str(exc)}
    finally:
        if targets_file and os.path.exists(targets_file):
            os.unlink(targets_file)


def paste_login(username, password, key):
    login_url = "https://pastebin.com/api/api_login.php"
    login_payload = {
        "api_dev_key": key,
        "api_user_name": username,
        "api_user_password": password,
    }

    login = requests.post(login_url, data=login_payload)
    user_key = login.text
    return user_key


def retrieve_pastes(key, user_key):
    url = "http://pastebin.com/api/api_post.php"
    paste_dict = {}

    values_list = {"api_option": "list", "api_dev_key": key, "api_user_key": user_key}

    data = urllib.parse.urlencode(values_list)
    data = data.encode("utf-8")  # data should be bytes
    req = urllib.request.Request(url, data)
    with urllib.request.urlopen(req) as response:
        the_page = response.read()

    key_v = ""
    title = ""

    root = et.fromstring("<root>" + str(the_page) + "</root>")
    for paste_root in root:
        for paste_element in paste_root:
            key = paste_element.tag.split("_", 1)[-1]
            if key == "key":
                key_v = paste_element.text
            if key == "title":
                title = paste_element.text

        paste_dict[title] = key_v
    return paste_dict


def delete_paste(key, user_key, paste_code):
    url = "http://pastebin.com/api/api_post.php"

    values_list = {
        "api_option": "delete",
        "api_dev_key": key,
        "api_user_key": user_key,
        "api_paste_key": paste_code,
    }

    data = urllib.parse.urlencode(values_list)
    data = data.encode("utf-8")  # data should be bytes
    req = urllib.request.Request(url, data)
    urllib.request.urlopen(req)


def create_paste(key, user_key, filename, text):
    url = "http://pastebin.com/api/api_post.php"

    values = {
        "api_option": "paste",
        "api_dev_key": key,
        "api_paste_code": text,
        "api_paste_private": "2",
        "api_paste_name": filename,
        "api_user_key": user_key,
    }

    data = urllib.parse.urlencode(values)
    data = data.encode("utf-8")  # data should be bytes
    req = urllib.request.Request(url, data)
    with urllib.request.urlopen(req) as response:
        the_page = response.read()


@shared_task(bind=False)
def send_to_field_agent_task(id, notes):
    cve = ""
    indicator = ""

    af = Device.objects.get(id=id)
    ports = af.port
    try:
        af_details = ShodanScan.objects.get(device_id=id)
        ports = af_details.ports[1:][:-1]
        if af_details.vulns:
            cve = af_details.vulns[1:][:-1]
        if af.indicator:
            indicator = af.indicator[2:][:-2]
    except Exception:
        logger.warning(
            "send_to_field_agent_task: ShodanScan record not found for device %s — skipping enrichment",
            id,
        )

    user_key = paste_login(
        _get_env_key("PASTEBIN_API_USER_NAME"),
        _get_env_key("PASTEBIN_API_USER_PASSWORD"),
        _get_env_key("PASTEBIN_API_DEV_KEY"),
    )

    pastes = retrieve_pastes(_get_env_key("PASTEBIN_API_DEV_KEY"), user_key=user_key)

    ip = af.ip
    lat = af.lat
    lon = af.lon
    org = af.org
    type = af.type

    notes = af.notes

    merge_string = (
        "ꓘ;"
        + lat
        + ";"
        + lon
        + ";"
        + ip
        + ";"
        + ports
        + ";"
        + org
        + ";"
        + type
        + ";"
        + cve
        + ";"
        + indicator
        + ";"
        + notes
    )

    print("\\xea\\x93\\x98amerka_" + af.ip)
    if "\\xea\\x93\\x98amerka_" + af.ip in pastes.keys():
        delete_paste(
            _get_env_key("PASTEBIN_API_DEV_KEY"),
            user_key,
            pastes["\\xea\\x93\\x98amerka_" + af.ip],
        )
        create_paste(
            _get_env_key("PASTEBIN_API_DEV_KEY"), user_key, "ꓘamerka_" + af.ip, merge_string
        )
    else:
        create_paste(
            _get_env_key("PASTEBIN_API_DEV_KEY"), user_key, "ꓘamerka_" + af.ip, merge_string
        )


@shared_task(bind=False)
def shodan_scan_task(id):
    SHODAN_API_KEY = _get_env_key("SHODAN_API_KEY", required=True)
    device = Device.objects.get(id=id)
    api = Shodan(SHODAN_API_KEY)
    product = []
    tags = []
    vulns = []
    try:
        # Search Shodan
        results = api.host(device.ip)
        # Show the results
        total = len(results["ports"])
        print(total)
        for counter, i in enumerate(results["data"]):

            if "product" in i:
                product.append(i["product"])

            if "tags" in i:
                for j in i["tags"]:
                    tags.append(j)

            current_task.update_state(
                state="PROGRESS",
                meta={
                    "current": counter,
                    "total": total,
                    "percent": int((float(counter) / total) * 100),
                },
            )
        if "vulns" in results:
            vulns = results["vulns"]

        ports = results["ports"]
        device1 = ShodanScan(
            device=device, products=product, ports=ports, tags=tags, vulns=vulns
        )
        device1.save()
        print(results["ports"])

        return {"current": total, "total": total, "percent": 100}

    except Exception as e:
        print(e.args)


ics_scan = {
    "dnp3": "--script=nmap_scripts/dnp3-info.nse",
    "niagara": "--script=nmap_scripts/fox-info.nse",
    "siemens": "--script=nmap_scripts/s7-info.nse",
    "proconos": "--script=nmap_scripts/proconos-info.nse",
    "pcworx": "--script=nmap_scripts/pcworx-info.nse",
    "omron": "--script=nmap_scripts/omron-info.nse",
    "modbus": "--script=nmap_scripts/modbus-discover.nse",
    "ethernetip": "--script=nmap_scripts/enip-info.nse",
    "codesys": "--script=nmap_scripts/codesys.nse",
    "ab_ethernet": "--script=nmap_scripts/cspv4-info.nse",
    "tank": "--script=nmap_scripts/atg-info.nse",
    "modicon": "--script=nmap_scripts/modicon-info.nse",
}


# Map of all available NSE scripts for the dropdown UI.  Keys are
# human-readable labels; values are file paths relative to project root.
NSE_SCRIPT_CATALOG = {
    "DNP3 Info": "nmap_scripts/dnp3-info.nse",
    "Fox / Niagara Info": "nmap_scripts/fox-info.nse",
    "S7 Info (Siemens)": "nmap_scripts/s7-info.nse",
    "S7 Enumerate (Siemens)": "nmap_scripts/s7-enumerate.nse",
    "ProConOS Info": "nmap_scripts/proconos-info.nse",
    "PC Worx Info": "nmap_scripts/pcworx-info.nse",
    "Omron Info": "nmap_scripts/omron-info.nse",
    "Modbus Discover": "nmap_scripts/modbus-discover.nse",
    "EtherNet/IP (ENIP) Info": "nmap_scripts/enip-info.nse",
    "CODESYS": "nmap_scripts/codesys.nse",
    "CIPv4 (CSPv4) Info": "nmap_scripts/cspv4-info.nse",
    "ATG Info (Tank Gauge)": "nmap_scripts/atg-info.nse",
    "Modicon Info": "nmap_scripts/modicon-info.nse",
    "BACnet Info": "nmap_scripts/bacnet-info.nse",
}


@shared_task(bind=True)
def nmap_device_scan(self, device_id, nse_script=None):
    """Run an Nmap scan against a device with optional NSE script.

    When *nse_script* is provided it must be a path relative to the project
    root (e.g. ``nmap_scripts/s7-info.nse``).  The path is validated to
    prevent directory-traversal attacks.

    Results are stored on ``device.scan`` and returned as a dict.
    """
    progress_recorder = ProgressRecorder(self)
    progress_recorder.set_progress(0, 4, description="Resolving device…")

    device = Device.objects.get(id=device_id)
    ip = device.ip
    port = device.port or ""

    import ipaddress as _ipa

    try:
        _ipa.ip_address(ip)
    except ValueError:
        return {"Error": "Invalid IP address: {}".format(ip)}

    # Determine scan port spec — fall back to common ICS/IoT ports.
    if port and str(port).strip():
        port_spec = str(port).strip().split(",")[0].strip()
    else:
        port_spec = "21,22,23,80,102,443,502,1911,4911,8080,9600,20000,44818,47808"

    # Build Nmap options
    if nse_script:
        # Security: validate path stays within nmap_scripts/
        safe_base = os.path.realpath(os.path.join(settings.BASE_DIR, "nmap_scripts"))
        script_abs = os.path.realpath(os.path.join(settings.BASE_DIR, nse_script))
        if not script_abs.startswith(safe_base + os.sep) and script_abs != safe_base:
            return {"Error": "Invalid script path"}
        if not os.path.isfile(script_abs):
            return {"Error": "NSE script not found: {}".format(nse_script)}
        options = "-p {} --script={}".format(port_spec, nse_script)
    elif device.type in ics_scan:
        options = "-p {} {}".format(port_spec, ics_scan[device.type])
    else:
        options = "-p {} -sV".format(port_spec)

    progress_recorder.set_progress(
        1, 4, description="Starting Nmap scan on {}…".format(ip)
    )

    return_dict = {}
    try:
        nm = NmapProcess(ip, options=options)
        nm.run_background()

        # Wait for the scan with a timeout
        start_time = time.time()
        max_runtime = getattr(settings, "NMAP_MAX_RUNTIME", 300)
        while nm.is_running():
            elapsed = time.time() - start_time
            if elapsed > max_runtime:
                try:
                    nm.stop()
                except Exception:
                    pass
                return {
                    "Error": "Nmap scan timed out after {} seconds".format(max_runtime)
                }
            progress_recorder.set_progress(
                2, 4, description="Scanning… {:.0f}s elapsed".format(elapsed)
            )
            sleep(2)

        progress_recorder.set_progress(3, 4, description="Processing results…")

        if not nm.stdout:
            return_dict["Error"] = "No Nmap output — nmap may not be installed"
            if nm.stderr:
                return_dict["stderr"] = nm.stderr[:500]
            device.scan = json.dumps(return_dict)
            device.exploited_scanned = True
            device.save()
            return return_dict

        u = xmltodict.parse(nm.stdout)

        # Extract script output if present
        try:
            host = u.get("nmaprun", {}).get("host", {})
            ports_data = host.get("ports", {}).get("port", {})

            if isinstance(ports_data, list):
                for p in ports_data:
                    port_id = p.get("@portid", "")
                    state = p.get("state", {}).get("@state", "")
                    return_dict["port_{}".format(port_id)] = state
                    scripts = p.get("script", {})
                    if isinstance(scripts, dict):
                        return_dict[scripts.get("@id", "script")] = scripts.get(
                            "@output", ""
                        )
                    elif isinstance(scripts, list):
                        for s in scripts:
                            return_dict[s.get("@id", "script")] = s.get("@output", "")
            elif isinstance(ports_data, dict):
                port_id = ports_data.get("@portid", "")
                state = ports_data.get("state", {}).get("@state", "")
                return_dict["port_{}".format(port_id)] = state
                scripts = ports_data.get("script", {})
                if isinstance(scripts, dict):
                    return_dict[scripts.get("@id", "script")] = scripts.get(
                        "@output", ""
                    )
                elif isinstance(scripts, list):
                    for s in scripts:
                        return_dict[s.get("@id", "script")] = s.get("@output", "")

            if not return_dict:
                return_dict["State"] = "No script output"
                return_dict["raw"] = nm.stdout[:2000]

        except Exception as e:
            logger.warning("nmap_device_scan parse error: %s", e)
            return_dict["State"] = "Parse error: {}".format(str(e))
            return_dict["raw"] = nm.stdout[:2000]

        device.scan = json.dumps(return_dict)
        device.exploited_scanned = True
        device.save()

        progress_recorder.set_progress(4, 4, description="Scan complete")
        return return_dict

    except Exception as e:
        logger.warning("nmap_device_scan error for %s: %s", ip, e)
        return {"Error": str(e)}


@shared_task(bind=False)
def scan(id):
    """Legacy synchronous Nmap scan — prefer nmap_device_scan() Celery task."""
    return_dict = {}
    device1 = Device.objects.get(id=id)
    ip = device1.ip
    port = device1.port
    type = device1.type

    if type in ics_scan.keys():
        nm = NmapProcess(ip, options="-p " + str(port) + " " + ics_scan[type])
        nm.run_background()

        while nm.is_running():
            print("Nmap Scan running: ETC: {0} DONE: {1}%".format(nm.etc, nm.progress))
            sleep(2)

        u = xmltodict.parse(nm.stdout)
        print(u["nmaprun"])

        try:
            for i in u["nmaprun"]["host"]["ports"]["port"]["script"]:
                print(i)

                if i == "@output":
                    return_dict["ID"] = u["nmaprun"]["host"]["ports"]["port"]["script"][
                        "@id"
                    ]
                    return_dict["Output"] = u["nmaprun"]["host"]["ports"]["port"][
                        "script"
                    ]["@output"]

            device1.scan = return_dict
            device1.exploited_scanned = True
            device1.save()
            return return_dict

        except Exception as e:
            logger.warning("%s", e)
            return_dict["State"] = u["nmaprun"]["host"]["ports"]["port"]["state"][
                "@state"
            ]
            return_dict["Reason"] = u["nmaprun"]["host"]["ports"]["port"]["state"][
                "@reason"
            ]
            device1.scan = return_dict
            device1.exploited_scanned = True

            device1.save()
            return return_dict

    else:
        nm = NmapProcess(ip, options="-p " + str(port))
        nm.run_background()

        while nm.is_running():
            print("Nmap Scan running: ETC: {0} DONE: {1}%".format(nm.etc, nm.progress))
            sleep(2)

        u = xmltodict.parse(nm.stdout)

        try:
            return_dict["State"] = u["nmaprun"]["host"]["ports"]["port"]["state"][
                "@state"
            ]
            return_dict["Reason"] = u["nmaprun"]["host"]["ports"]["port"]["state"][
                "@reason"
            ]
            device1.scan = return_dict
            device1.exploited_scanned = True
            device1.save()
            return return_dict
        except Exception:
            pass


@shared_task(bind=False)
def exploit(id):
    device1 = Device.objects.get(id=id)
    print(device1.type)
    if device1.type == "bosch_security":
        usernames = exploits.bosch_usernames(device1)
        return usernames
    if device1.type == "hikvision":
        creds = exploits.hikvision(device1)
        return creds
    if device1.type == "videoiq":
        users = exploits.videoiq(device1)
        return users
    if device1.type == "contec":
        usernames = exploits.contec(device1)
        return usernames
    if device1.type == "grandstream":
        check = exploits.grandstream(device1)
        return check
    if device1.type == "netwave":
        status = exploits.netwave(device1)
        return status
    if device1.type == "CirCarLife":
        plc_status = exploits.circarlife(device1)
        return plc_status
    if device1.type == "amcrest":
        videotalk = exploits.amcrest(device1)
        return videotalk
    if device1.type == "lutron":
        config = exploits.lutron(device1)
        return config

    else:
        return {"Reason": "No exploit assigned"}


@shared_task(bind=False)
def whoisxml(id):
    """Perform a WHOIS lookup for the device IP using the FOSS ipwhois library."""
    from ipwhois import IPWhois

    device1 = Device.objects.get(id=id)

    netrange = ""
    admin_org = ""
    admin_email = ""
    admin_phone = ""
    city = ""
    email = ""
    street = ""
    name = ""
    org = ""

    try:
        obj = IPWhois(device1.ip)
        result = obj.lookup_rdap(depth=1)

        network = result.get("network", {})
        netrange = network.get("cidr", "")

        entities = result.get("objects", {})
        for key, entity in entities.items():
            roles = entity.get("roles", [])
            contact = entity.get("contact") or {}

            entity_name = contact.get("name", "") or ""
            entity_org = (contact.get("org") or [{}])[0].get("value", "")
            entity_email = (contact.get("email") or [{}])[0].get("value", "")
            entity_phone = (contact.get("phone") or [{}])[0].get("value", "")
            address_parts = contact.get("address") or []
            entity_street = address_parts[0].get("value", "") if address_parts else ""
            entity_city = ""
            if entity_street and "\n" in entity_street:
                lines = [l.strip() for l in entity_street.split("\n") if l.strip()]
                entity_street = lines[0] if lines else entity_street
                entity_city = lines[1] if len(lines) > 1 else ""

            if "registrant" in roles or "abuse" in roles:
                if not org:
                    org = entity_org or entity_name
                if not name:
                    name = entity_name
                if not email:
                    email = entity_email
                if not street:
                    street = entity_street
                if not city:
                    city = entity_city

            if "administrative" in roles or "technical" in roles:
                if not admin_org:
                    admin_org = entity_org or entity_name
                if not admin_email:
                    admin_email = entity_email
                if not admin_phone:
                    admin_phone = entity_phone

    except Exception as e:
        logger.warning("ipwhois lookup failed for %s: %s", device1.ip, e)

    wh = Whois(
        device=device1,
        org=org,
        street=street,
        city=city,
        admin_org=admin_org,
        admin_email=admin_email,
        admin_phone=admin_phone,
        netrange=netrange,
        name=name,
        email=email,
    )

    wh.save()


@shared_task(bind=False)
def whois_ip(id):
    """Perform a WHOIS lookup on the device IP using the system whois command.

    Parses the plain-text output into the structured Whois model fields.
    Falls back to the RDAP lookup (whoisxml) when the whois binary is not
    available or produces no parseable output.
    """
    device1 = Device.objects.get(id=id)
    ip = device1.ip

    name = org = street = city = netrange = admin_org = admin_email = admin_phone = (
        email
    ) = ""

    try:
        proc = subprocess.run(
            ["whois", ip],
            text=True,
            timeout=30,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        if proc.stderr.strip():
            logger.warning("whois_ip stderr for %s: %s", ip, proc.stderr.strip())
        raw = proc.stdout
    except FileNotFoundError:
        return whoisxml(id)
    except Exception as exc:
        logger.warning("whois_ip subprocess failed for %s: %s", ip, exc)
        return whoisxml(id)

    for line in raw.splitlines():
        lower = line.lower()
        if ":" not in line:
            continue
        key, _, val = line.partition(":")
        val = val.strip()
        if not val:
            continue
        key = key.strip().lower()
        if key in ("netname", "name", "orgname", "owner") and not name:
            name = val[:100]
        elif key in ("org", "organisation", "organization") and not org:
            org = val[:100]
        elif key in ("address", "street") and not street:
            street = val[:100]
        elif key == "city" and not city:
            city = val[:100]
        elif key in ("inetnum", "netrange", "cidr") and not netrange:
            netrange = val[:100]
        elif key in ("orgabusehandle", "tech-c") and not admin_org:
            admin_org = val[:100]
        elif (
            key in ("orgabuseemail", "abuse-mailbox", "orgtechemail")
            and not admin_email
        ):
            if "@" in val:
                admin_email = val[:100]
        elif key in ("orgabusephone",) and not admin_phone:
            admin_phone = val[:100]
        elif key in ("orgtechhandle",) and not admin_org:
            admin_org = val[:100]
        elif key in ("orgtechphone",) and not admin_phone:
            admin_phone = val[:100]
        elif "email" in key and not email:
            if "@" in val:
                email = val[:100]

    if not any(
        [name, org, street, city, netrange, admin_org, admin_email, admin_phone, email]
    ):
        return whoisxml(id)

    wh = Whois(
        device=device1,
        name=name,
        org=org,
        street=street,
        city=city,
        netrange=netrange,
        admin_org=admin_org,
        admin_email=admin_email,
        admin_phone=admin_phone,
        email=email,
    )
    wh.save()
    return {"ip": ip, "org": org, "name": name, "netrange": netrange}


@shared_task(bind=False)
def whois_domain(id):
    """Perform a WHOIS/RDAP lookup for the device and save to the Whois model.

    Delegates to the RDAP-based whoisxml() helper to avoid relying on the
    undeclared ``python-whois`` dependency.  whoisxml() handles persistence
    to the Whois model directly.
    """
    return whoisxml(id)


@shared_task(bind=False)
def bosch_check(id):
    """Retrieve Bosch device credentials via the /User.cgi endpoint.

    Only runs when the device product field identifies it as a Bosch device.
    Decodes the base64-encoded username and password fields returned by the
    Bosch Security CGI API and persists them to the Bosch model.
    """
    device1 = Device.objects.get(id=id)

    if "bosch" not in (device1.product or "").lower():
        return {"skipped": "Not identified as a Bosch device"}

    ip = device1.ip
    port = device1.port

    return_dict = {}
    try:
        req = requests.get(
            "http://{}:{}/User.cgi?cmd=get_user".format(ip, port),
            timeout=10,
        )
        doc = xmltodict.parse(req.text)
        for user_key, user_data in doc.get("USER_SETTING", {}).items():
            if user_key == "result":
                continue
            if not isinstance(user_data, dict):
                continue
            try:
                username = base64.b64decode(user_data.get("USERNAME", "")).decode(
                    "utf-8"
                )
                password = base64.b64decode(user_data.get("PWD", "")).decode("utf-8")
                if username:
                    return_dict[username] = password
                    Bosch.objects.update_or_create(
                        device=device1,
                        username=username[:100],
                        defaults={"password": password[:100]},
                    )
            except Exception:
                continue
    except Exception as exc:
        logger.warning("bosch_check failed for %s: %s", ip, exc)
        return {"error": str(exc)}

    if return_dict:
        device1.exploit = return_dict
        device1.exploited_scanned = True
        device1.save()

    return return_dict


def _shodan_convert(download_path, fmt):
    """Run ``shodan convert <download_path> <fmt>`` and return the output path.

    This is exactly the workflow from snippets.shodan.io:
        shodan convert data.json.gz kml
        shodan convert data.json.gz csv
        shodan convert data.json.gz geo.json

    The shodan CLI writes the converted file next to the source with the
    format as its new extension (e.g. ``data.kml``, ``data.csv``,
    ``data.geo.json``).  Returns the path to that file.
    """
    from django.conf import settings

    downloads_dir = os.path.realpath(
        os.path.join(settings.BASE_DIR, "shodan_downloads")
    )
    safe_path = os.path.realpath(download_path)
    if not safe_path.startswith(downloads_dir + os.sep):
        raise ValueError(
            "download_path is outside the shodan_downloads directory: {}".format(
                download_path
            )
        )
    subprocess.run(["shodan", "convert", safe_path, fmt], check=True)
    return safe_path.replace(".json.gz", ".{}".format(fmt))


def shodan_csv_export(search_id, output_path):
    """Export Shodan results as CSV via ``shodan convert data.json.gz csv``.

    Load the resulting file directly into PyVista or PyQt6 for 3-D
    visualisation of Shodan findings.
    If no download file exists a header-only CSV is written as a fallback.
    """
    download_path = _shodan_download_path(search_id)
    if os.path.exists(download_path):
        converted = _shodan_convert(download_path, "csv")
        shutil.copy(converted, output_path)
    else:
        with open(output_path, "w", encoding="utf-8") as fout:
            fout.write(
                "ip_str,port,org,location.country_code,location.city,"
                "location.latitude,location.longitude,product,vulns\n"
            )
    return output_path


def shodan_kml_export(search_id, output_path):
    """Export Shodan results as KML via ``shodan convert data.json.gz kml``.

    Load the resulting file into PyVista or PyQt6 for 3-D globe visualisation,
    or into QGIS, Leaflet, and uMap for 2-D mapping.
    If no download file exists a valid empty KML document is written.
    """
    download_path = _shodan_download_path(search_id)
    if os.path.exists(download_path):
        converted = _shodan_convert(download_path, "kml")
        shutil.copy(converted, output_path)
    else:
        with open(output_path, "w", encoding="utf-8") as fout:
            fout.write(
                '<?xml version="1.0" encoding="UTF-8"?>\n'
                '<kml xmlns="http://www.opengis.net/kml/2.2">'
                "<Document></Document></kml>"
            )
    return output_path


def shodan_json_export(search_id):
    """Export Shodan results as GeoJSON via ``shodan convert data.json.gz geo.json``.

    Load the resulting file into PyVista or PyQt6 to populate a 3-D globe
    or map with Shodan findings.
    Returns the GeoJSON string; an empty FeatureCollection is returned when no
    download file exists.
    """
    download_path = _shodan_download_path(search_id)
    if os.path.exists(download_path):
        converted = _shodan_convert(download_path, "geo.json")
        with open(converted, "r", encoding="utf-8") as f:
            return f.read()
    return '{"type":"FeatureCollection","features":[]}'


NMAP_RTSP_PORTS = "80,443,554,502"
NMAP_RTSP_TIMING = "-T4"


@shared_task(bind=False)
def nmap_rtsp_scan(id, ports=None, timing=None):
    """Run RTSP enumeration and manufacturer-specific NSE scripts against a device."""
    return_dict = {}
    device1 = Device.objects.get(id=id)
    ip = device1.ip
    device_type = device1.type

    scan_ports = ports or NMAP_RTSP_PORTS
    scan_timing = timing or NMAP_RTSP_TIMING

    options = "-sV -p {} {} --script=rtsp-url-brute".format(scan_ports, scan_timing)

    if device_type == "hikvision":
        options += ",http-hikvision-backdoor"
    elif device_type in ("dahua", "amcrest"):
        options += ",http-auth"

    nm = NmapProcess(ip, options=options)
    nm.run_background()

    while nm.is_running():
        sleep(2)

    try:
        parsed = NmapParser.parse(nm.stdout)
        for host in parsed.hosts:
            for svc in host.services:
                return_dict["port_{}".format(svc.port)] = {
                    "state": svc.state,
                    "service": svc.service,
                    "banner": svc.banner or "",
                    "scripts": (
                        {s["id"]: s["output"] for s in svc.scripts_results}
                        if svc.scripts_results
                        else {}
                    ),
                }

        device1.scan = json.dumps(return_dict)
        device1.exploited_scanned = True
        device1.save()
    except Exception as e:
        return_dict["error"] = str(e)

    return return_dict


# ---------------------------------------------------------------------------
# Deep Protocol Fingerprinting — Nmap NSE metadata parsers
# ---------------------------------------------------------------------------

# Maps protocol names to relevant ICS ports for targeted scanning.
PROTOCOL_PORTS = {
    "modbus": "502",
    "s7": "102",
    "bacnet": "47808",
    "dnp3": "20000",
    "ethernetip": "44818",
    "niagara": "1911",
    "fox": "1911",
    "codesys": "2455",
    "cspv4": "2222",
    "atg": "10001",
    "modicon": "502",
    "omron": "9600",
    "pcworx": "1962",
    "proconos": "20547",
}

# NSE scripts used for deep protocol fingerprinting.
DEEP_SCAN_SCRIPTS = {
    "modbus": "nmap_scripts/modbus-discover.nse",
    "s7": "nmap_scripts/s7-enumerate.nse,nmap_scripts/s7-info.nse",
    "bacnet": "nmap_scripts/bacnet-info.nse",
    "dnp3": "nmap_scripts/dnp3-info.nse",
    "ethernetip": "nmap_scripts/enip-info.nse",
    "fox": "nmap_scripts/fox-info.nse",
    "codesys": "nmap_scripts/codesys.nse",
    "cspv4": "nmap_scripts/cspv4-info.nse",
    "atg": "nmap_scripts/atg-info.nse",
    "modicon": "nmap_scripts/modicon-info.nse",
    "omron": "nmap_scripts/omron-info.nse",
    "pcworx": "nmap_scripts/pcworx-info.nse",
    "proconos": "nmap_scripts/proconos-info.nse",
}


def _parse_modbus_output(raw_output):
    """Parse Modbus NSE script output for protocol metadata.

    Extracts Slave ID, Vendor, Product Code from modbus-discover output.
    """
    result = {}
    # Match patterns like "Slave ID data: \xab\x..." or readable text
    sid_match = re.search(r"Slave ID data:\s*(.+?)(?:\n|$)", raw_output)
    if sid_match:
        result["slave_id"] = sid_match.group(1).strip()

    device_id_match = re.search(
        r"Device Identification:\s*(.+?)(?:\n|$)", raw_output, re.IGNORECASE
    )
    if device_id_match:
        result["vendor_id"] = device_id_match.group(1).strip()

    vendor_match = re.search(r"Vendor Name:\s*(.+?)(?:\n|$)", raw_output, re.IGNORECASE)
    if vendor_match:
        result["vendor_id"] = vendor_match.group(1).strip()

    product_match = re.search(
        r"Product Code:\s*(.+?)(?:\n|$)", raw_output, re.IGNORECASE
    )
    if product_match:
        result["project_name"] = product_match.group(1).strip()

    version_match = re.search(
        r"(?:Revision|Major Minor Revision):\s*(.+?)(?:\n|$)", raw_output, re.IGNORECASE
    )
    if version_match:
        result["firmware_version"] = version_match.group(1).strip()

    return result


def _parse_s7_output(raw_output):
    """Parse S7 (Siemens) NSE script output for protocol metadata.

    Extracts Module, Plant ID, Serial Number, Hardware/Firmware Version.
    """
    result = {}
    module_match = re.search(
        r"Module(?:\s+name)?:\s*(.+?)(?:\n|$)", raw_output, re.IGNORECASE
    )
    if module_match:
        result["module_name"] = module_match.group(1).strip()

    plant_match = re.search(
        r"Plant(?:\s+identification)?:\s*(.+?)(?:\n|$)", raw_output, re.IGNORECASE
    )
    if plant_match:
        result["plant_id"] = plant_match.group(1).strip()

    serial_match = re.search(
        r"Serial(?:\s+number)?:\s*(.+?)(?:\n|$)", raw_output, re.IGNORECASE
    )
    if serial_match:
        result["serial_number"] = serial_match.group(1).strip()

    hw_match = re.search(
        r"Hardware(?:\s+version)?:\s*(.+?)(?:\n|$)", raw_output, re.IGNORECASE
    )
    if hw_match:
        result["hardware_version"] = hw_match.group(1).strip()

    fw_match = re.search(
        r"Firmware(?:\s+version)?:\s*(.+?)(?:\n|$)", raw_output, re.IGNORECASE
    )
    if fw_match:
        result["firmware_version"] = fw_match.group(1).strip()

    name_match = re.search(
        r"(?:PLC\s+name|Module\s+type):\s*(.+?)(?:\n|$)", raw_output, re.IGNORECASE
    )
    if name_match:
        result["project_name"] = name_match.group(1).strip()

    vendor_match = re.search(
        r"(?:Copyright|Vendor):\s*(.+?)(?:\n|$)", raw_output, re.IGNORECASE
    )
    if vendor_match:
        result["vendor_id"] = vendor_match.group(1).strip()
    elif "siemens" in raw_output.lower() or "s7" in raw_output.lower():
        result["vendor_id"] = "Siemens"

    return result


def _parse_bacnet_output(raw_output):
    """Parse BACnet NSE script output for protocol metadata."""
    result = {}
    vendor_match = re.search(
        r"Vendor(?:\s+(?:Name|ID))?:\s*(.+?)(?:\n|$)", raw_output, re.IGNORECASE
    )
    if vendor_match:
        result["vendor_id"] = vendor_match.group(1).strip()

    model_match = re.search(
        r"(?:Model\s+Name|Object\s+Name):\s*(.+?)(?:\n|$)", raw_output, re.IGNORECASE
    )
    if model_match:
        result["project_name"] = model_match.group(1).strip()

    fw_match = re.search(
        r"(?:Firmware|Application Software)(?:\s+Version)?:\s*(.+?)(?:\n|$)",
        raw_output,
        re.IGNORECASE,
    )
    if fw_match:
        result["firmware_version"] = fw_match.group(1).strip()

    desc_match = re.search(r"Description:\s*(.+?)(?:\n|$)", raw_output, re.IGNORECASE)
    if desc_match:
        result["module_name"] = desc_match.group(1).strip()

    return result


# Dispatcher for protocol-specific parsers
_PROTOCOL_PARSERS = {
    "modbus": _parse_modbus_output,
    "s7": _parse_s7_output,
    "bacnet": _parse_bacnet_output,
}


def _parse_generic_nse_output(raw_output):
    """Generic parser for NSE script output — extracts common key:value pairs."""
    result = {}
    for line in raw_output.splitlines():
        line = line.strip().lstrip("|").strip()
        if ":" in line:
            key, _, val = line.partition(":")
            key = key.strip().lower().replace(" ", "_")
            val = val.strip()
            if val and key:
                if "vendor" in key:
                    result["vendor_id"] = val
                elif "version" in key or "firmware" in key:
                    result["firmware_version"] = val
                elif "serial" in key:
                    result["serial_number"] = val
                elif "module" in key or "model" in key:
                    result["module_name"] = val
                elif "product" in key or "name" in key or "project" in key:
                    result["project_name"] = val
                elif "hardware" in key:
                    result["hardware_version"] = val
                elif "plant" in key or "location" in key:
                    result["plant_id"] = val
                elif "slave" in key or "unit" in key:
                    result["slave_id"] = val
    return result


@shared_task(bind=False)
def deep_protocol_scan(device_id, protocol=None):
    """Run deep protocol fingerprinting using Nmap NSE scripts.

    Executes protocol-specific NSE scripts against a device and parses
    the output to extract Vendor ID, Project Name, Hardware Version, etc.
    Results are saved to the ProtocolFingerprint model.
    """
    device = Device.objects.get(id=device_id)
    ip = device.ip

    # Determine which protocol(s) to scan
    if protocol and protocol in DEEP_SCAN_SCRIPTS:
        protocols_to_scan = [protocol]
    else:
        # Auto-detect based on device type or scan all known protocols
        device_type = (device.type or "").lower()
        if device_type in DEEP_SCAN_SCRIPTS:
            protocols_to_scan = [device_type]
        elif device_type == "siemens":
            protocols_to_scan = ["s7"]
        else:
            protocols_to_scan = list(DEEP_SCAN_SCRIPTS.keys())

    results = {}
    for proto in protocols_to_scan:
        # Use the protocol's expected port for deep scans instead of blindly
        # reusing device.port, which may refer to an unrelated service.
        scan_port = PROTOCOL_PORTS.get(proto, "")
        if not scan_port:
            continue

        scripts = DEEP_SCAN_SCRIPTS[proto]
        options = "-p {} --script={}".format(scan_port, scripts)

        try:
            nm = NmapProcess(ip, options=options)
            nm.run_background()

            start_time = time.time()
            max_runtime = getattr(settings, "NMAP_MAX_RUNTIME", 300)
            timed_out = False

            while nm.is_running():
                if time.time() - start_time > max_runtime:
                    timed_out = True
                    try:
                        nm.stop()
                    except Exception as stop_err:
                        logger.warning(
                            "Failed to stop timed-out nmap process for %s/%s: %s",
                            ip,
                            proto,
                            stop_err,
                        )
                    logger.warning(
                        "Deep protocol scan timeout for %s/%s after %s seconds",
                        ip,
                        proto,
                        max_runtime,
                    )
                    results[proto] = {
                        "error": "Nmap scan timeout after {} seconds".format(
                            max_runtime
                        )
                    }
                    break
                sleep(2)

            if timed_out:
                continue

            if not nm.stdout:
                continue

            raw_xml = nm.stdout
            parsed_data = xmltodict.parse(raw_xml)

            # Extract script output from nmap XML
            raw_output = ""
            try:
                host = parsed_data.get("nmaprun", {}).get("host", {})
                ports = host.get("ports", {}).get("port", {})
                if isinstance(ports, list):
                    for p in ports:
                        scripts_data = p.get("script", {})
                        if isinstance(scripts_data, list):
                            for s in scripts_data:
                                raw_output += s.get("@output", "") + "\n"
                        elif isinstance(scripts_data, dict):
                            raw_output += scripts_data.get("@output", "") + "\n"
                elif isinstance(ports, dict):
                    scripts_data = ports.get("script", {})
                    if isinstance(scripts_data, list):
                        for s in scripts_data:
                            raw_output += s.get("@output", "") + "\n"
                    elif isinstance(scripts_data, dict):
                        raw_output += scripts_data.get("@output", "") + "\n"
            except Exception as e:
                logger.warning("Error extracting NSE output: %s", e)
                raw_output = raw_xml

            if not raw_output.strip():
                continue

            # Parse protocol-specific metadata
            parser = _PROTOCOL_PARSERS.get(proto, _parse_generic_nse_output)
            metadata = parser(raw_output) if parser else {}

            # Save fingerprint to database
            fp = ProtocolFingerprint(
                device=device,
                protocol=proto,
                vendor_id=metadata.get("vendor_id", ""),
                project_name=metadata.get("project_name", ""),
                hardware_version=metadata.get("hardware_version", ""),
                firmware_version=metadata.get("firmware_version", ""),
                serial_number=metadata.get("serial_number", ""),
                module_name=metadata.get("module_name", ""),
                slave_id=metadata.get("slave_id", ""),
                plant_id=metadata.get("plant_id", ""),
                raw_output=raw_output[:10000],
            )
            fp.save()

            results[proto] = metadata
            results[proto]["raw_output"] = raw_output[:500]

        except Exception as e:
            logger.warning("Deep protocol scan error for %s/%s: %s", ip, proto, e)
            results[proto] = {"error": str(e)}

    return results


@shared_task(bind=False)
def nvd_lookup(device_id):
    """Query the NIST NVD API for CVEs matching the device vendor/version.

    Uses the device's vendor and product information (from ProtocolFingerprint
    or Shodan CPE data) to find matching vulnerabilities, then enriches each
    CVE with EPSS scores and CISA KEV status.
    """
    device = Device.objects.get(id=device_id)
    cve_ids = []

    # Collect CVE IDs from device.vulns
    if device.vulns:
        try:
            import ast

            vulns_list = ast.literal_eval(device.vulns)
            if isinstance(vulns_list, list):
                cve_ids.extend(vulns_list)
        except Exception:
            pass

    # Also try to get CVEs from CPE string
    cpe = device.cpe or ""
    if cpe and not cve_ids:
        try:
            url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
            params = {"cpeName": cpe, "resultsPerPage": 20}
            resp = requests.get(url, params=params, timeout=30)
            if resp.status_code == 200:
                data = resp.json()
                for vuln in data.get("vulnerabilities", []):
                    cve_data = vuln.get("cve", {})
                    cve_id = cve_data.get("id", "")
                    if cve_id:
                        cve_ids.append(cve_id)
        except Exception as e:
            logger.warning("NVD CPE lookup error for %s: %s", device.ip, e)

    if not cve_ids:
        return {"status": "no_cves", "device_id": device_id}

    # Fetch EPSS scores in batch
    epss_scores = _fetch_epss_scores(cve_ids)

    # Fetch CISA KEV list
    kev_set = _fetch_kev_list()

    results = []
    nvd_api_key = _get_env_key("NVD_API_KEY", "")
    # NVD rate limits: 5 req/30s without key, 50 req/30s with key
    rate_delay = 0.7 if nvd_api_key else 6.5

    for idx, cve_id in enumerate(cve_ids):
        epss_data = epss_scores.get(cve_id, {})
        is_kev = cve_id in kev_set

        # Fetch individual CVE detail from NVD for CVSS score
        cvss = 0.0
        description = ""
        exploit_available = is_kev  # KEV implies exploited
        exploit_refs_list = []
        try:
            url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
            params = {"cveId": cve_id}
            headers = {}
            if nvd_api_key:
                headers["apiKey"] = nvd_api_key
            resp = requests.get(url, params=params, headers=headers, timeout=30)
            if resp.status_code == 403:
                logger.warning("NVD rate limited on %s, sleeping 30s", cve_id)
                sleep(30)
                resp = requests.get(url, params=params, headers=headers, timeout=30)
            if resp.status_code == 200:
                data = resp.json()
                vulns = data.get("vulnerabilities", [])
                if vulns:
                    cve_data = vulns[0].get("cve", {})
                    # Get CVSS score
                    metrics = cve_data.get("metrics", {})
                    for version_key in (
                        "cvssMetricV31",
                        "cvssMetricV30",
                        "cvssMetricV2",
                    ):
                        metric_list = metrics.get(version_key, [])
                        if metric_list:
                            cvss = (
                                metric_list[0].get("cvssData", {}).get("baseScore", 0.0)
                            )
                            break
                    # Get description
                    descs = cve_data.get("descriptions", [])
                    for d in descs:
                        if d.get("lang") == "en":
                            description = d.get("value", "")
                            break
                    # Check references for exploit-db links and exploit tags
                    for ref in cve_data.get("references", []):
                        ref_url = ref.get("url", "")
                        ref_tags = ref.get("tags", [])
                        if "Exploit" in ref_tags:
                            exploit_available = True
                        if "exploit-db.com" in ref_url:
                            exploit_available = True
                            exploit_refs_list.append(
                                {
                                    "url": ref_url,
                                    "title": "ExploitDB: " + ref_url.split("/")[-1],
                                }
                            )
                        elif "Exploit" in ref_tags and ref_url:
                            exploit_refs_list.append(
                                {
                                    "url": ref_url,
                                    "title": ref.get("source", "Exploit"),
                                }
                            )
            elif resp.status_code != 404:
                logger.warning("NVD returned %d for %s", resp.status_code, cve_id)
        except Exception as e:
            logger.warning("NVD detail lookup error for %s: %s", cve_id, e)

        # Rate limit between NVD requests
        if idx < len(cve_ids) - 1:
            sleep(rate_delay)

        exploit_refs_json = json.dumps(exploit_refs_list) if exploit_refs_list else ""

        # Save to database
        VulnIntelligence.objects.update_or_create(
            device=device,
            cve_id=cve_id,
            defaults={
                "cvss_score": cvss,
                "epss_score": epss_data.get("epss", 0.0),
                "epss_percentile": epss_data.get("percentile", 0.0),
                "kev_listed": is_kev,
                "exploit_available": exploit_available,
                "exploit_refs": exploit_refs_json,
                "description": description[:2000],
                "source": "nvd",
            },
        )
        results.append(
            {
                "cve_id": cve_id,
                "cvss": cvss,
                "epss": epss_data.get("epss", 0.0),
                "kev": is_kev,
                "exploit_available": exploit_available,
            }
        )

    return {"status": "ok", "cve_count": len(results), "results": results}


def _fetch_epss_scores(cve_ids):
    """Fetch EPSS scores from the FIRST.org EPSS API.

    Returns a dict mapping CVE ID to {"epss": float, "percentile": float}.
    Batches requests in chunks of 100 to respect API limits.
    """
    if not cve_ids:
        return {}

    # Deduplicate while preserving order
    seen = set()
    unique_cves = []
    for cve in cve_ids:
        if cve not in seen:
            seen.add(cve)
            unique_cves.append(cve)

    url = "https://api.first.org/data/v1/epss"
    batch_size = 100
    results = {}

    for start in range(0, len(unique_cves), batch_size):
        batch = unique_cves[start : start + batch_size]
        if not batch:
            continue
        try:
            params = {"cve": ",".join(batch)}
            resp = requests.get(url, params=params, timeout=30)
            if resp.status_code != 200:
                continue
            data = resp.json()
            for item in data.get("data", []):
                cve = item.get("cve", "")
                if not cve:
                    continue
                results[cve] = {
                    "epss": float(item.get("epss", 0.0)),
                    "percentile": float(item.get("percentile", 0.0)),
                }
        except Exception as e:
            logger.warning("EPSS API error (batch %d): %s", start, e)

    return results


def _fetch_kev_list():
    """Fetch the CISA Known Exploited Vulnerabilities catalog.

    Returns a set of CVE IDs that are on the KEV list.
    """
    try:
        url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        resp = requests.get(url, timeout=30)
        if resp.status_code == 200:
            data = resp.json()
            return {v.get("cveID", "") for v in data.get("vulnerabilities", [])}
    except Exception as e:
        logger.warning("CISA KEV API error: %s", e)
    return set()


# ---------------------------------------------------------------------------
# Honeypot signatures — known patterns for common honeypots
# ---------------------------------------------------------------------------
CONPOT_SIGNATURES = [
    "Siemens, SIMATIC, S7-200",
    "Moxa Nport",
    "Schneider Electric",
]

COWRIE_SIGNATURES = ["SSH-2.0-OpenSSH_5.9p1 Arch Linux-1"]


@shared_task(bind=False)
def honeypot_check(device_id):
    """Analyze a device for honeypot characteristics.

    Checks for:
    - Shodan Honeyscore API (authoritative probability score)
    - Banner density in /24 subnet (>= 500 identical banners indicates honeypot)
    - Conpot/Cowrie signature matching
    - Response time analysis (suspiciously perfect / static times)
    """
    device = Device.objects.get(id=device_id)
    probability = 0.0
    reasons = []
    banner = (device.data or "").strip()
    response_time_ms = 0.0

    # Shodan Honeyscore — authoritative honeypot probability (0.0–1.0)
    ip = device.ip
    api_key = _get_env_key("SHODAN_API_KEY")
    if api_key:
        try:
            resp = requests.get(
                "https://api.shodan.io/labs/honeyscore/{}".format(ip),
                params={"key": api_key},
                timeout=10,
            )
            if resp.status_code == 200:
                score = float(resp.text.strip())
                probability = max(probability, score)
                if score > 0.5:
                    reasons.append(
                        "Shodan Honeyscore: {:.2f} (> 0.5 threshold)".format(score)
                    )
        except Exception as exc:
            logger.warning("Shodan Honeyscore API error for %s: %s", ip, exc)

    # Measure response time to the device
    port = device.port or "80"
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        start = time.perf_counter()
        sock.connect((ip, int(port)))
        response_time_ms = (time.perf_counter() - start) * 1000
        sock.close()

        # Flag suspiciously perfect response times (honeypot indicators)
        rounded_ms = round(response_time_ms, 1)
        if response_time_ms > 0 and (rounded_ms % 10 == 0 or response_time_ms < 1.0):
            probability += 0.15
            reasons.append(
                "Suspiciously static response time: {:.3f}ms".format(response_time_ms)
            )
    except Exception:
        pass

    # Check banner density in /24 subnet
    ip_parts = device.ip.split(".")
    subnet_count = 0
    if len(ip_parts) == 4:
        subnet_prefix = ".".join(ip_parts[:3])
        subnet_devices = Device.objects.filter(ip__startswith=subnet_prefix + ".")
        if banner:
            subnet_count = subnet_devices.filter(data=banner).count()
            if subnet_count >= 500:
                probability += 0.4
                reasons.append(
                    "High banner density: {} identical banners in /{} subnet".format(
                        subnet_count, 24
                    )
                )
            elif subnet_count >= 100:
                probability += 0.2
                reasons.append(
                    "Elevated banner density: {} identical banners in /{} subnet".format(
                        subnet_count, 24
                    )
                )

    # Check Conpot signatures
    is_conpot = False
    for sig in CONPOT_SIGNATURES:
        if sig.lower() in banner.lower():
            is_conpot = True
            probability += 0.3
            reasons.append("Matches Conpot signature: {}".format(sig))
            break

    # Check Cowrie signatures
    is_cowrie = False
    for sig in COWRIE_SIGNATURES:
        if sig.lower() in banner.lower():
            is_cowrie = True
            probability += 0.3
            reasons.append("Matches Cowrie signature: {}".format(sig))
            break

    # Check Shodan scan tags — if Shodan has already tagged this device as a
    # honeypot that is a very strong authoritative signal.
    if ShodanScan.objects.filter(device=device, tags__icontains="honeypot").exists():
        probability = max(probability, 0.8)
        reasons.append("Shodan has tagged this device as 'honeypot'")

    # Cap probability at 1.0
    probability = min(probability, 1.0)

    # Save analysis
    HoneypotAnalysis.objects.update_or_create(
        device=device,
        defaults={
            "probability": probability,
            "reasons": json.dumps(reasons),
            "banner_count_in_subnet": subnet_count,
            "is_conpot": is_conpot,
            "is_cowrie": is_cowrie,
            "response_time_ms": response_time_ms,
        },
    )

    return {
        "probability": probability,
        "reasons": reasons,
        "is_conpot": is_conpot,
        "is_cowrie": is_cowrie,
        "banner_count": subnet_count,
        "response_time_ms": response_time_ms,
    }


@shared_task(bind=False)
def sbom_lookup(device_id):
    """Look up known software components for the device firmware/product.

    Uses the device's CPE string and product name to identify known
    software components (BusyBox, OpenSSL, etc.) that are commonly
    bundled with the firmware model.
    """
    device = Device.objects.get(id=device_id)
    product = (device.product or "").lower()
    cpe = device.cpe or ""
    components_found = []

    # Known firmware component mappings (common ICS/IoT firmware stacks)
    KNOWN_COMPONENTS = {
        "goahead": [
            {
                "name": "GoAhead WebServer",
                "type": "framework",
                "cpe": "cpe:2.3:a:embedthis:goahead",
            },
        ],
        "lighttpd": [
            {
                "name": "lighttpd",
                "type": "framework",
                "cpe": "cpe:2.3:a:lighttpd:lighttpd",
            },
        ],
        "busybox": [
            {"name": "BusyBox", "type": "os", "cpe": "cpe:2.3:a:busybox:busybox"},
        ],
        "hikvision": [
            {"name": "Hikvision Firmware", "type": "framework"},
            {"name": "BusyBox", "type": "os"},
            {"name": "OpenSSL", "type": "library"},
            {"name": "lighttpd", "type": "framework"},
        ],
        "dahua": [
            {"name": "Dahua Firmware", "type": "framework"},
            {"name": "BusyBox", "type": "os"},
            {"name": "OpenSSL", "type": "library"},
        ],
        "siemens": [
            {"name": "Siemens S7 Runtime", "type": "framework"},
        ],
        "schneider": [
            {"name": "Schneider Electric Firmware", "type": "framework"},
            {"name": "OpenSSL", "type": "library"},
        ],
    }

    # Match by product name
    for key, components in KNOWN_COMPONENTS.items():
        if key in product:
            components_found.extend(components)

    # Match by CPE
    if cpe:
        for key, components in KNOWN_COMPONENTS.items():
            if key in cpe.lower():
                for c in components:
                    if c not in components_found:
                        components_found.append(c)

    # Also check Wappalyzer results for web components
    wap_results = WappalyzerResult.objects.filter(device=device)
    for wap in wap_results:
        techs = wap.technologies
        if isinstance(techs, list):
            for entry in techs:
                tech_list = (
                    entry.get("technologies", []) if isinstance(entry, dict) else []
                )
                for tech in tech_list:
                    components_found.append(
                        {
                            "name": tech.get("name", ""),
                            "version": tech.get("version", ""),
                            "type": "library",
                        }
                    )

    # Save components to database — skip empty names, track created-vs-updated
    saved_count = 0
    for comp in components_found:
        name = comp.get("name", "").strip()
        if not name:
            continue
        _, created = SBOMComponent.objects.update_or_create(
            device=device,
            component_name=name,
            defaults={
                "version": comp.get("version", ""),
                "component_type": comp.get("type", "library"),
                "cpe_string": comp.get("cpe", ""),
                "source": "known_mapping",
            },
        )
        if created:
            saved_count += 1

    return {"status": "ok", "components": saved_count}


@shared_task(bind=False)
def gfw_check(device_id):
    """Check if the device IP is reachable from China using the OONI Probe API.

    Queries the OONI API for recent measurement data on the device's IP
    to determine if it's blocked by the Great Firewall.
    """
    device = Device.objects.get(id=device_id)
    ip = device.ip

    reachable = True
    blocking_type = ""
    report_id = ""

    try:
        url = "https://api.ooni.io/api/v1/measurements"
        params = {
            "input": ip,
            "probe_cc": "CN",
            "limit": 5,
            "order_by": "measurement_start_time",
            "order": "desc",
        }
        resp = requests.get(url, params=params, timeout=30)
        if resp.status_code == 200:
            data = resp.json()
            results = data.get("results", [])
            for r in results:
                if r.get("anomaly", False) or r.get("confirmed", False):
                    reachable = False
                    blocking_type = r.get("test_name", "unknown")
                    report_id = r.get("report_id", "")
                    break
                report_id = r.get("report_id", report_id)
        else:
            reachable = False
            blocking_type = "api_error_{}".format(resp.status_code)
    except Exception as e:
        logger.warning("OONI API error for %s: %s", ip, e)

    GFWStatus.objects.update_or_create(
        device=device,
        defaults={
            "reachable": reachable,
            "ooni_report_id": report_id[:200],
            "blocking_type": blocking_type[:100],
        },
    )

    return {
        "reachable": reachable,
        "blocking_type": blocking_type,
        "report_id": report_id,
    }


def check_search_cost(query, country=None):
    """Check the estimated API credit cost of a Shodan search.

    Calls shodan.count() to get the number of results without consuming
    search credits, allowing the UI to show a confirmation dialog.
    Returns dict with 'count' and 'credits_cost'.
    """
    SHODAN_API_KEY = _get_env_key("SHODAN_API_KEY")
    if not SHODAN_API_KEY:
        return {"count": 0, "credits_cost": 0, "error": "No API key configured"}

    try:
        api = Shodan(SHODAN_API_KEY)
        if country:
            query_str = "{} country:{}".format(query, country)
        else:
            query_str = query

        result = api.count(query_str)
        total = result.get("total", 0)
        # Shodan charges 1 credit per 100 results (first page is free)
        credits_cost = max(0, (total // 100))

        return {
            "count": total,
            "credits_cost": credits_cost,
            "query": query_str,
        }
    except Exception as e:
        logger.warning("Shodan count error: %s", e)
        return {"count": 0, "credits_cost": 0, "error": str(e)}


# ---------------------------------------------------------------------------
# ExploitDB Search — uses searchsploit CLI or NVD reference parsing
# ---------------------------------------------------------------------------


@shared_task(bind=True)
def exploitdb_search(self, device_id):
    """Search ExploitDB for exploits matching device CVEs.

    Uses searchsploit CLI (if available) and NVD reference data already
    stored in VulnIntelligence. Results are stored back to exploit_refs.
    """
    progress_recorder = ProgressRecorder(self)
    progress_recorder.set_progress(0, 3, description="Loading device CVEs…")

    device = Device.objects.get(id=device_id)
    vuln_intels = VulnIntelligence.objects.filter(device=device)

    if not vuln_intels.exists():
        return {"exploits": [], "message": "No CVEs found. Run CVE Intelligence first."}

    cve_ids = [vi.cve_id for vi in vuln_intels if vi.cve_id]
    all_exploits = []

    # Check if searchsploit is available
    import shutil

    searchsploit_bin = shutil.which("searchsploit")

    progress_recorder.set_progress(1, 3, description="Searching ExploitDB…")

    for vi in vuln_intels:
        if not vi.cve_id:
            continue

        exploit_refs_list = []

        # Parse existing exploit_refs from NVD data
        if vi.exploit_refs:
            try:
                existing = json.loads(vi.exploit_refs)
                if isinstance(existing, list):
                    exploit_refs_list.extend(existing)
            except (json.JSONDecodeError, TypeError):
                pass

        # Try searchsploit CLI
        if searchsploit_bin:
            try:
                import subprocess

                result = subprocess.run(
                    [searchsploit_bin, "--cve", vi.cve_id, "-j"],
                    capture_output=True,
                    text=True,
                    timeout=30,
                )
                if result.returncode == 0 and result.stdout:
                    ss_data = json.loads(result.stdout)
                    for exp in ss_data.get("RESULTS_EXPLOIT", []):
                        edb_id = exp.get("EDB-ID", "")
                        title = exp.get("Title", "Unknown")
                        url = "https://www.exploit-db.com/exploits/{}".format(edb_id)
                        if not any(r.get("url") == url for r in exploit_refs_list):
                            exploit_refs_list.append(
                                {
                                    "url": url,
                                    "title": title,
                                    "edb_id": str(edb_id),
                                }
                            )
            except Exception as e:
                logger.warning("searchsploit error for %s: %s", vi.cve_id, e)

        if exploit_refs_list:
            vi.exploit_available = True
            vi.exploit_refs = json.dumps(exploit_refs_list)
            vi.save()
            for ref in exploit_refs_list:
                ref["cve_id"] = vi.cve_id
                all_exploits.append(ref)

    progress_recorder.set_progress(3, 3, description="Search complete")
    return {"exploits": all_exploits, "count": len(all_exploits)}


# ---------------------------------------------------------------------------
# Screenshot Capture — uses Selenium headless Chrome
# ---------------------------------------------------------------------------


@shared_task(bind=True)
def capture_screenshot(self, device_id):
    """Capture a screenshot of the device's web interface using Selenium.

    Stores the screenshot as base64 PNG in device.screenshot and returns it.
    Falls back gracefully if Selenium / Chrome are not installed.
    """
    import base64

    progress_recorder = ProgressRecorder(self)
    progress_recorder.set_progress(0, 3, description="Preparing…")

    device = Device.objects.get(id=device_id)
    port = str(device.port or "80").strip().split(",")[0].strip()

    # Determine URL scheme
    if port in ("443", "8443", "9443"):
        target_url = "https://{}:{}".format(device.ip, port)
    else:
        target_url = "http://{}:{}".format(device.ip, port)

    progress_recorder.set_progress(1, 3, description="Capturing {}…".format(target_url))

    try:
        from selenium import webdriver
        from selenium.webdriver.chrome.options import Options
        from selenium.webdriver.chrome.service import Service
    except ImportError:
        return {"error": "Selenium not installed. Run: pip install selenium"}

    try:
        chrome_options = Options()
        chrome_options.add_argument("--headless=new")
        chrome_options.add_argument("--no-sandbox")
        chrome_options.add_argument("--disable-dev-shm-usage")
        chrome_options.add_argument("--disable-gpu")
        chrome_options.add_argument("--window-size=1280,1024")
        chrome_options.add_argument("--ignore-certificate-errors")
        chrome_options.page_load_strategy = "eager"

        driver = webdriver.Chrome(options=chrome_options)
        driver.set_page_load_timeout(20)
        try:
            driver.get(target_url)
            sleep(2)  # Wait for dynamic content
            screenshot_bytes = driver.get_screenshot_as_png()
        finally:
            driver.quit()

        b64_data = base64.b64encode(screenshot_bytes).decode("utf-8")

        progress_recorder.set_progress(2, 3, description="Saving screenshot…")

        device.screenshot = b64_data
        device.save()

        progress_recorder.set_progress(3, 3, description="Done")
        return {"screenshot": b64_data}

    except Exception as e:
        logger.warning("Screenshot capture error for %s: %s", device.ip, e)
        return {"error": "Screenshot failed: {}".format(str(e))}
