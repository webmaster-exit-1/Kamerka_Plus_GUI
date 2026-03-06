import json
import logging
import math
import re
import subprocess

import maxminddb
from libnmap.parser import NmapParser
import os
from time import sleep
import requests
from celery import shared_task, current_task
from celery_progress.backend import ProgressRecorder
from shodan import Shodan
import time
from bs4 import BeautifulSoup
import pynmea2
import base64
import xmltodict

from libnmap.process import NmapProcess
from libnmap.parser import NmapParser
import xmltodict

import urllib.parse
import urllib.request
import xml.etree.ElementTree as et

from app_kamerka import exploits

from app_kamerka.models import Device, DeviceNearby, Search, ShodanScan, \
    Whois, Bosch, WappalyzerResult, NucleiResult

logger = logging.getLogger(__name__)

healthcare_queries = {"zoll": "http.favicon.hash:-236942626",
                      'dicom': "dicom",
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
                      "xero_viewer": "http.title:'XERO Viewer'"}

ics_queries = {"niagara": "port:1911,4911 product:Niagara",
               'bacnet': '"Instance ID:" "Object Name:"',
               'modbus': "Unit ID: 0",
               'siemens': 'Original Siemens Equipment Basic Firmware:',
               'dnp3': "port:20000 source address",
               "ethernetip": '"Product name:" "Vendor ID:"',
               "gestrip": 'port:18245,18246 product:"general electric"',
               'hart': "port:5094 hart-ip",
               'pcworx': "port:1962 PLC",
               "mitsubishi": "port:5006,5007 product:mitsubishi",
               "omron": "port:9600 response code",
               "redlion": 'port:789 product:"Red Lion Controls"',
               'codesys': 'product:"3S-Smart Software Solutions"',
               "iec": "port:2404 asdu address",
               'proconos': "port:20547 PLC",

               "plantvisor": "Server: CarelDataServer",
               "iologik": "iologik",
               "moxa": "Moxa",
               "akcp": "Server: AKCP Embedded Web Server",
               "spidercontrol": "powered by SpiderControl TM",
               "tank": "port:10001 tank",
               "iq3": "Server: IQ3",
               "is2": "IS2 Web Server",
               "vtscada": "Server: VTScada",
               'zworld': "Z-World Rabbit 200 OK",
               "nordex": "html:nordex",
               "sailor": 'title:Sailor title:VSAT',
               'nmea': "$GPGGA",

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
               "total_access": 'ta gen3 port:2000',
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
               }

coordinates_queries = {"videoiq": 'title:"VideoIQ Camera Login"',
                       "hikvision":'product:"Hikvision IP Camera"',
                       "webcam": "device:webcam",
                       "webcamxp": "webcamxp",
                       "vivotek": "vivotek",
                       "netwave": 'product:"Netwave IP camera http config"',
                       "techwin": "techwin",
                       "lutron": 'html:<h1>LUTRON</h1>',
                       "mobotix": "mobotix",
                       "iqinvision": "iqinvision",
                       "grandstream": 'ssl:"Grandstream" "Set-Cookie: TRACKID"',
                       "amcrest": 'html:"@WebVersion@" html:amcrest',
                       "contec": '"content/smarthome.php"',
                       'printer': "device:printer",
                       'mqtt': 'product:mqtt',
                       'rtsp': "port:'554'",
                       "ipcamera": "IPCamera_Logo",
                       "yawcam": "yawcam",
                       "blueiris": "http.favicon.hash:-520888198",
                       'ubnt': "UBNT Streaming Server",
                       "go1984": "go1984",
                       "dlink": "Server: Camera Web Server",
                       "avtech": "linux upnp avtech",
                       "adh": "ADH-web",
                       "axis": 'http.title:"axis" http.html:live',
                       "rdp": "has_screenshot:true port:3389",
                       "vnc": "has_screenthos:true port:5901",
                       "screenshot": "has_screenshot:true !port:3389 !port:3388 !port:5900",
                       "bbvs": "Server: BBVS",
                       "baudisch": "http.favicon.hash:746882768",
                       "loxone_intercom": "title:'Loxone Intercom Video'",

                       "idss": "Intelligent Digital Security System",
                       "webiopi": 'webiopi 200 ok',
                       "iobroker": "ioBroker.admin",
                       "comelit": "html:comelit",

                       "niagara": "port:1911,4911 product:Niagara",
                       'bacnet': '"Instance ID:" "Object Name:"',
                       'modbus': "Unit ID: 0",
                       'siemens': 'Original Siemens Equipment Basic Firmware:',
                       'dnp3': "port:20000 source address",
                       "ethernetip": '"Product name:" "Vendor ID:"',
                       "gestrip": 'port:18245,18246 product:"general electric"',
                       'hart': "port:5094 hart-ip",
                       'pcworx': "port:1962 PLC",
                       "mitsubishi": "port:5006,5007 product:mitsubishi",
                       "omron": "port:9600 response code",
                       "redlion": 'port:789 product:"Red Lion Controls"',
                       'codesys': "port:2455 operating system",
                       "iec": "port:2404 asdu address",
                       'proconos': "port:20547 PLC",

                       "plantvisor": "Server: CarelDataServer",
                       "iologik": "iologik",
                       "moxa": "Moxa",
                       "akcp": "Server: AKCP Embedded Web Server",
                       "spidercontrol": "powered by SpiderControl TM",
                       "tank": "port:10001 tank",
                       "iq3": "Server: IQ3",
                       "is2": "IS2 Web Server",
                       "vtscada": "Server: VTScada",
                       'zworld': "Z-World Rabbit",
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
                       "total_access": 'ta gen3 port:2000',
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
                       "GNSS": "NTRIP" "SOURCETABLE",
                       "traccar": "title:traccar",
                       "trimble": 'html:"trimble Navigation"',
                       "spacelynk": "title:spaceLYnk",
                       }

attackers_infra_queries = {"cobaltstrike": 'product:"Cobalt Strike Beacon"',
                           "msf": 'ssl:MetasploitSelfSignedCA',
                           "covenant": 'ssl:”Covenant” http.component:”Blazor”',
                           "mythic": 'ssl:"Mythic" port:7443',
                           "bruteratel": "http.html_hash:-1957161625",
                           }



def _get_env_key(name, *, required=False):
    """Return an environment variable value.

    Logs a warning when a key that is marked *required* is missing so that
    operators know immediately which variable to set, without crashing the
    whole worker on startup.
    """
    value = os.environ.get(name, "")
    if required and not value:
        logger.warning(
            "Environment variable %s is not set. "
            "Features that depend on it will fail at runtime. "
            "Set it in your shell or in a .env file.",
            name,
        )
    return value



@shared_task(bind=False)
def devices_nearby(lat, lon, id, query):
    SHODAN_API_KEY = _get_env_key('SHODAN_API_KEY', required=True)

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
        total = len(results['matches'])
        for counter, result in enumerate(results['matches']):
            if 'product' in result:
                product = result['product']
            else:
                product = ""
            current_task.update_state(state='PROGRESS',
                                      meta={'current': counter, 'total': total,
                                            'percent': int((float(counter) / total) * 100)})
            device1 = DeviceNearby(device=device, ip=result['ip_str'], product=product, org=result['org'],
                                   port=str(result['port']), lat=str(result['location']['latitude']),
                                   lon=str(result['location']['longitude']))
            device1.save()

        return {'current': total, 'total': total, 'percent': 100}
    except Exception as e:
        logger.warning("%s", e)


@shared_task(bind=True)
def shodan_search(self, fk, country=None, coordinates=None, ics=None, healthcare=None, coordinates_search=None,
                  all_results=False, infra=None):
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
                        shodan_search_worker(country=country, fk=fk, query=healthcare_queries[i], search_type=i,
                                             category="healthcare",
                                             all_results=all_results)
                        progress_recorder.set_progress(c + 1, total=total)
                    except Exception:
                        pass
            else:

                if i in ics_queries:
                    try:
                        result += c
                        shodan_search_worker(country=country, fk=fk, query=ics_queries[i], search_type=i,
                                             category="ics",
                                             all_results=all_results)
                        progress_recorder.set_progress(c + 1, total=total)
                    except Exception:
                        pass

                if i in attackers_infra_queries:
                    try:
                        result += c
                        shodan_search_worker(country=country, fk=fk, query=attackers_infra_queries[i], search_type=i,
                                             category="infra",
                                             all_results=all_results)
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
                    shodan_search_worker(fk=fk, query=coordinates_queries[i], search_type=i, category="coordinates",
                                         coordinates=coordinates, all_results=all_results)
                    progress_recorder.set_progress(c + 1, total=total)
                except Exception:
                    pass
    return result


def check_credits():
    keys_list = []
    try:
        SHODAN_API_KEY = _get_env_key('SHODAN_API_KEY', required=True)

        api = Shodan(SHODAN_API_KEY)
        a = api.info()
        keys_list.append(a['query_credits'])
    except Exception as e:
        logger.warning("%s", e)

    return keys_list


def shodan_search_worker(fk, query, search_type, category, country=None, coordinates=None, all_results=False):
    results = True
    page = 1
    SHODAN_API_KEY = _get_env_key('SHODAN_API_KEY', required=True)
    pages = 0
    screenshot = ""
    print(query)
    # print(coordinates)
    # print(country)

    while results:
        if pages == page:
            results = False
            break

        # Shodan sometimes fails with no reason, sleeping when it happens and it prevents rate limitation
        search = Search.objects.get(id=fk)
        api = Shodan(SHODAN_API_KEY)
        fail = False

        while not fail:
            try:
                time.sleep(3)
                if coordinates:
                    results = api.search("geo:" + coordinates + ",20 " + query, page)
                    # print(results)
                    fail = True
                    # print("geo:" + coordinates + ",20 " + query)
                elif country == "XX":
                    results = api.search(query, page)
                    fail = True
                else:
                    results = api.search("country:" + country + " " + query, page)
                    fail = True
            except Exception as exc:
                fail = False
                logger.warning("shodan_search_worker: Shodan API call failed, will retry: %s", exc)
                # Brief back-off before retrying to respect Shodan's rate limit.
                sleep(2)

        try:
            total = results['total']

            if total == 0:
                print("no results")
                break
        except Exception as e:
            logger.warning("%s", e)
            break

        # print(results)
        pages = math.ceil(total / 100) + 1
        print("Pages: " + str(pages))
        for counter, result in enumerate(results['matches']):
            lat = str(result['location']['latitude'])
            lon = str(result['location']['longitude'])
            city = ""
            indicator = []

            try:
                product = result['product']
            except Exception:
                product = ""

            if 'vulns' in result:
                vulns = [*result['vulns']]
            else:
                vulns = ""

            if result['location']['city'] != None:
                city = result['location']['city']

            hostnames = ""
            try:
                if 'hostnames' in result:
                    hostnames = result['hostnames'][0]
            except Exception:
                pass

            try:
                if 'SAILOR' in result['http']['title']:
                    html = result['http']['html']
                    soup = BeautifulSoup(html)
                    for gps in soup.find_all("span", {"id": "gnss_position"}):
                        coordinates = gps.contents[0]
                        space = coordinates.split(' ')
                        if "W" in space:
                            lon = "-" + space[2][:-1]
                        else:
                            lon = space[2][:-1]
                        lat = space[0][:-1]
            except Exception as e:
                pass

            if 'opts' in result:
                try:
                    screenshot = result['opts']['screenshot']['data']

                    with open("app_kamerka/static/images/screens/" + result['ip_str'] + ".jpg", "wb") as fh:
                        fh.write(base64.b64decode(screenshot))
                        fh.close()
                        for i in result['opts']['screenshot']['labels']:
                            indicator.append(i)
                except Exception as e:
                    pass

            if query == "Niagara Web Server":
                try:
                    soup = BeautifulSoup(result['http']['html'], features="html.parser")
                    nws = soup.find("div", {"class": "top"})
                    indicator.append(nws.contents[0])
                except Exception:
                    pass

            if "SOURCETABLE" in query:
                data = result['data'].split(";")
                try:
                    if re.match(r"^((\-?|\+?)?\d+(\.\d+)?)$", data[9]):
                        indicator.append(data[9] + "," + data[10])
                        lat = data[9]
                        lon = data[10]
                    else:
                        pass
                except Exception as e:
                    pass

            # get indicator from niagara fox
            if result['port'] == 1911 or result['port'] == 4911:
                try:
                    fox_data_splitted = result['data'].split("\n")
                    for i in fox_data_splitted:
                        if "station.name" in i:
                            splitted = i.split(":")
                            indicator.append(splitted[1])
                except Exception:
                    pass

            # get indicator from tank
            if result['port'] == 10001 and "Siemens" not in query:
                try:
                    tank_info = result['data'].split("\r\n\r\n")
                    indicator.append(tank_info[1])
                except Exception:
                    pass

            if result['port'] == 2000:
                try:
                    ta_data = result['data'].split("\\n")
                    indicator.append(ta_data[1][:-3])
                except Exception as e:
                    pass

            if result['port'] == 502:
                try:
                    sch_el = result['data'].split('\n')
                    if sch_el[4].startswith("-- Project"):
                        indicator.append(sch_el[4].split(": ")[1])
                except Exception:
                    pass

            if "GPGGA" in result['data']:
                try:
                    splitted_data = result['data'].split('\n')
                    for i in splitted_data:
                        if "GPGGA" in i:
                            msg = pynmea2.parse(i)
                            lat = msg.latitude
                            lon = msg.longitude
                            break
                except Exception as e:
                    pass

            if result['port'] == 102:
                try:
                    s7_data = result['data'].split("\n")
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
            if result['port'] == 47808:
                try:
                    bacnet_data_splitted = result['data'].split("\n")
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

            device = Device(search=search, ip=result['ip_str'], product=product, org=result['org'],
                            data=result['data'], port=str(result['port']), type=search_type, city=city,
                            lat=lat, lon=lon,
                            country_code=result['location']['country_code'], query=search_type, category=category,
                            vulns=vulns, indicator=indicator, hostnames=hostnames, screenshot=screenshot)
            device.save()

        page = page + 1
        if not all_results:
            results = False


def nmap_host_worker(host_arg, max_reader, search):
    ports_list = []
    hostname = host_arg.hostnames[0] if host_arg.hostnames else ""

    a = max_reader.get(host_arg.address)
    if a is None:
        logger.warning("MaxMind lookup returned no result for IP: %s", host_arg.address)
        a = {}
    location = a.get('location') or {}
    lat = location.get('latitude')
    lon = location.get('longitude')
    if lat is None or lon is None:
        logger.warning("Missing latitude/longitude in MaxMind data for IP: %s", host_arg.address)
    country = a.get('country') or {}
    country_code = country.get('iso_code', '')
    logger.debug("lat=%s lon=%s", lat, lon)
    for ports in host_arg.services:
        if ports.state == 'open':
            ports_list.append(ports.port)
        else:
            ports_list.append("None")

    ports_string = ', '.join(str(e) for e in ports_list)
    logger.debug("ports_string length=%d", len(ports_string))
    device = Device(search=search, ip=host_arg.address, product="", org="",
                    data="", port=ports_string, type="NMAP", city="NMAP",
                    lat=lat if lat is not None else "",
                    lon=lon if lon is not None else "",
                    country_code=country_code, query="NMAP SCAN", category="NMAP",
                    vulns="", indicator="", hostnames=hostname, screenshot="")
    device.save()


def validate_nmap(file):
    NmapParser.parse_fromfile(file)


def validate_maxmind():
    try:
        maxminddb.open_database('GeoLite2-City.mmdb')
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
    max_reader = maxminddb.open_database('GeoLite2-City.mmdb')
    nmap_report = NmapParser.parse_fromfile(file)
    total = len(nmap_report.hosts)
    for c, i in enumerate(nmap_report.hosts):
        result += c
        nmap_host_worker(host_arg=i, max_reader=max_reader, search=search)
        progress_recorder.set_progress(c + 1, total=total)
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
                ip, max_scans, window_seconds,
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
            exc, ip,
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
        for part in re.split(r'[,\s]+', existing):
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

    discovery_ports = getattr(_s, 'NAABU_DISCOVERY_PORTS', '1-65535')
    discovery_timeout = getattr(_s, 'NAABU_DISCOVERY_TIMEOUT', 120)
    logger.info(
        "_resolve_open_ports: running Naabu discovery against %s (ports: %s)",
        device.ip, discovery_ports,
    )
    results = run_naabu(device.ip, ports=discovery_ports, timeout=discovery_timeout)
    if results:
        open_ports = sorted(set(r['port'] for r in results if r.get('port')))
        device.port = ', '.join(str(p) for p in open_ports)
        device.save(update_fields=['port'])
        logger.info(
            "_resolve_open_ports: discovered ports %s on %s",
            device.port, device.ip,
        )
        return open_ports

    logger.warning(
        "_resolve_open_ports: no open ports found on %s "
        "(host may be unreachable or all ports filtered)", device.ip
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
        ipaddress_mod = __import__('ipaddress')
        ipaddress_mod.ip_address(device.ip)  # basic SSRF guard
    except ValueError:
        return {"error": "Invalid IP address: {}".format(device.ip)}

    # Rate limiting — abort if this IP is being scanned too aggressively.
    if not _rate_limit_check(device.ip):
        return {"error": "Rate limit exceeded for {} — try again in 60 seconds".format(device.ip)}

    ports = discovered_ports if discovered_ports is not None else _resolve_open_ports(device)
    if not ports:
        return {"error": "No open ports discovered on {} — Naabu may not be installed "
                "(see KAMERKA_NAABU_BIN) or the host is unreachable".format(device.ip)}

    all_technologies = {}
    for url, is_known_tls in _build_target_urls(device.ip, ports):
        # Extract port number once for use in logging and dict keys.
        port = int(url.rsplit(":", 1)[-1])

        def _try_wappalyzer(target_url):
            return subprocess.run(
                ["wappalyzer", target_url, "-oJ"],
                capture_output=True, text=True, timeout=60,
            )

        try:
            result = _try_wappalyzer(url)
            # Two-pass: if we used http:// and got an SSL error, retry with https://
            if not is_known_tls and result.returncode != 0 and (
                "ssl" in result.stderr.lower() or "tls" in result.stderr.lower()
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
            logger.warning("wappalyzer_scan: JSON parse error on %s:%s", device.ip, port)
        except Exception as exc:
            logger.warning("wappalyzer_scan: error on %s:%s — %s", device.ip, port, exc)

    return all_technologies if all_technologies else {"error": "No output from Wappalyzer on any port"}


@shared_task(bind=False)
def nuclei_scan(id, templates_dir=None, severity=None, rate_limit=150, discovered_ports=None):
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
            return {"error": "Invalid severity '{}'. Must be one of: {}".format(
                severity, ", ".join(sorted(_VALID_SEVERITIES)))}

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
        ipaddress_mod = __import__('ipaddress')
        ipaddress_mod.ip_address(device.ip)
    except ValueError:
        return {"error": "Invalid IP address: {}".format(device.ip)}

    # Rate limiting.
    if not _rate_limit_check(device.ip):
        return {"error": "Rate limit exceeded for {} — try again in 60 seconds".format(device.ip)}

    ports = discovered_ports if discovered_ports is not None else _resolve_open_ports(device)
    if not ports:
        return {"error": "No open ports discovered on {} — Naabu may not be installed "
                "(see KAMERKA_NAABU_BIN) or the host is unreachable".format(device.ip)}

    # Build target URLs — both http:// and https:// variants for non-TLS ports
    # so Nuclei can probe both.  Well-known TLS ports get https:// directly.
    target_urls = [url for url, _ in _build_target_urls(device.ip, ports)]
    # Also add https:// variant for every non-TLS port so Nuclei covers both.
    for url, is_tls in _build_target_urls(device.ip, ports):
        if not is_tls:
            target_urls.append(url.replace("http://", "https://", 1))

    targets_file = None
    try:
        fd, targets_file = _tmp.mkstemp(suffix='.txt', text=True)
        try:
            with os.fdopen(fd, 'w') as tf:
                tf.write('\n'.join(target_urls) + '\n')
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

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=nuclei_timeout,
        )
        findings = []
        if result.stdout.strip():
            for line in result.stdout.strip().split("\n"):
                try:
                    finding = json.loads(line)
                    nuclei_result = NucleiResult(
                        device=device,
                        template_id=finding.get("template-id", ""),
                        name=finding.get("info", {}).get("name", ""),
                        severity=finding.get("info", {}).get("severity", ""),
                        matched_at=finding.get("matched-at", ""),
                        description=finding.get("info", {}).get("description", ""),
                        raw_output=line[:10000],
                    )
                    nuclei_result.save()
                    findings.append(finding)
                except json.JSONDecodeError:
                    continue

        return {"findings_count": len(findings), "findings": findings}
    except FileNotFoundError:
        return {"error": "Nuclei binary not installed"}
    except subprocess.TimeoutExpired:
        return {"error": "Nuclei scan timed out"}
    except Exception as exc:
        return {"error": str(exc)}
    finally:
        if targets_file and os.path.exists(targets_file):
            os.unlink(targets_file)


def paste_login(username, password, key):
    login_url = "https://pastebin.com/api/api_login.php"
    login_payload = {"api_dev_key": key, "api_user_name": username, "api_user_password": password}

    login = requests.post(login_url, data=login_payload)
    user_key = login.text
    return user_key


def retrieve_pastes(key, user_key):
    url = "http://pastebin.com/api/api_post.php"
    paste_dict = {}

    values_list = {'api_option': 'list',
                   'api_dev_key': key,
                   'api_user_key': user_key}

    data = urllib.parse.urlencode(values_list)
    data = data.encode('utf-8')  # data should be bytes
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

    values_list = {'api_option': 'delete',
                   'api_dev_key': key,
                   'api_user_key': user_key,
                   "api_paste_key": paste_code}

    data = urllib.parse.urlencode(values_list)
    data = data.encode('utf-8')  # data should be bytes
    req = urllib.request.Request(url, data)
    urllib.request.urlopen(req)


def create_paste(key, user_key, filename, text):
    url = "http://pastebin.com/api/api_post.php"

    values = {'api_option': 'paste',
              'api_dev_key': key,
              'api_paste_code': text,
              'api_paste_private': '2',
              'api_paste_name': filename,
              'api_user_key': user_key}

    data = urllib.parse.urlencode(values)
    data = data.encode('utf-8')  # data should be bytes
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
        logger.warning("send_to_field_agent_task: ShodanScan record not found for device %s — skipping enrichment", id)

    user_key = paste_login(_get_env_key('PASTEBIN_USER'), _get_env_key('PASTEBIN_PASSWORD'),
                           _get_env_key('PASTEBIN_DEV_KEY'))

    pastes = retrieve_pastes(_get_env_key('PASTEBIN_DEV_KEY'), user_key=user_key)

    ip = af.ip
    lat = af.lat
    lon = af.lon
    org = af.org
    type = af.type

    notes = af.notes

    merge_string = "ꓘ;" + lat + ";" + lon + ";" + ip + ";" + ports + ";" + org + ";" + type + ";" + cve + ";" + indicator + ";" + notes

    print("\\xea\\x93\\x98amerka_" + af.ip)
    if "\\xea\\x93\\x98amerka_" + af.ip in pastes.keys():
        delete_paste(_get_env_key('PASTEBIN_DEV_KEY'), user_key, pastes["\\xea\\x93\\x98amerka_" + af.ip])
        create_paste(_get_env_key('PASTEBIN_DEV_KEY'), user_key, "ꓘamerka_" + af.ip, merge_string)
    else:
        create_paste(_get_env_key('PASTEBIN_DEV_KEY'), user_key, "ꓘamerka_" + af.ip, merge_string)



@shared_task(bind=False)
def shodan_scan_task(id):
    SHODAN_API_KEY = _get_env_key('SHODAN_API_KEY', required=True)
    device = Device.objects.get(id=id)
    api = Shodan(SHODAN_API_KEY)
    product = []
    tags = []
    vulns = []
    try:
        # Search Shodan
        results = api.host(device.ip)
        # Show the results
        total = len(results['ports'])
        print(total)
        for counter, i in enumerate(results['data']):

            if 'product' in i:
                product.append(i['product'])

            if 'tags' in i:
                for j in i['tags']:
                    tags.append(j)

            current_task.update_state(state='PROGRESS',
                                      meta={'current': counter, 'total': total,

                                            'percent': int((float(counter) / total) * 100)})
        if 'vulns' in results:
            vulns = results['vulns']

        ports = results['ports']
        device1 = ShodanScan(device=device, products=product,
                             ports=ports, tags=tags, vulns=vulns)
        device1.save()
        print(results['ports'])

        return {'current': total, 'total': total, 'percent': 100}

    except Exception as e:
        print(e.args)


ics_scan = {"dnp3": "--script=nmap_scripts/dnp3-info.nse", "niagara": "--script=nmap_scripts/fox-info.nse",
            "siemens": "--script=nmap_scripts/s7-info.nse", "proconos": "--script=nmap_scripts/proconos-info.nse",
            "pcworx": "--script=nmap_scripts/pcworx-info.nse", "omron": "--script=nmap_scripts/omron-info.nse",
            "modbus": "--script=nmap_scripts/modbus-discover.nse", "ethernetip": "--script=nmap_scripts/enip-info.nse",
            "codesys": "--script=nmap_scripts/codesys.nse", "ab_ethernet": "--script=nmap_scripts/cspv4-info.nse",
            "tank": "--script=nmap_scripts/atg-info.nse", "modicon": "--script=nmap_scripts/modicon-info.nse"}


@shared_task(bind=False)
def scan(id):
    return_dict = {}
    device1 = Device.objects.get(id=id)
    ip = device1.ip
    port = device1.port
    type = device1.type

    if type in ics_scan.keys():
        nm = NmapProcess(ip, options="-p " + str(port) + " " + ics_scan[type])
        nm.run_background()

        while nm.is_running():
            print("Nmap Scan running: ETC: {0} DONE: {1}%".format(nm.etc,
                                                                  nm.progress))
            sleep(2)

        u = xmltodict.parse(nm.stdout)
        print(u['nmaprun'])

        try:
            for i in u['nmaprun']['host']['ports']['port']['script']:
                print(i)

                if i == "@output":
                    return_dict["ID"] = u['nmaprun']['host']['ports']['port']['script']["@id"]
                    return_dict["Output"] = u['nmaprun']['host']['ports']['port']['script']["@output"]

            device1.scan = return_dict
            device1.exploited_scanned = True
            device1.save()
            return return_dict


        except Exception as e:
            logger.warning("%s", e)
            return_dict["State"] = u['nmaprun']['host']['ports']['port']['state']["@state"]
            return_dict["Reason"] = u['nmaprun']['host']['ports']['port']['state']["@reason"]
            device1.scan = return_dict
            device1.exploited_scanned = True

            device1.save()
            return return_dict


    else:
        nm = NmapProcess(ip, options="-p " + str(port))
        nm.run_background()

        while nm.is_running():
            print("Nmap Scan running: ETC: {0} DONE: {1}%".format(nm.etc,
                                                                  nm.progress))
            sleep(2)

        u = xmltodict.parse(nm.stdout)

        try:
            return_dict["State"] = u['nmaprun']['host']['ports']['port']['state']['@state']
            return_dict["Reason"] = u['nmaprun']['host']['ports']['port']['state']['@reason']
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

        network = result.get('network', {})
        netrange = network.get('cidr', "")

        entities = result.get('objects', {})
        for key, entity in entities.items():
            roles = entity.get('roles', [])
            contact = entity.get('contact') or {}

            entity_name = contact.get('name', "") or ""
            entity_org = (contact.get('org') or [{}])[0].get('value', "")
            entity_email = (contact.get('email') or [{}])[0].get('value', "")
            entity_phone = (contact.get('phone') or [{}])[0].get('value', "")
            address_parts = contact.get('address') or []
            entity_street = address_parts[0].get('value', "") if address_parts else ""
            entity_city = ""
            if entity_street and '\n' in entity_street:
                lines = [l.strip() for l in entity_street.split('\n') if l.strip()]
                entity_street = lines[0] if lines else entity_street
                entity_city = lines[1] if len(lines) > 1 else ""

            if 'registrant' in roles or 'abuse' in roles:
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

            if 'administrative' in roles or 'technical' in roles:
                if not admin_org:
                    admin_org = entity_org or entity_name
                if not admin_email:
                    admin_email = entity_email
                if not admin_phone:
                    admin_phone = entity_phone

    except Exception as e:
        logger.warning("ipwhois lookup failed for %s: %s", device1.ip, e)

    wh = Whois(device=device1, org=org,
               street=street,
               city=city,
               admin_org=admin_org,
               admin_email=admin_email,
               admin_phone=admin_phone, netrange=netrange, name=name, email=email)

    wh.save()


def shodan_csv_export(search_id, output_path):
    """Export Shodan device data to CSV for SandDance 3D visualization."""
    import pandas as pd

    devices = Device.objects.filter(search_id=search_id)
    records = []
    for d in devices:
        vuln_count = 0
        if d.vulns:
            try:
                vuln_list = json.loads(d.vulns.replace("'", '"'))
                vuln_count = len(vuln_list) if isinstance(vuln_list, list) else 0
            except (json.JSONDecodeError, ValueError):
                pass

        records.append({
            "IP_Address": d.ip,
            "Latitude": d.lat,
            "Longitude": d.lon,
            "Severity_Count": vuln_count,
            "Vendor_Name": d.product,
            "Network_Port": d.port,
            "Organization": d.org or "",
            "City": d.city or "",
            "Country_Code": d.country_code,
            "Device_Type": d.type,
        })

    _CSV_COLUMNS = [
        "IP_Address", "Latitude", "Longitude", "Severity_Count",
        "Vendor_Name", "Network_Port", "Organization", "City",
        "Country_Code", "Device_Type",
    ]
    df = pd.DataFrame(records, columns=_CSV_COLUMNS)
    df.to_csv(output_path, index=False)
    return output_path


def shodan_kml_export(search_id, output_path):
    """Export Shodan device data to KML for Mapbox geospatial intelligence."""
    import simplekml

    devices = Device.objects.filter(search_id=search_id)
    kml = simplekml.Kml()

    for d in devices:
        try:
            lon = float(d.lon)
            lat = float(d.lat)
        except (ValueError, TypeError):
            continue

        name = "{} - {}".format(d.product or "Unknown", d.ip)
        pnt = kml.newpoint(name=name, coords=[(lon, lat)])
        pnt.description = "IP: {}\nPort: {}\nOrg: {}\nCity: {}\nVulns: {}".format(
            d.ip, d.port, d.org or "", d.city or "", d.vulns or "None"
        )

        ext = pnt.extendeddata
        ext.newdata("ip", d.ip)
        ext.newdata("port", d.port)
        ext.newdata("product", d.product or "")
        ext.newdata("org", d.org or "")
        ext.newdata("country_code", d.country_code or "")
        ext.newdata("vulns", d.vulns or "")

    kml.save(output_path)
    return output_path


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
                    "scripts": {s['id']: s['output'] for s in svc.scripts_results} if svc.scripts_results else {}
                }

        device1.scan = json.dumps(return_dict)
        device1.exploited_scanned = True
        device1.save()
    except Exception as e:
        return_dict["error"] = str(e)

    return return_dict
