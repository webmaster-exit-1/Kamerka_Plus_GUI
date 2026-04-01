import ast
import json
import logging
import os
from collections import Counter
from django.conf import settings
from django.core.files.storage import FileSystemStorage
from .forms import UploadFileForm
import pycountry
from celery.result import AsyncResult
from django.core import serializers
from django.db.models import Count, Max, Exists, OuterRef, Subquery, FloatField
from django.db.models.functions import Coalesce
from django.http import HttpResponse, JsonResponse
from django.http import HttpResponseRedirect
from django.shortcuts import render
from app_kamerka import forms
from app_kamerka.models import (
    Search,
    Device,
    DeviceNearby,
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
from kamerka.tasks import (
    shodan_search,
    devices_nearby,
    shodan_scan_task,
    whoisxml,
    check_credits,
    send_to_field_agent_task,
    nmap_scan,
    validate_nmap,
    validate_maxmind,
    scan,
    exploit,
    wappalyzer_scan,
    nuclei_scan,
    shodan_csv_export,
    shodan_kml_export,
    shodan_json_export,
    nmap_rtsp_scan,
    port_scan_task,
    deep_protocol_scan,
    nvd_lookup,
    honeypot_check,
    sbom_lookup,
    gfw_check,
    check_search_cost,
    nmap_device_scan,
    NSE_SCRIPT_CATALOG,
    exploitdb_search,
    capture_screenshot,
)

_views_logger = logging.getLogger(__name__)


def _parse_vulns(raw):
    """Parse a Device.vulns string (Python list literal) into a list of CVE IDs.

    Returns an empty list when the value is absent, unparseable, or not a list.
    """
    if not raw:
        return []
    try:
        result = ast.literal_eval(raw)
        return result if isinstance(result, list) else []
    except Exception:
        return []


# Create your views here.

passwds = {
    "bosch_security": """The Bosch Video Recorder 630/650 Series is an 8/16
          channel digital recorder that uses the latest H.264
          compression technology. With the supplied PC
          software and built-in web server, the 630/650 Series is
          a fully integrated, stand-alone video management
          solution that's ready to go, straight out of the box.
          Available with a variety of storage capacities, the
          630/650 Series features a highly reliable embedded
          design that minimizes maintenance and reduces
          operational costs. The recorder is also available with a
          built-in DVD writer <br>
          https://www.exploit-db.com/exploits/34956 """,
    "niagara": "Tridium is the developer of Niagara Framework® — a comprehensive software platform for the development and deployment of connected products and device-to-enterprise applications. Niagara provides the critical device connectivity, cyber security, control, data management, device management and user presentation capabilities needed to extract value and insight from real-time operational data <br> Default credentials: <br>tridium:niagara",
    "siemens": "S7 (S7 Communication) is a Siemens proprietary protocol that runs between programmable logic controllers (PLCs) of the Siemens S7 family. <br>Default credentials: <br> Hardcoded password: Basisk:Basisk <br> admin:blank",
    "bacnet": "BACnet is a communications protocol for building automation and control networks. It was designed to allow communication of building automation and control systems for applications such as heating, air-conditioning, lighting, and fire detection systems.",
    "modbus": "Modbus is a popular protocol for industrial control systems (ICS). It provides easy, raw access to the control system without requiring any authentication.",
    "dnp3": "DNP3 (Distributed Network Protocol) is a set of communications protocols used between components in process automation systems. Its main use is in utilities such as electric and water companies.",
    "plantivosr": "PlantVisor Enhanced is monitoring and telemaintenance software for refrigeration and air-conditioning systems controlled by CAREL instruments. PlantVisor, thanks to the embedded Web Server, can be used on a series of PCs connected to a TCP/IP network. In this way, the information can be shared by a number of users at the same time. <br> Default credentials: <br> admin:admin",
    "iologik": "The ioLogik E1200 Series supports the most often-used protocols for retrieving I/O data, making it capable of handling a wide variety of applications. Most IT engineers use SNMP or RESTful API protocols, but OT engineers are more familiar with OT-based protocols, such as Modbus and EtherNet/IP. <br>Default credentials: <br> administrator:blank",
    "akcp": "The AKCP sensorProbe+ series of base units are our flagship Remote Environmental Sensor Monitoring Device. Our sensor monitoring systems are deployed in a wide variety of industries including Data Center Environmental Monitoring, Warehouse Temperature Monitoring, Cold Storage Temperature Monitoring, Fuel / Generator Monitoring, and other Remote Site Monitoring applications.<br>Default credentials: <br> administrator:public <br> admin:public",
    "vtscada": "https://www.vtscada.com/wp-content/uploads/2016/09/VTScada11-2-AdminGuide.pdf",
    "sailor": "<br>Default credentials: <br> admin:1234 <br> https://www.livewire-connections.com/sites/default/files/files/documents/Sailor%20900%20Ka%20Installation%20Manual.pdf",
    "digi": "Digi TransPort WR21 is a full-featured cellular router offering the flexibility to scale from basic connectivity applications to enterprise class routing and security solutions. With its high-performance architecture, Digi TransPort WR21 provides primary and backup WWAN connectivity over 3G/4G/LTE. The platform includes software selectable multi-carrier and regional LTE variants. <br>Default credentials:<br>username:password",
    "ilon": "The i.LON® SmartServer is a low-cost, high-performance controller, network manager, router, remote network interface, and Web server that you can use to connect LONWORKS®, Modbus, and M-Bus devices to corporate IP networks or the Internet.  <br>Default credentials: <br> for ftp and lns servers:, ilon:ilon <br> ",
    "eig": "<br>Default credentials: <br> anonymous:anonymous <br> eignet:inp100",
    "mitsubishi": "<br>Default credentials: <br> MELSEC:MELSEC <br> QNUDECPU:QNUDECPU <br> MELSEC-Q Series use a proprietary network protocol for communication. The devices are used by equipment and manufacturing facilities to provide high-speed, large volume data processing and machine control.",
    "moxahttp": "NPort® 5100 device servers are designed to make serial devices network-ready in an instant. The small size of the servers makes them ideal for connecting devices such as card readers and payment terminals to an IP-based Ethernet LAN. Use the NPort 5100 device servers to give your PC software direct access to serial devices from anywhere on the network. <br>Default credentials: <br> admmin:moxa",
    "omron": "FINS, Factory Interface Network Service, is a network protocol used by Omron PLCs, over different physical networks like Ethernet, Controller Link, DeviceNet and RS-232C. <br>Default credentials: <br> for http: ETHERNET, for ftp: CONFIDENTIAL <br> default:default",
    "power_logic": "https://www.se.com/ww/en/product-range/62252-powerlogic-pm8000-series/?selected-node-id=12146165208#tabs-top <br>Default credentials: <br> 0000 <br> 0 <br> Administrator:Gateway <br> Administrator:admin, User 1:master, User 2:engineer, User 3:operator",
    "scalance": "SCALANCE network components form the basis of communication networks in manufacturing and process automation. Make your industrial networks fit for the future! SCALANCE products have been specially designed for use in industrial applications. As a result, they fulfill all requirements for ultra-efficient industrial networks and bus systems. Whether switching, routing, security applications, remote access or Industrial Wireless LAN – SCALANCE is the solution!  <br>Default credentials: <br> admin:admin (HTTP), user:user (HTTP), siemens:siemens (FTP)",
    "stulz_klimatechnik": "he WIB (Web Interface Board) is an interface between STULZ air conditioning units and the intranet or inter-net via an ethernet connection. This connection allows monitoring and control of  A/C units. On the operators’s side the appropriate hardware (PC or server) and the appropriate software (SNMP client and/or web browser) are necessary. <br>Default credentials: <br> Administrator, highest authorization:, ganymed, Medium authorization:, kallisto, Lowest authorization:, europa ",
    "wago": "<br>Default credentials: <br> admin:wago, user:user, guest:guest <br> http, ftp:, user:user00 , administrator:, su:ko2003wa <br> root:wago , admin:wago, user:user , guest:guest ",
    "axis": "<br>Default credentials: <br> root:pass",
    "intellislot": "Provides Web access, environmental sensor data, and third-party customer protocols for Vertiv™ equipment. The cards employ Ethernet and RS-485 networks to monitor and manage a wide range of operating parameters, alarms and notifications. Provides a communication interface to Trellis™, LIFE™ Services, Liebert® Nform, and third-party building and network management applications. <br>Default credentials: <br> Liebert:Liebert, User:User",
    "iqinvision": "<br>Default credentials: <br> root:system",
    "lantronix": "Lantronix EDS-MD is specifically designed for the medical industry, allowing for remote access and management of electronic and medical devices. <br>Default credentials: <br> admin:PASS ",
    "loytec": "https://www.loytec.com/support/download/lvis-3me7-g2 <br>Default credentials: <br> admin:loytec4u",
    "videoiq": "VideoIQ develops intelligent video surveillance cameras using edge video IP security cameras paired with video analytics. <br> VideoIQ is vulnerable to remote file disclosure which allows to any unauthenticated user read any file system including file configurations.<br>Default credentials"
    "<br>supervisor:supervisor <br> https://www.exploit-db.com/exploits/40284",
    "webcamxp": """webcamXP is the most popular webcam and network camera software for Windows.It allows you to monitor your belongings from any location with access to Internet by turning your computer into a security system.
            Connect remotely by using other computers or your mobile phone. Broadcast live video to your website. Schedule automatic captures or recordings. Trig specific actions using the motion detector. You can easily use those features among others with webcamXP.<br>Default credentials:<br>admin:<blank>""",
    "vivotek": "Default credentials:<br>root:<blank>",
    "mobotix": "https://www.mobotix.com/en/products/outdoor-cameras<br>Default credentials:<br>admin:meinsm",
    "grandstream": "Create and customize a security environment with Grandstream’s range of Full HD IP cameras. Easy to setup, deploy and manage, these cameras offer a proactive security system to keep a user’s facility secured and protected. The GSC3600 series of HD IP cameras feature full HD resolution and include weatherproof casing designed for increased security and facility management in any indoor or outdoor area for wide-angle monitoring of nearby subjects.<br>Default credentials:<br>admin:meinsm<br>https://www.exploit-db.com/exploits/48247",
    "contec": "http://www.contec-touch.com/wireless-smart-home/ <br> https://www.exploit-db.com/exploits/44295",
    "netwave": "https://www.exploit-db.com/exploits/41236",
    "CirCarLife": "CirCarlife Scada represents an integral software solution that focuses on the control and parameterisation of smart electric vehicle charging points and units. It gives centralised control of the whole installation for management and maintenance purposes.<br>https://www.exploit-db.com/exploits/45384",
    "amcrest": "https://www.exploit-db.com/exploits/47188",
    "lutron": "Quantum is a lighting control and energy management system that provides total light management by tying the most complete line of lighting controls, motorized window shades, digital ballasts and LED drivers, and sensors together under one software umbrella. Quantum is ideal for new construction or retrofit applications and can easily scale from a single area to a building, or to a campus with many buildings.<br>https://www.exploit-db.com/exploits/44488",
}


def _get_env_key(name, *, required=False):
    """Return an environment-variable API key value.

    Logs a warning when a required key is missing so operators know which
    variable to set in their shell.
    """
    import os as _os

    value = _os.environ.get(name, "")
    if required and not value:
        _views_logger.warning(
            "Environment variable %s is not set. "
            "Features that depend on it will fail at runtime.",
            name,
        )
    return value


def search_main(request):
    if request.method == "POST":

        # create a form instance and populate it with data from the request:
        coordinates_form = forms.CoordinatesForm(request.POST)
        ics_form = forms.CountryForm(request.POST)
        healthcare_form = forms.CountryHealthcareForm(request.POST)
        infra_form = forms.InfraForm(request.POST)

        if ics_form.is_valid():
            code = ics_form.cleaned_data["country"]

            ics_country = request.POST.getlist("ics_country")

            if len(ics_country) == 0:
                form = forms.CountryForm()
                return render(request, "search_main.html", {"form": form})

            search = Search(country=code, ics=ics_country)
            search.save()
            post = request.POST.getlist("ics_country")

            if ics_form.cleaned_data["all"] == True:
                all_results = True
            else:
                all_results = False

            shodan_search_task = shodan_search.delay(
                fk=search.id, country=code, ics=post, all_results=all_results
            )
            request.session["task_id"] = shodan_search_task.task_id

            return HttpResponseRedirect("index")

        elif healthcare_form.is_valid():
            code = healthcare_form.cleaned_data["country_healthcare"]

            healthcare_country = request.POST.getlist("healthcare")

            if len(healthcare_country) == 0:

                form = forms.CountryHealthcareForm()
                return render(request, "search_main.html", {"form": form})

            search = Search(country=code, ics=healthcare_country)
            search.save()
            post = request.POST.getlist("healthcare")

            if healthcare_form.cleaned_data["all"] == True:
                all_results = True
            else:
                all_results = False

            shodan_search_task = shodan_search.delay(
                fk=search.id,
                country=code,
                ics=post,
                healthcare=True,
                all_results=all_results,
            )
            request.session["task_id"] = shodan_search_task.task_id

            return HttpResponseRedirect("index")

        elif coordinates_form.is_valid():

            coordinates = coordinates_form.cleaned_data["coordinates"]
            if len(coordinates) == 0:
                form = forms.CountryForm()
                return render(request, "search_main.html", {"form": form})

            search = Search(
                coordinates=coordinates_form.cleaned_data["coordinates"],
                coordinates_search=request.POST.getlist("coordinates_search"),
            )

            search.save()
            shodan_search_task = shodan_search.delay(
                fk=search.id,
                coordinates=coordinates,
                coordinates_search=request.POST.getlist("coordinates_search"),
            )

            request.session["task_id"] = shodan_search_task.task_id

            return HttpResponseRedirect("index")

        elif infra_form.is_valid():

            code = infra_form.cleaned_data["country_infra"]

            infra_country = request.POST.getlist("country_infra")

            if len(infra_country) == 0:
                form = forms.CountryForm()
                return render(request, "search_main.html", {"form": form})

            search = Search(country=code, ics=infra_country)
            search.save()
            post = request.POST.getlist("infra")

            if ics_form.cleaned_data["all"] == True:
                all_results = True
            else:
                all_results = False

            shodan_search_task = shodan_search.delay(
                fk=search.id, country=code, ics=post, all_results=all_results
            )
            request.session["task_id"] = shodan_search_task.task_id

            return HttpResponseRedirect("index")

        try:
            myfile = request.FILES["myfile"]
        except:
            form = forms.CountryForm()
            return render(request, "search_main.html", {"form": form})

        if request.method == "POST" and request.FILES["myfile"]:
            myfile = request.FILES["myfile"]
            try:
                fs = FileSystemStorage()
                filename = fs.save(myfile.name, myfile)
                uploaded_file_path = fs.path(filename)
                print(uploaded_file_path)
                validate_nmap(uploaded_file_path)
                validate_maxmind()
                search = Search(country="NMAP Scan", ics=myfile.name, nmap=True)
                search.save()
                nmap_task = nmap_scan.delay(uploaded_file_path, fk=search.id)

                request.session["task_id"] = nmap_task.task_id
                print("session")
            except Exception as e:
                print(e)
                return JsonResponse({"message": str(e)}, status=500)

            return HttpResponseRedirect("index")

        else:

            form = forms.CountryForm()
            return render(request, "search_main.html", {"form": form})

    else:
        form = forms.CountryForm()
        return render(request, "search_main.html", {"form": form})


def index(request):
    all_devices = Device.objects.all()
    last_5_searches = Search.objects.filter().order_by("-id")[:5]
    ics_len = Device.objects.filter(category="ics")
    coordinates_search_len = Device.objects.filter(category="coordinates")
    healthcare_len = Device.objects.filter(category="healthcare")
    search_all = Search.objects.all()
    task = request.session.pop("task_id", None)
    ports = Device.objects.values("port").annotate(c=Count("port")).order_by("-c")[:7]
    ports_list = list(ports)
    vulns = Device.objects.exclude(vulns__isnull=True).exclude(vulns__exact="")

    vulns_list = []

    for i in vulns:
        vulns_list.append(ast.literal_eval(i.vulns))

    cves = []
    for i in vulns_list:
        for j in i:
            cves.append(j)

    countr_cves = {}
    c = Counter(cves)
    for key, value in c.items():
        countr_cves[key] = value

    sort = sorted(countr_cves.items())[:7]

    countries = {}
    for i in search_all:
        countries[i.country] = "1"

    # make list out of last 5 searches
    for j in last_5_searches:
        try:
            j.country = pycountry.countries.get(alpha_2=j.country).name
            j.ics = ast.literal_eval(j.ics)
        except:
            pass
        try:
            j.coordinates_search = ast.literal_eval(j.coordinates_search)
        except:
            pass

    credits = check_credits()

    context = {
        "device": all_devices,
        "search": last_5_searches,
        "ics": ics_len,
        "coordinates": coordinates_search_len,
        "healthcare": healthcare_len,
        "ports": ports_list,
        "countries": countries,
        "vulns": sort,
        "task_id": task,
        "search_len": search_all,
        "credits": credits,
    }
    return render(request, "index.html", context)


def devices(request):
    all_devices = Device.objects.all()

    for i in all_devices:
        try:
            i.indicator = ast.literal_eval(i.indicator)
        except:
            pass
        try:
            i.vulns_list = _parse_vulns(i.vulns)
        except Exception:
            i.vulns_list = []

    context = {"devices": all_devices}

    return render(request, "devices.html", context=context)


def map(request):
    all_devices = Device.objects.all()

    context = {"devices": all_devices}

    return render(request, "map.html", context=context)


def gallery(request):
    all_devices = Device.objects.filter(screenshot__gt="", screenshot__isnull=False)
    context = {"devices": all_devices}

    return render(request, "gallery.html", context=context)


def results(request, id):
    all_devices = Device.objects.filter(search_id=id)
    ports = (
        Device.objects.filter(search_id=id)
        .values("port")
        .annotate(c=Count("port"))
        .order_by("-c")[:7]
    )
    city = (
        Device.objects.filter(search_id=id)
        .values("city")
        .annotate(c=Count("city"))
        .order_by("-c")[:7]
    )
    category = (
        Device.objects.filter(search_id=id)
        .values("type")
        .annotate(c=Count("type"))
        .order_by("-c")
    )

    categories_list = list(category)
    ports_list = list(ports)
    cities_list = list(city)

    for i in categories_list:
        i["label"] = i.pop("type")
        i["value"] = i.pop("c")

    vulns = Device.objects.exclude(vulns__isnull=True).exclude(vulns__exact="")

    cves_list = []

    for i in vulns:
        cves_list.append(ast.literal_eval(i.vulns))
    cves = []
    for i in cves_list:
        for j in i:
            cves.append(j)

    cves_counter = {}
    c = Counter(cves)
    for key, value in c.items():
        cves_counter[key] = value

    sort = sorted(cves_counter.items())[:7]

    for i in all_devices:
        try:
            i.indicator = ast.literal_eval(i.indicator)

        except:
            pass
        try:
            i.vulns_list = _parse_vulns(i.vulns)
        except Exception:
            i.vulns_list = []

    context = {
        "search": all_devices,
        "ports": ports_list,
        "vulns": sort,
        "category": categories_list,
        "city": cities_list,
    }

    return render(request, "results.html", context)


def history(request):
    all_searches = Search.objects.all()

    for i in all_searches:
        try:
            i.coordinates_search = ast.literal_eval(i.coordinates_search)
        except Exception as e:
            print(e)

        try:
            i.ics = ast.literal_eval(i.ics)
        except Exception as e:
            print(e)

    context = {"history": all_searches}
    return render(request, "history.html", context)


def update_coordinates(request, id, coordinates):
    if (
        request.method == "GET"
        and request.headers.get("X-Requested-With") == "XMLHttpRequest"
    ):
        dev = Device.objects.get(id=id)
        splitted_coord = coordinates.split(",")
        dev.lat = splitted_coord[0]
        dev.lon = splitted_coord[1]
        dev.located = True
        dev.save()
        return HttpResponse(
            json.dumps({"Status": "OK"}), content_type="application/json"
        )
    else:
        return HttpResponse(
            json.dumps({"Status": "NO OK"}), content_type="application/json"
        )


def device(request, id, device_id, ip):
    all_devices = Device.objects.get(search_id=id, id=device_id)
    nearby = DeviceNearby.objects.filter(device_id=all_devices.id)
    shodan = ShodanScan.objects.filter(device_id=all_devices.id)
    wappalyzer = WappalyzerResult.objects.filter(device_id=all_devices.id)
    nuclei = NucleiResult.objects.filter(device_id=all_devices.id)

    try:
        all_devices.indicator = ast.literal_eval(all_devices.indicator)
    except:
        pass

    if all_devices.type in passwds.keys():
        info = passwds[all_devices.type]
    else:
        info = ""

    nuclei_templates_dir = os.path.join(settings.BASE_DIR, "nuclei_templates")
    nuclei_template_list = []
    device_type_lower = (all_devices.type or "").lower()

    # Load the manifest so we know which template paths are recommended for
    # this device type without relying on directory-name guessing.
    manifest_matched_paths = set()
    manifest_path = os.path.join(nuclei_templates_dir, "manifest.yaml")
    if os.path.isfile(manifest_path):
        try:
            import yaml as _yaml

            with open(manifest_path) as _mf:
                _manifest = _yaml.safe_load(_mf) or {}
            for tpl_path in (_manifest.get("mappings") or {}).get(
                device_type_lower, []
            ):
                # Normalise: strip trailing slash, resolve to absolute, then
                # verify the result is still inside nuclei_templates_dir to
                # prevent path-traversal attacks via a malicious manifest entry.
                tpl_path = tpl_path.rstrip("/")
                abs_path = os.path.realpath(
                    os.path.join(nuclei_templates_dir, tpl_path)
                )
                real_templates_dir = os.path.realpath(nuclei_templates_dir)
                if (
                    not abs_path.startswith(real_templates_dir + os.sep)
                    and abs_path != real_templates_dir
                ):
                    _views_logger.warning(
                        "manifest.yaml path %r resolves outside nuclei_templates — skipped",
                        tpl_path,
                    )
                    continue
                manifest_matched_paths.add(os.path.relpath(abs_path, settings.BASE_DIR))
        except Exception as exc:
            _views_logger.debug(
                "Failed to load nuclei_templates/manifest.yaml: %s", exc
            )

    if os.path.isdir(nuclei_templates_dir):
        for root, dirs, files in os.walk(nuclei_templates_dir):
            dirs.sort()
            yaml_files = sorted(
                f
                for f in files
                if (f.endswith((".yaml", ".yml")) and f != "manifest.yaml")
            )
            # Directory-level entry lets the user run all templates in that folder at once.
            if yaml_files and root != nuclei_templates_dir:
                rel_dir = os.path.relpath(root, settings.BASE_DIR)
                label_dir = os.path.relpath(root, nuclei_templates_dir)
                nuclei_template_list.append(
                    {
                        "label": label_dir + " [all]",
                        "path": rel_dir,
                        "is_dir": True,
                        "match": rel_dir in manifest_matched_paths,
                    }
                )
            for fname in yaml_files:
                full_path = os.path.join(root, fname)
                rel_path = os.path.relpath(full_path, settings.BASE_DIR)
                label = os.path.relpath(full_path, nuclei_templates_dir)
                nuclei_template_list.append(
                    {
                        "label": label,
                        "path": rel_path,
                        "is_dir": False,
                        "match": False,
                    }
                )

    cve_list = _parse_vulns(all_devices.vulns)

    # New intelligence data
    fingerprints = ProtocolFingerprint.objects.filter(device_id=all_devices.id)
    vuln_intel = VulnIntelligence.objects.filter(device_id=all_devices.id)
    honeypot = HoneypotAnalysis.objects.filter(device_id=all_devices.id).first()
    sbom_components = SBOMComponent.objects.filter(device_id=all_devices.id)
    gfw_status = GFWStatus.objects.filter(device_id=all_devices.id).first()

    # Compute max EPSS for risk meter
    max_epss = 0.0
    has_kev = False
    has_exploit = False
    for vi in vuln_intel:
        if vi.epss_score > max_epss:
            max_epss = vi.epss_score
        if vi.kev_listed:
            has_kev = True
        if vi.exploit_available:
            has_exploit = True
        # Attach parsed exploit refs for template rendering
        vi.parsed_exploit_refs = []
        if vi.exploit_refs:
            try:
                vi.parsed_exploit_refs = json.loads(vi.exploit_refs)
            except (json.JSONDecodeError, TypeError):
                pass

    # Build NSE script list for dropdown
    nse_scripts = [{"label": k, "path": v} for k, v in NSE_SCRIPT_CATALOG.items()]

    context = {
        "device": all_devices,
        "nearby": nearby,
        "shodan": shodan,
        "wappalyzer": wappalyzer,
        "nuclei": nuclei,
        "passwd": info,
        "nuclei_templates": nuclei_template_list,
        "cve_list": cve_list,
        "fingerprints": fingerprints,
        "vuln_intel": vuln_intel,
        "honeypot": honeypot,
        "sbom_components": sbom_components,
        "gfw_status": gfw_status,
        "max_epss": max_epss,
        "max_epss_percent": max_epss * 100,
        "has_kev": has_kev,
        "has_exploit": has_exploit,
        "nse_scripts": nse_scripts,
    }

    return render(request, "device.html", context)


def nearby(request, id, query):
    if (
        request.method == "GET"
        and request.headers.get("X-Requested-With") == "XMLHttpRequest"
    ):
        all_devices = Device.objects.filter(id=id)
        device_nearby_task = devices_nearby.delay(
            lat=all_devices[0].lat, lon=all_devices[0].lon, id=id, query=query
        )
        return HttpResponse(
            json.dumps({"task_id": device_nearby_task.id}),
            content_type="application/json",
        )
    else:
        return HttpResponse(
            json.dumps({"task_id": None}), content_type="application/json"
        )


def sources(request):
    return render(request, "sources.html", {})


def wappalyzer_scan_view(request, id):
    if request.method == "GET":
        wap_results = WappalyzerResult.objects.filter(device_id=id)
        if wap_results:
            return HttpResponse(
                json.dumps({"Error": "Already in database"}),
                content_type="application/json",
            )
        wap_task = wappalyzer_scan.delay(id=id)
        return HttpResponse(
            json.dumps({"task_id": wap_task.id}), content_type="application/json"
        )
    else:
        return HttpResponse(
            json.dumps({"task_id": None}), content_type="application/json"
        )


def nuclei_scan_view(request, id):
    if request.method == "GET":
        severity = request.GET.get("severity", None)
        templates_dir = request.GET.get("templates_dir", None)
        nuclei_task = nuclei_scan.delay(
            id=id, templates_dir=templates_dir, severity=severity
        )
        return HttpResponse(
            json.dumps({"task_id": nuclei_task.id}), content_type="application/json"
        )
    else:
        return HttpResponse(
            json.dumps({"task_id": None}), content_type="application/json"
        )


def get_wappalyzer_results(request, id):
    if request.method == "GET":
        wap_results = WappalyzerResult.objects.filter(device_id=id)
        response_data = serializers.serialize("json", wap_results)
        return HttpResponse(response_data, content_type="application/json")


def get_nuclei_results(request, id):
    if request.method == "GET":
        nuclei_results = NucleiResult.objects.filter(device_id=id)
        response_data = serializers.serialize("json", nuclei_results)
        return HttpResponse(response_data, content_type="application/json")


def shodan_scan(request, id):
    if (
        request.method == "GET"
        and request.headers.get("X-Requested-With") == "XMLHttpRequest"
    ):

        shodan_scan2 = ShodanScan.objects.filter(device_id=id)

        if shodan_scan2:
            print("already")
            return HttpResponse(
                json.dumps({"Error": "Already in database"}),
                content_type="application/json",
            )

        shodan_scan_task2 = shodan_scan_task.delay(id=id)
        return HttpResponse(
            json.dumps({"task_id": shodan_scan_task2.id}),
            content_type="application/json",
        )
    else:
        return HttpResponse(
            json.dumps({"task_id": None}), content_type="application/json"
        )


def get_task_info(request):
    """Return Celery task state and result as JSON.

    Requires the ``X-Requested-With: XMLHttpRequest`` header so that only
    in-page AJAX calls (not cross-origin browser navigations) can poll task
    state.  This is consistent with all other polling views in the app and
    prevents unauthenticated cross-origin access to task results which may
    contain IP addresses, port lists, and vulnerability findings.
    """
    if request.headers.get("X-Requested-With") != "XMLHttpRequest":
        return HttpResponse("Forbidden", status=403)
    task_id = request.GET.get("task_id", None)
    try:
        if task_id is not None:
            task = AsyncResult(task_id)
            result = task.result
            # Ensure the result is JSON-serializable (Exceptions are not)
            if isinstance(result, Exception):
                result = {"error": str(result)}
            elif result is not None:
                try:
                    json.dumps(result)
                except (TypeError, ValueError):
                    result = {"error": str(result)}
            data = {
                "state": task.state,
                "result": result,
            }
            return HttpResponse(json.dumps(data), content_type="application/json")
        else:
            return HttpResponse(
                json.dumps({"error": "No job id given."}),
                content_type="application/json",
            )
    except Exception as e:
        logger.warning("get_task_info: %s", e)
        return HttpResponse(
            json.dumps({"state": "FAILURE", "result": {"error": str(e)}}),
            content_type="application/json",
        )


def get_shodan_scan_results(request, id):
    if (
        request.method == "GET"
        and request.headers.get("X-Requested-With") == "XMLHttpRequest"
    ):
        shodan_scan2 = ShodanScan.objects.filter(device_id=id)

        if not shodan_scan2.exists():
            return HttpResponse(json.dumps([]), content_type="application/json")

        response_data = serializers.serialize("json", shodan_scan2)

        return HttpResponse(response_data, content_type="application/json")


def get_nearby_devices(request, id):
    if (
        request.method == "GET"
        and request.headers.get("X-Requested-With") == "XMLHttpRequest"
    ):
        nearby_devices = DeviceNearby.objects.filter(device_id=id)

        response_data = serializers.serialize("json", nearby_devices)

        return HttpResponse(response_data, content_type="application/json")


def scan_dev(request, id):
    if (
        request.method == "GET"
        and request.headers.get("X-Requested-With") == "XMLHttpRequest"
    ):
        nse_script = request.GET.get("nse_script", None)
        task = nmap_device_scan.delay(int(id), nse_script=nse_script)
        return HttpResponse(
            json.dumps({"task_id": task.id}), content_type="application/json"
        )
    else:
        return HttpResponse(
            json.dumps({"task_id": None}), content_type="application/json"
        )


def exploit_dev(request, id):
    if (
        request.method == "GET"
        and request.headers.get("X-Requested-With") == "XMLHttpRequest"
    ):
        res = exploit(id)
        if res:
            return HttpResponse(json.dumps(res), content_type="application/json")
        else:
            return HttpResponse(
                json.dumps({"Error": "Connection Error"}),
                content_type="application/json",
            )


def port_scan_view(request, id):
    """Launch a ``port_scan_task`` for a device and return the Celery task ID.

    The task runs Naabu against the device and reports progress via the
    standard ``/get-task-info/`` polling endpoint.  Once complete the caller
    can use the returned ``task_id`` to chain a nuclei or wappalyzer scan.

    GET /port_scan/<id>  →  {"task_id": "..."}
    """
    if (
        request.method == "GET"
        and request.headers.get("X-Requested-With") == "XMLHttpRequest"
    ):
        scan_task = port_scan_task.delay(int(id))
        return HttpResponse(
            json.dumps({"task_id": scan_task.id}), content_type="application/json"
        )
    return HttpResponse(json.dumps({"task_id": None}), content_type="application/json")


def port_scan_ip_view(request, target_ip):
    """Launch a port scan against a raw IP address entered on the dashboard.

    Creates a minimal Device record (and a parent Search) when the IP has not
    been seen before, then delegates to the existing ``port_scan_task``.  If
    the IP already exists in the database the most-recently-added device is
    reused so duplicate records are avoided.

    GET /port_scan/ip/<target_ip>  →  {"task_id": "...", "device_id": <id>}
    """
    import ipaddress

    if (
        request.method == "GET"
        and request.headers.get("X-Requested-With") == "XMLHttpRequest"
    ):
        try:
            ipaddress.ip_address(target_ip)
        except ValueError:
            return HttpResponse(
                json.dumps({"Error": "Invalid IP address."}),
                content_type="application/json",
            )
        device = Device.objects.filter(ip=target_ip).order_by("-id").first()
        if device is None:
            search = Search(
                coordinates="",
                country="PORT SCAN",
                ics="Port Scan",
                coordinates_search="",
            )
            search.save()
            device = Device(
                search=search,
                ip=target_ip,
                product="",
                org="",
                data="",
                port="",
                type="PORT SCAN",
                city="",
                lat="0",
                lon="0",
                country_code="",
                query="PORT SCAN",
                category="port_scan",
                vulns="",
                indicator="",
                hostnames="",
                screenshot="",
            )
            device.save()
        scan_task = port_scan_task.delay(device.id)
        return HttpResponse(
            json.dumps({"task_id": scan_task.id, "device_id": device.id}),
            content_type="application/json",
        )
    return HttpResponse(json.dumps({"task_id": None}), content_type="application/json")


def export_csv(request, id):
    """Export search results as CSV for FOSS geospatial tools (QGIS, Kepler.gl, the built-in globe)."""
    import tempfile

    fd, output_path = tempfile.mkstemp(suffix=".csv")
    os.close(fd)
    shodan_csv_export(id, output_path)
    try:
        with open(output_path, "r") as f:
            response = HttpResponse(f.read(), content_type="text/csv")
            response["Content-Disposition"] = (
                'attachment; filename="shodan_export_{}.csv"'.format(id)
            )
            return response
    finally:
        if os.path.exists(output_path):
            os.remove(output_path)


def export_kml(request, id):
    """Export search results as KML for FOSS geospatial tools (QGIS, Leaflet, uMap)."""
    import tempfile

    fd, output_path = tempfile.mkstemp(suffix=".kml")
    os.close(fd)
    shodan_kml_export(id, output_path)
    try:
        with open(output_path, "r") as f:
            response = HttpResponse(
                f.read(), content_type="application/vnd.google-earth.kml+xml"
            )
            response["Content-Disposition"] = (
                'attachment; filename="shodan_export_{}.kml"'.format(id)
            )
            return response
    finally:
        if os.path.exists(output_path):
            os.remove(output_path)


def export_json(request, id):
    """Export search results as GeoJSON using Shodan's own GeoJsonConverter.

    Equivalent to ``shodan convert <file.json.gz> geojson``.  The output is a
    GeoJSON FeatureCollection that can be loaded directly into the built-in
    globe, QGIS, Kepler.gl, or any GeoJSON-aware tool.
    """
    geojson_str = shodan_json_export(id)
    response = HttpResponse(geojson_str, content_type="application/geo+json")
    response["Content-Disposition"] = (
        'attachment; filename="shodan_export_{}.geojson"'.format(id)
    )
    return response


def rtsp_scan_view(request, id):
    """Trigger RTSP enumeration scan for a device."""
    if request.method == "GET":
        rtsp_task = nmap_rtsp_scan.delay(id=id)
        return HttpResponse(
            json.dumps({"task_id": rtsp_task.id}), content_type="application/json"
        )
    else:
        return HttpResponse(
            json.dumps({"task_id": None}), content_type="application/json"
        )


def screenshot_view(request, id):
    """Capture a screenshot of the device's web interface."""
    if (
        request.method == "GET"
        and request.headers.get("X-Requested-With") == "XMLHttpRequest"
    ):
        task = capture_screenshot.delay(int(id))
        return HttpResponse(
            json.dumps({"task_id": task.id}), content_type="application/json"
        )
    return HttpResponse(json.dumps({"task_id": None}), content_type="application/json")


def exploitdb_search_view(request, id):
    """Search ExploitDB for exploits matching device CVEs."""
    if (
        request.method == "GET"
        and request.headers.get("X-Requested-With") == "XMLHttpRequest"
    ):
        task = exploitdb_search.delay(int(id))
        return HttpResponse(
            json.dumps({"task_id": task.id}), content_type="application/json"
        )
    return HttpResponse(json.dumps({"task_id": None}), content_type="application/json")


def get_nearby_devices_coordinates(request, id):
    if (
        request.method == "GET"
        and request.headers.get("X-Requested-With") == "XMLHttpRequest"
    ):
        nearby_devices = DeviceNearby.objects.filter(device_id=id)

        response_data = serializers.serialize("json", nearby_devices)

        return HttpResponse(response_data, content_type="application/json")


def send_to_field_agent(request, id, notes):
    if (
        request.method == "GET"
        and request.headers.get("X-Requested-With") == "XMLHttpRequest"
    ):
        print(id)

        host = Device.objects.get(id=id)
        host.notes = notes
        host.save()

        af_task = send_to_field_agent_task.delay(id, notes)

        return HttpResponse(
            json.dumps({"Status": "OK"}), content_type="application/json"
        )
    else:
        return HttpResponse(
            json.dumps({"task_id": None}), content_type="application/json"
        )


def whois(request, id):
    if (
        request.method == "GET"
        and request.headers.get("X-Requested-With") == "XMLHttpRequest"
    ):

        whoiss = Whois.objects.filter(device_id=id)

        if whoiss:
            print("already")
            return HttpResponse(
                json.dumps({"Error": "Already in database"}),
                content_type="application/json",
            )

        wh_task = whoisxml.delay(id=id)

        return HttpResponse(
            json.dumps({"task_id": wh_task.id}), content_type="application/json"
        )
    else:
        return HttpResponse(
            json.dumps({"task_id": None}), content_type="application/json"
        )


def get_whois(request, id):
    if (
        request.method == "GET"
        and request.headers.get("X-Requested-With") == "XMLHttpRequest"
    ):
        whoiss = Whois.objects.filter(device_id=id)

        response_data = serializers.serialize("json", whoiss)

        return HttpResponse(response_data, content_type="application/json")


def globe(request):
    """Render the 3-D WebGL globe page."""
    return render(request, "globe.html", {})


def globe_devices_json(request):
    """
    Return all devices as JSON for the Three.js globe.

    Each record mirrors the CSV export schema (IP, lat, lon, product, type,
    port, city, org, vuln_count, severity) so the same data that feeds
    QGIS / Kepler.gl also drives the built-in globe and heat-map.

    Severity is derived from the vuln count using the same bands as the
    desktop globe_3d widget:
        0 vulns  → info
        1-2      → low
        3-5      → medium
        6-10     → high
        >10      → critical
    """
    devices = Device.objects.all()
    records = []
    for d in devices:
        try:
            lat = float(d.lat)
            lon = float(d.lon)
        except (ValueError, TypeError):
            continue

        vuln_count = 0
        if d.vulns:
            try:
                vuln_list = json.loads(d.vulns.replace("'", '"'))
                vuln_count = len(vuln_list) if isinstance(vuln_list, list) else 0
            except (json.JSONDecodeError, ValueError):
                pass

        if vuln_count > 10:
            severity = "critical"
        elif vuln_count > 5:
            severity = "high"
        elif vuln_count > 2:
            severity = "medium"
        elif vuln_count > 0:
            severity = "low"
        else:
            severity = "info"

        records.append(
            {
                "ip": d.ip,
                "lat": lat,
                "lon": lon,
                "product": d.product or "",
                "type": d.type or "",
                "port": d.port or "",
                "city": d.city or "",
                "org": d.org or "",
                "country": d.country_code or "",
                "vuln_count": vuln_count,
                "severity": severity,
            }
        )

    return JsonResponse(records, safe=False)


# ---------------------------------------------------------------------------
# Deep Protocol Scan views
# ---------------------------------------------------------------------------


def deep_scan_view(request, id):
    """Trigger a deep protocol fingerprinting scan via Celery."""
    if (
        request.method == "GET"
        and request.headers.get("X-Requested-With") == "XMLHttpRequest"
    ):
        protocol = request.GET.get("protocol", None)
        task = deep_protocol_scan.delay(device_id=id, protocol=protocol)
        return HttpResponse(
            json.dumps({"task_id": task.id}), content_type="application/json"
        )
    return HttpResponse(json.dumps({"task_id": None}), content_type="application/json")


def get_fingerprint_results(request, id):
    """Return protocol fingerprint data for a device."""
    if (
        request.method == "GET"
        and request.headers.get("X-Requested-With") == "XMLHttpRequest"
    ):
        fps = ProtocolFingerprint.objects.filter(device_id=id)
        if not fps.exists():
            return HttpResponse(json.dumps([]), content_type="application/json")
        # Select only curated fields — exclude raw_output to avoid bloat
        data = list(
            fps.values(
                "id",
                "protocol",
                "vendor_id",
                "project_name",
                "hardware_version",
                "firmware_version",
                "serial_number",
                "module_name",
                "slave_id",
                "plant_id",
                "scan_date",
            )
        )
        # Convert datetimes to strings for JSON serialisation
        for item in data:
            if item.get("scan_date"):
                item["scan_date"] = item["scan_date"].isoformat()
        return HttpResponse(json.dumps(data), content_type="application/json")
    return HttpResponse(json.dumps([]), content_type="application/json")


# ---------------------------------------------------------------------------
# Vulnerability Intelligence views
# ---------------------------------------------------------------------------


def nvd_scan_view(request, id):
    """Trigger NVD lookup + EPSS/KEV enrichment via Celery."""
    if (
        request.method == "GET"
        and request.headers.get("X-Requested-With") == "XMLHttpRequest"
    ):
        task = nvd_lookup.delay(device_id=id)
        return HttpResponse(
            json.dumps({"task_id": task.id}), content_type="application/json"
        )
    return HttpResponse(json.dumps({"task_id": None}), content_type="application/json")


def get_vuln_intel(request, id):
    """Return vulnerability intelligence data for a device."""
    if (
        request.method == "GET"
        and request.headers.get("X-Requested-With") == "XMLHttpRequest"
    ):
        vulns = VulnIntelligence.objects.filter(device_id=id)
        if not vulns.exists():
            return HttpResponse(json.dumps([]), content_type="application/json")
        data = []
        for v in vulns:
            data.append(
                {
                    "cve_id": v.cve_id,
                    "cvss_score": v.cvss_score,
                    "epss_score": v.epss_score,
                    "epss_percentile": v.epss_percentile,
                    "kev_listed": v.kev_listed,
                    "exploit_available": v.exploit_available,
                    "description": v.description[:300],
                }
            )
        return HttpResponse(json.dumps(data), content_type="application/json")
    return HttpResponse(json.dumps([]), content_type="application/json")


# ---------------------------------------------------------------------------
# Honeypot Analysis views
# ---------------------------------------------------------------------------


def honeypot_scan_view(request, id):
    """Trigger honeypot probability analysis via Celery."""
    if (
        request.method == "GET"
        and request.headers.get("X-Requested-With") == "XMLHttpRequest"
    ):
        task = honeypot_check.delay(device_id=id)
        return HttpResponse(
            json.dumps({"task_id": task.id}), content_type="application/json"
        )
    return HttpResponse(json.dumps({"task_id": None}), content_type="application/json")


# ---------------------------------------------------------------------------
# SBOM views
# ---------------------------------------------------------------------------


def sbom_scan_view(request, id):
    """Trigger SBOM component lookup via Celery."""
    if (
        request.method == "GET"
        and request.headers.get("X-Requested-With") == "XMLHttpRequest"
    ):
        task = sbom_lookup.delay(device_id=id)
        return HttpResponse(
            json.dumps({"task_id": task.id}), content_type="application/json"
        )
    return HttpResponse(json.dumps({"task_id": None}), content_type="application/json")


def get_sbom_results(request, id):
    """Return SBOM components for a device."""
    if (
        request.method == "GET"
        and request.headers.get("X-Requested-With") == "XMLHttpRequest"
    ):
        components = SBOMComponent.objects.filter(device_id=id)
        if not components.exists():
            return HttpResponse(json.dumps([]), content_type="application/json")
        data = []
        for c in components:
            data.append(
                {
                    "component_name": c.component_name,
                    "version": c.version,
                    "component_type": c.component_type,
                    "license_name": c.license_name,
                    "cpe_string": c.cpe_string,
                }
            )
        return HttpResponse(json.dumps(data), content_type="application/json")
    return HttpResponse(json.dumps([]), content_type="application/json")


# ---------------------------------------------------------------------------
# GFW Reachability views
# ---------------------------------------------------------------------------


def gfw_check_view(request, id):
    """Trigger GFW reachability check via Celery."""
    if (
        request.method == "GET"
        and request.headers.get("X-Requested-With") == "XMLHttpRequest"
    ):
        task = gfw_check.delay(device_id=id)
        return HttpResponse(
            json.dumps({"task_id": task.id}), content_type="application/json"
        )
    return HttpResponse(json.dumps({"task_id": None}), content_type="application/json")


# ---------------------------------------------------------------------------
# Search Cost Estimate view
# ---------------------------------------------------------------------------


def search_cost_view(request):
    """Return estimated Shodan API credit cost for a search query."""
    if (
        request.method == "GET"
        and request.headers.get("X-Requested-With") == "XMLHttpRequest"
    ):
        query = request.GET.get("query", "")
        country = request.GET.get("country", None)
        if not query:
            return HttpResponse(
                json.dumps({"error": "No query provided"}),
                content_type="application/json",
            )
        result = check_search_cost(query, country)
        return HttpResponse(json.dumps(result), content_type="application/json")
    return HttpResponse(
        json.dumps({"error": "Invalid request"}), content_type="application/json"
    )


# ---------------------------------------------------------------------------
# Enhanced globe_devices_json with EPSS/KEV data
# ---------------------------------------------------------------------------


def globe_devices_epss_json(request):
    """Return devices with EPSS risk scoring for the 3D globe.

    Extends the base globe_devices_json with EPSS scores, KEV status,
    and honeypot probability for enhanced spike coloring.
    Uses annotate() for O(1) database queries instead of per-device lookups.
    """
    # Subquery for honeypot probability
    hp_subquery = (
        HoneypotAnalysis.objects.filter(device=OuterRef("pk"))
        .order_by("-scan_date")
        .values("probability")[:1]
    )

    devices = Device.objects.annotate(
        max_epss=Coalesce(Max("vulnintelligence__epss_score"), 0.0),
        has_kev_ann=Exists(
            VulnIntelligence.objects.filter(device=OuterRef("pk"), kev_listed=True)
        ),
        honeypot_prob_ann=Coalesce(
            Subquery(hp_subquery, output_field=FloatField()), 0.0
        ),
    )

    records = []
    for d in devices:
        try:
            lat = float(d.lat)
            lon = float(d.lon)
        except (ValueError, TypeError):
            continue

        vuln_count = 0
        if d.vulns:
            try:
                vuln_list = json.loads(d.vulns.replace("'", '"'))
                vuln_count = len(vuln_list) if isinstance(vuln_list, list) else 0
            except (json.JSONDecodeError, ValueError):
                pass

        max_epss = d.max_epss
        is_kev = d.has_kev_ann
        honeypot_prob = d.honeypot_prob_ann

        # EPSS-based severity (overrides vuln-count severity)
        if is_kev:
            severity = "kev"
        elif max_epss > 0.7:
            severity = "critical"
        elif max_epss > 0.4:
            severity = "high"
        elif max_epss > 0.1:
            severity = "medium"
        elif vuln_count > 0:
            severity = "low"
        else:
            severity = "info"

        records.append(
            {
                "ip": d.ip,
                "lat": lat,
                "lon": lon,
                "product": d.product or "",
                "type": d.type or "",
                "port": d.port or "",
                "city": d.city or "",
                "org": d.org or "",
                "country": d.country_code or "",
                "vuln_count": vuln_count,
                "severity": severity,
                "epss_score": max_epss,
                "kev_listed": is_kev,
                "honeypot_prob": honeypot_prob,
            }
        )

    return JsonResponse(records, safe=False)
