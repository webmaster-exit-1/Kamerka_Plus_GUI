"""Shodan preset keys, labels, and query resolution for search UI + cost estimates."""

from kamerka.tasks import (
    attackers_infra_queries,
    coordinates_queries,
    healthcare_queries,
    ics_queries,
)

ALL_QUERY_MAP = {}
ALL_QUERY_MAP.update(ics_queries)
ALL_QUERY_MAP.update(coordinates_queries)
ALL_QUERY_MAP.update(healthcare_queries)
ALL_QUERY_MAP.update(attackers_infra_queries)

# Keys kept in ALL_QUERY_MAP for backwards compatibility but omitted from curated UI.
UI_HIDDEN_KEYS = frozenset(
    {
        "moxahttp",
        "niagara_audit",
        "niagara_web_server",
        "WAGO",
        "siemens_Sm@rtClient",
        "simatic",
        "windriver",
    }
)

# Human labels for curated ICS presets (key must exist in ics_queries).
ICS_CURATED = [
    ("niagara", "Niagara / Tridium"),
    ("tridium_niagara4", "Niagara 4"),
    ("modbus", "Modbus"),
    ("bacnet", "BACnet"),
    ("dnp3", "DNP3"),
    ("ethernetip", "Ethernet/IP"),
    ("codesys", "CODESYS"),
    ("iec", "IEC 60870"),
    ("proconos", "ProconOS"),
    ("gestrip", "GE Industrial"),
    ("hart", "HART-IP"),
    ("pcworx", "PC Worx"),
    ("mitsubishi", "Mitsubishi"),
    ("mitsubishi_melsec", "MELSEC-Q"),
    ("omron", "Omron"),
    ("redlion", "Red Lion"),
    ("siemens", "Siemens (generic)"),
    ("s7", "S7 / s7 (country:XX s7)"),
    ("simatic_s7", "Siemens S7 portal"),
    ("siemens_s7_200", "S7-200"),
    ("siemens_s7_300", "S7-300"),
    ("siemens_s7_1200", "S7-1200"),
    ("siemens_s7_1500", "S7-1500"),
    ("rockwell_micrologix", "Rockwell MicroLogix"),
    ("allen_bradley", "Allen-Bradley"),
    ("modicon", "Modicon"),
    ("ab_ethernet", "AB / Ethernet"),
    ("schneider_electric", "Schneider Electric"),
    ("schneider_citectscada", "CitectSCADA"),
    ("schneider_modicon_m340", "Modicon M340"),
    ("ge_cimplicity", "GE CIMPLICITY"),
    ("ge_proficy", "GE Proficy"),
    ("abb_ac800m", "ABB AC 800M"),
    ("abb_rtu560", "ABB RTU560"),
    ("honeywell_xl_web", "Honeywell XL Web"),
    ("honeywell_falcon", "Honeywell Falcon"),
    ("phoenix_ilc", "Phoenix ILC"),
    ("moxa", "Moxa"),
    ("moxa_nport", "Moxa NPort"),
    ("moxa_oncell", "Moxa OnCell"),
    ("wago", "WAGO"),
    ("plantvisor", "PlantVisor"),
    ("clearSCADA", "ClearSCADA"),
    ("vtscada", "VTScada"),
    ("web_scada", "Web SCADA"),
    ("bas_scada", "BAS SCADA"),
    ("atvise", "atvise"),
    ("vantage_infusion", "Vantage InFusion"),
    ("automated_logic", "Automated Logic WebCTRL"),
    ("carrier_i_vu", "Carrier i-Vu"),
    ("tracer_sc", "Tracer SC"),
    ("climatix", "Siemens Climatix"),
    ("mqtt_1883", "MQTT :1883"),
    ("mqtt_8883", "MQTT :8883"),
    ("doors", "Physical access / HID"),
    ("veeder_root_tls", "Veeder-Root TLS"),
    ("gas_station_pump", "Gas station ATG"),
    ("sma_solar_inverter", "SMA solar inverter"),
    ("enercon_wind", "Enercon wind"),
    ("tesla_powerpack", "Tesla PowerPack"),
    ("ev_charger", "EV charger"),
    ("railroad_management", "Railroad management"),
    ("anpr_alpr", "ANPR / ALPR"),
    ("samsung_billboard", "Digital billboard"),
    ("windweb", "Wind SCADA"),
    ("nordex", "Nordex"),
    ("xzeres", "XZERES wind"),
    ("tank", "Tank monitoring"),
    ("gnss", "GNSS / NTRIP"),
    ("traccar", "Traccar GPS"),
    ("other_hmi", "Generic HMI"),
    ("gestrip", "GE Industrial"),
    ("hart", "HART-IP"),
    ("pcworx", "PC Worx"),
    ("omron", "Omron"),
    ("redlion", "Red Lion"),
    ("akcp", "AKCP"),
    ("spidercontrol", "SpiderControl"),
    ("iologik", "Moxa ioLogik"),
    ("zworld", "Z-World"),
    ("axc", "AXC PLC"),
    ("xp277", "XP277 HMI"),
    ("vxworks", "VxWorks"),
    ("eig", "EIG / Nexus"),
    ("digi", "Digi Transport"),
    ("lantronix", "Lantronix"),
    ("entelitouch", "Delta enteliTOUCH"),
    ("crestron", "Crestron"),
    ("fronius", "Fronius solar"),
    ("power_logic", "PowerLogic"),
    ("telemecanique_bxm", "Telemecanique BMX"),
    ("ilon", "i.LON"),
    ("webvisu", "Webvisu"),
    ("sailor", "Sailor VSAT"),
    ("nmea", "NMEA marine"),
    ("jeedom", "Jeedom"),
    ("doorbird", "DoorBird"),
    ("carel_pcoweb", "Carel pCOWeb"),
    ("cimetrics", "Cimetrics Eplus"),
    ("delta_controls", "Delta Controls"),
]

IOT_CAMERA_CURATED = [
    ("webcam", "Webcam"),
    ("hikvision", "Hikvision"),
    ("axis", "Axis"),
    ("dahua", "Dahua"),
    ("foscam", "Foscam"),
    ("reolink", "Reolink"),
    ("amcrest", "Amcrest"),
    ("vivotek", "Vivotek"),
    ("mobotix", "Mobotix"),
    ("rtsp", "RTSP"),
    ("videoiq", "VideoIQ"),
    ("netwave", "Netwave"),
    ("ubnt", "Ubiquiti stream"),
    ("blueiris", "Blue Iris"),
    ("go1984", "go1984"),
    ("webcamxp", "WebcamXP"),
]

IOT_OTHER_CURATED = [
    ("mqtt", "MQTT"),
    ("printer", "Printers"),
    ("rdp", "RDP (screenshot)"),
    ("vnc", "VNC (screenshot)"),
    ("screenshot", "Screenshot hosts"),
    ("contec", "Contec smart home"),
    ("lutron", "Lutron"),
]

IOT_ICS_CURATED = [
    ("modbus", "Modbus"),
    ("bacnet", "BACnet"),
    ("siemens", "Siemens"),
    ("niagara", "Niagara"),
    ("codesys", "CODESYS"),
    ("moxa", "Moxa"),
]


def _curated_options(pairs):
    """Return (key, label) pairs that exist in the query map and are not hidden."""
    out = []
    seen = set()
    for key, label in pairs:
        if key in seen or key in UI_HIDDEN_KEYS:
            continue
        if key not in ALL_QUERY_MAP:
            continue
        seen.add(key)
        out.append((key, label))
    return out


def ics_preset_options():
    return _curated_options(ICS_CURATED)


def iot_camera_preset_options():
    return _curated_options(IOT_CAMERA_CURATED)


def iot_other_preset_options():
    return _curated_options(IOT_OTHER_CURATED)


def iot_ics_preset_options():
    return _curated_options(IOT_ICS_CURATED)


# Legacy template typos → canonical ics_queries keys.
KEY_ALIASES = {
    "siemens_Sm@rtClient": "Siemens Sm@rtClient",
    "WAGO": "wago",
}


def resolve_selection_keys(keys):
    """Map UI preset keys to Shodan query strings; pass through unknown values."""
    queries = []
    unknown = []
    for raw in keys:
        key = KEY_ALIASES.get((raw or "").strip(), (raw or "").strip())
        if not key:
            continue
        if key in ALL_QUERY_MAP:
            queries.append(ALL_QUERY_MAP[key])
        else:
            unknown.append(key)
            queries.append(key)
    return queries, unknown


def _preset_label_map():
    pairs = ICS_CURATED + IOT_CAMERA_CURATED + IOT_OTHER_CURATED + IOT_ICS_CURATED
    label_by_key = {k: lbl for k, lbl in pairs}
    for key, query in ALL_QUERY_MAP.items():
        label_by_key.setdefault(key, key.replace("_", " ").title())
    return label_by_key


def selection_labels(keys):
    """Return display labels for selected keys."""
    labels = []
    label_by_key = _preset_label_map()
    for key in keys:
        key = (key or "").strip()
        if not key:
            continue
        labels.append(label_by_key.get(key, key))
    return labels