from django.conf import settings
from django.db import models
from django.utils import timezone
from datetime import timedelta

# Create your models here.


class Search(models.Model):
    coordinates = models.CharField(max_length=100)
    country = models.CharField(max_length=100)
    ics = models.CharField(max_length=100)
    coordinates_search = models.CharField(max_length=1000)
    nmap = models.BooleanField(default=False)


class Watchlist(models.Model):
    QUERY_COUNTRY = "country"
    QUERY_COORDINATES = "coordinates"
    QUERY_TYPE_CHOICES = [
        (QUERY_COUNTRY, "Country"),
        (QUERY_COORDINATES, "Coordinates"),
    ]

    name = models.CharField(max_length=120, unique=True)
    query_type = models.CharField(
        max_length=20, choices=QUERY_TYPE_CHOICES, default=QUERY_COUNTRY
    )
    country = models.CharField(max_length=100, default="", blank=True)
    coordinates = models.CharField(max_length=100, default="", blank=True)
    query_items = models.JSONField(default=list, blank=True)
    category = models.CharField(max_length=100, default="ics")
    healthcare = models.BooleanField(default=False)
    all_results = models.BooleanField(default=False)
    enabled = models.BooleanField(default=True)
    refresh_interval_minutes = models.PositiveIntegerField(default=60)
    last_run_at = models.DateTimeField(null=True, blank=True)
    next_run_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.name

    def compute_next_run_at(self, from_time=None):
        base = from_time or timezone.now()
        return base + timedelta(minutes=max(1, self.refresh_interval_minutes))


class Device(models.Model):
    search = models.ForeignKey(Search, on_delete=models.CASCADE)
    ip = models.CharField(max_length=100, default="", db_index=True)
    product = models.CharField(max_length=500, default="")
    org = models.CharField(max_length=100, default="", null=True)
    data = models.TextField(default="")
    port = models.TextField(default="")
    type = models.CharField(max_length=100, default="")
    city = models.CharField(max_length=100, default="", null=True)
    lon = models.DecimalField(max_digits=9, decimal_places=6, null=True, blank=True, default=None)
    lat = models.DecimalField(max_digits=9, decimal_places=6, null=True, blank=True, default=None)
    country_code = models.CharField(max_length=100, default="")
    query = models.CharField(max_length=100, default="")
    category = models.CharField(max_length=100, default="")
    vulns = models.TextField(default="")
    indicator = models.CharField(max_length=100, default="")
    hostnames = models.CharField(max_length=500, default="")
    isp = models.CharField(max_length=200, default="")
    cpe = models.CharField(max_length=500, default="")
    screenshot = models.TextField(default="")
    located = models.BooleanField(default=False, null=True)
    notes = models.CharField(max_length=1000, default="")
    scan = models.TextField(default="")
    exploit = models.TextField(default="")
    exploited_scanned = models.BooleanField(default=False)
    last_scanned = models.DateTimeField(
        null=True,
        blank=True,
        db_index=True,
        help_text=(
            "Timestamp of the most recent Shodan API scan for this IP. "
            "Used by verification.shodan_analytics.should_skip_ip() to avoid "
            "redundant API calls for recently-checked assets."
        ),
    )
    risk_score = models.IntegerField(
        default=0,
        help_text=(
            "Composite risk score 0–100 computed by "
            "app_kamerka.enrichment.compute_risk_score(). "
            "Higher = more likely high-risk device."
        ),
    )
    layer_context = models.JSONField(
        default=dict,
        blank=True,
        help_text=(
            "JSON context from enrichment: nearby_infra, recent_alerts, "
            "kev_listed, likely_honeypot."
        ),
    )
    is_camera_candidate = models.BooleanField(
        default=False,
        db_index=True,
        help_text=(
            "True when camera classification heuristics identify this asset as "
            "a likely camera/NVR endpoint."
        ),
    )
    camera_score = models.IntegerField(
        default=0,
        db_index=True,
        help_text=(
            "Heuristic camera confidence score (0–100) derived from ports, "
            "tags, product strings, and RTSP hints."
        ),
    )
    camera_reasons = models.JSONField(
        default=list,
        blank=True,
        help_text="List of rule hits that contributed to camera_score.",
    )

    def port_scan_label(self):
        """Short label used in the Port Scan Task dropdown (ID · IP · product or type)."""
        detail = (self.product or self.type or "")[:30]
        return "#{} {} {}".format(
            self.id, self.ip, ("· " + detail) if detail else ""
        ).strip()


class DeviceNearby(models.Model):
    device = models.ForeignKey(Device, on_delete=models.CASCADE)
    lat = models.CharField(max_length=100)
    lon = models.CharField(max_length=100)
    ip = models.CharField(max_length=100)
    product = models.CharField(max_length=100)
    port = models.CharField(max_length=100)
    org = models.CharField(max_length=100)


class WappalyzerResult(models.Model):
    device = models.ForeignKey(Device, on_delete=models.CASCADE)
    technologies = models.JSONField(default=dict)
    raw_output = models.TextField(default="")
    scan_date = models.DateTimeField(auto_now_add=True)


class NucleiResult(models.Model):
    device = models.ForeignKey(Device, on_delete=models.CASCADE)
    template_id = models.CharField(max_length=200, default="")
    name = models.CharField(max_length=500, default="")
    severity = models.CharField(max_length=50, default="")
    matched_at = models.CharField(max_length=500, default="")
    description = models.TextField(default="")
    raw_output = models.TextField(default="")
    scan_date = models.DateTimeField(auto_now_add=True)


class ShodanScan(models.Model):
    device = models.ForeignKey(Device, on_delete=models.CASCADE)
    ports = models.TextField(default="")
    tags = models.TextField(default="")
    products = models.TextField(default="")
    module = models.TextField(default="")
    vulns = models.TextField(default="")


class Whois(models.Model):
    device = models.ForeignKey(Device, on_delete=models.CASCADE)
    name = models.CharField(max_length=100)
    org = models.CharField(max_length=100)
    street = models.CharField(max_length=100)
    city = models.CharField(max_length=100)
    netrange = models.CharField(max_length=100)
    admin_org = models.CharField(max_length=100)
    admin_email = models.CharField(max_length=100)
    admin_phone = models.CharField(max_length=100)
    email = models.CharField(max_length=100)


class Bosch(models.Model):
    device = models.ForeignKey(Device, on_delete=models.CASCADE)
    username = models.CharField(max_length=100)
    password = models.CharField(max_length=100)


class Dnp3(models.Model):
    device = models.ForeignKey(Device, on_delete=models.CASCADE)
    source = models.CharField(max_length=100)
    destination = models.CharField(max_length=100)
    control = models.CharField(max_length=100)


class ProtocolFingerprint(models.Model):
    device = models.ForeignKey(Device, on_delete=models.CASCADE)
    protocol = models.CharField(max_length=50, default="")
    vendor_id = models.CharField(max_length=200, default="")
    project_name = models.CharField(max_length=200, default="")
    hardware_version = models.CharField(max_length=200, default="")
    firmware_version = models.CharField(max_length=200, default="")
    serial_number = models.CharField(max_length=200, default="")
    module_name = models.CharField(max_length=200, default="")
    slave_id = models.CharField(max_length=100, default="")
    plant_id = models.CharField(max_length=200, default="")
    raw_output = models.TextField(default="")
    scan_date = models.DateTimeField(auto_now_add=True)


class VulnIntelligence(models.Model):
    device = models.ForeignKey(Device, on_delete=models.CASCADE)
    cve_id = models.CharField(max_length=30, default="")
    cvss_score = models.FloatField(default=0.0)
    epss_score = models.FloatField(default=0.0)
    epss_percentile = models.FloatField(default=0.0)
    kev_listed = models.BooleanField(default=False)
    description = models.TextField(default="")
    exploit_available = models.BooleanField(default=False)
    exploit_refs = models.TextField(default="", blank=True)
    source = models.CharField(max_length=50, default="nvd")
    ransomware_campaign = models.CharField(max_length=300, default="", blank=True)
    propose_action = models.TextField(default="", blank=True)
    last_updated = models.DateTimeField(auto_now=True)


class HoneypotAnalysis(models.Model):
    device = models.ForeignKey(Device, on_delete=models.CASCADE)
    probability = models.FloatField(default=0.0)
    reasons = models.TextField(default="")
    banner_count_in_subnet = models.IntegerField(default=0)
    is_conpot = models.BooleanField(default=False)
    is_cowrie = models.BooleanField(default=False)
    response_time_ms = models.FloatField(default=0.0)
    scan_date = models.DateTimeField(auto_now_add=True)


class SBOMComponent(models.Model):
    device = models.ForeignKey(Device, on_delete=models.CASCADE)
    component_name = models.CharField(max_length=200, default="")
    version = models.CharField(max_length=100, default="")
    component_type = models.CharField(max_length=50, default="library")
    license_name = models.CharField(max_length=100, default="")
    cpe_string = models.CharField(max_length=300, default="")
    source = models.CharField(max_length=50, default="")
    scan_date = models.DateTimeField(auto_now_add=True)


class GFWStatus(models.Model):
    device = models.ForeignKey(Device, on_delete=models.CASCADE)
    reachable = models.BooleanField(default=True)
    last_checked = models.DateTimeField(auto_now=True)
    ooni_report_id = models.CharField(max_length=200, default="")
    blocking_type = models.CharField(max_length=100, default="")


class TaskRun(models.Model):
    STATUS_PENDING = "pending"
    STATUS_RUNNING = "running"
    STATUS_SUCCESS = "success"
    STATUS_FAILURE = "failure"
    STATUS_CHOICES = [
        (STATUS_PENDING, "Pending"),
        (STATUS_RUNNING, "Running"),
        (STATUS_SUCCESS, "Success"),
        (STATUS_FAILURE, "Failure"),
    ]

    TOOL_WAPPALYZER = "wappalyzer"
    TOOL_NUCLEI = "nuclei"
    TOOL_NMAP = "nmap"
    TOOL_PORT_SCAN = "port_scan"
    TOOL_SCREENSHOT = "screenshot"
    TOOL_RTSP = "rtsp"
    TOOL_SHODAN_SCAN = "shodan_scan"
    TOOL_WHOIS = "whois"
    TOOL_NEARBY = "nearby"
    TOOL_DEEP_SCAN = "deep_scan"
    TOOL_NVD = "nvd"
    TOOL_NRICH = "nrich"
    TOOL_CVEDB = "cvedb"
    TOOL_INTEL = "intel"
    TOOL_HONEYPOT = "honeypot"
    TOOL_SBOM = "sbom"
    TOOL_GFW = "gfw"
    TOOL_EXPLOITDB = "exploitdb"
    TOOL_OTHER = "other"
    TOOL_CHOICES = [
        (TOOL_WAPPALYZER, "Wappalyzer"),
        (TOOL_NUCLEI, "Nuclei"),
        (TOOL_NMAP, "Nmap"),
        (TOOL_PORT_SCAN, "Port Scan"),
        (TOOL_SCREENSHOT, "Screenshot"),
        (TOOL_RTSP, "RTSP"),
        (TOOL_SHODAN_SCAN, "Shodan Scan"),
        (TOOL_WHOIS, "Whois"),
        (TOOL_NEARBY, "Nearby"),
        (TOOL_DEEP_SCAN, "Deep Scan"),
        (TOOL_NVD, "NVD"),
        (TOOL_NRICH, "NRICH"),
        (TOOL_CVEDB, "CVEDB"),
        (TOOL_INTEL, "Shodan Intel"),
        (TOOL_HONEYPOT, "Honeypot"),
        (TOOL_SBOM, "SBOM"),
        (TOOL_GFW, "GFW"),
        (TOOL_EXPLOITDB, "ExploitDB"),
        (TOOL_OTHER, "Other"),
    ]

    task_id = models.CharField(max_length=100, db_index=True, unique=True)
    tool = models.CharField(max_length=50, choices=TOOL_CHOICES, default=TOOL_OTHER)
    triggered_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True
    )
    device = models.ForeignKey(Device, on_delete=models.SET_NULL, null=True, blank=True)
    search = models.ForeignKey(Search, on_delete=models.SET_NULL, null=True, blank=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default=STATUS_PENDING)
    started_at = models.DateTimeField(auto_now_add=True)
    finished_at = models.DateTimeField(null=True, blank=True)
    output = models.TextField(default="", blank=True)
    error = models.TextField(default="", blank=True)
    celery_task_name = models.CharField(max_length=255, default="", blank=True)

    class Meta:
        ordering = ["-started_at"]

    def __str__(self):
        return f"{self.tool}:{self.task_id}:{self.status}"


class Playbook(models.Model):
    """A named, ordered sequence of tool plugins to run against one or more devices.

    Steps are stored as a JSON list of dicts::

        [
          {"tool": "screenshot", "order": 1, "exec_type": "chain"},
          {"tool": "nuclei",     "order": 2, "exec_type": "chain"},
        ]

    ``exec_type`` is reserved for future chain/group semantics (currently
    all steps run sequentially / independently per device).
    """

    name = models.CharField(max_length=120, unique=True)
    description = models.TextField(default="", blank=True)
    steps = models.JSONField(
        default=list,
        blank=True,
        help_text=(
            "Ordered list of step dicts: "
            '[{"tool": "screenshot", "order": 1, "exec_type": "chain"}]'
        ),
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.name


class PlaybookRun(models.Model):
    """Records a single execution of a Playbook against a set of devices."""

    STATUS_PENDING = "pending"
    STATUS_RUNNING = "running"
    STATUS_SUCCESS = "success"
    STATUS_FAILURE = "failure"
    STATUS_CHOICES = [
        (STATUS_PENDING, "Pending"),
        (STATUS_RUNNING, "Running"),
        (STATUS_SUCCESS, "Success"),
        (STATUS_FAILURE, "Failure"),
    ]

    playbook = models.ForeignKey(
        Playbook, on_delete=models.CASCADE, related_name="runs"
    )
    device_ids = models.JSONField(
        default=list,
        blank=True,
        help_text="Primary keys of the Device records targeted by this run.",
    )
    status = models.CharField(
        max_length=20, choices=STATUS_CHOICES, default=STATUS_PENDING
    )
    # List of dicts: [{device_id, tool, task_id, task_run_id}, ...]
    task_runs = models.JSONField(default=list, blank=True)
    error = models.TextField(default="", blank=True)
    started_at = models.DateTimeField(auto_now_add=True)
    finished_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["-started_at"]

    def __str__(self):
        return "PlaybookRun #{} ({}) — {}".format(self.pk, self.playbook.name, self.status)
