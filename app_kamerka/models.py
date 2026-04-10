from django.db import models

# Create your models here.


class Search(models.Model):
    coordinates = models.CharField(max_length=100)
    country = models.CharField(max_length=100)
    ics = models.CharField(max_length=100)
    coordinates_search = models.CharField(max_length=1000)
    nmap = models.BooleanField(default=False)


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
    vulns = models.CharField(max_length=100, default="")
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
    ports = models.CharField(max_length=100)
    tags = models.CharField(max_length=100)
    products = models.CharField(max_length=100)
    module = models.CharField(max_length=100)
    vulns = models.CharField(max_length=100)


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
