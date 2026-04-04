"""
Management command: scan_ip — terminal-mode Nmap / Shodan scanner.

Provides a pure-CLI workflow for operators who prefer terminal interaction
over the web UI.  Runs Celery tasks synchronously (via ``.apply()``) and
prints results to stdout.

Usage examples
--------------
::

    # Basic Nmap scan with default ports
    python manage.py scan_ip 192.168.1.1

    # Specify ports and timing
    python manage.py scan_ip 10.0.0.5 --ports 22,80,443,502 --timing T4

    # Run with a specific NSE script
    python manage.py scan_ip 10.0.0.5 --nse nmap_scripts/modbus-discover.nse

    # Custom extra flags
    python manage.py scan_ip 10.0.0.5 --ports 80 --extra-flags "-sV --osscan-guess"

    # Shodan host lookup (requires SHODAN_API_KEY env var)
    python manage.py scan_ip 10.0.0.5 --shodan

    # JSON output (for scripting / piping)
    python manage.py scan_ip 10.0.0.5 --output json
"""

import ipaddress
import json
import textwrap

from django.core.management.base import BaseCommand, CommandError


class Command(BaseCommand):
    help = (
        "Run Nmap and/or Shodan scans against an IP address from the terminal. "
        "Results are printed to stdout — no web UI required."
    )

    def add_arguments(self, parser):
        parser.add_argument("ip", type=str, help="Target IP address to scan")
        parser.add_argument(
            "--ports",
            type=str,
            default=None,
            help="Comma-separated port list (e.g. 22,80,443,502). "
            "Defaults to common ICS/IoT ports.",
        )
        parser.add_argument(
            "--timing",
            type=str,
            default=None,
            choices=["T0", "T1", "T2", "T3", "T4", "T5"],
            help="Nmap timing template (T0=paranoid … T5=insane).",
        )
        parser.add_argument(
            "--nse",
            type=str,
            default=None,
            help="Path to an NSE script relative to the project root "
            "(e.g. nmap_scripts/modbus-discover.nse).",
        )
        parser.add_argument(
            "--extra-flags",
            type=str,
            default=None,
            dest="extra_flags",
            help="Additional Nmap flags (e.g. '-sV --osscan-guess'). "
            "Validated against an allow-list.",
        )
        parser.add_argument(
            "--shodan",
            action="store_true",
            default=False,
            help="Also run a Shodan host lookup (requires SHODAN_API_KEY).",
        )
        parser.add_argument(
            "--output",
            type=str,
            default="table",
            choices=["table", "json"],
            help="Output format: 'table' (human-readable) or 'json'.",
        )
        parser.add_argument(
            "--no-nmap",
            action="store_true",
            default=False,
            dest="no_nmap",
            help="Skip the Nmap scan (useful with --shodan for Shodan-only lookup).",
        )

    def handle(self, *args, **options):
        ip = options["ip"]

        # Validate IP address
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            raise CommandError("Invalid IP address: {}".format(ip))

        results = {}

        # ── Nmap scan ──────────────────────────────────────────────────────
        if not options["no_nmap"]:
            self.stderr.write(self.style.NOTICE("Starting Nmap scan on {}…".format(ip)))
            nmap_result = self._run_nmap(
                ip,
                ports=options["ports"],
                timing=options["timing"],
                nse_script=options["nse"],
                extra_flags=options["extra_flags"],
            )
            results["nmap"] = nmap_result

        # ── Shodan host lookup ─────────────────────────────────────────────
        if options["shodan"]:
            self.stderr.write(
                self.style.NOTICE("Running Shodan host lookup for {}…".format(ip))
            )
            shodan_result = self._run_shodan(ip)
            results["shodan"] = shodan_result

        # ── Output ─────────────────────────────────────────────────────────
        if options["output"] == "json":
            self.stdout.write(json.dumps(results, indent=2))
        else:
            self._print_table(results)

    def _run_nmap(self, ip, ports=None, timing=None, nse_script=None, extra_flags=None):
        """Run Nmap scan synchronously and return the result dict."""
        from kamerka.tasks import (
            _run_nmap_with_timeout,
            _sanitize_nmap_flags,
        )

        import re
        import os
        import xmltodict
        from django.conf import settings

        # Build options
        port_spec = ports or "21,22,23,80,102,443,502,1911,4911,8080,9600,20000,44818,47808"
        if not re.match(r"^[\d,-]+$", port_spec):
            return {"Error": "Invalid port specification: {}".format(port_spec)}

        options = "-p {}".format(port_spec)

        if timing:
            options += " -{}".format(timing)

        if nse_script:
            safe_base = os.path.realpath(
                os.path.join(settings.BASE_DIR, "nmap_scripts")
            )
            script_abs = os.path.realpath(
                os.path.join(settings.BASE_DIR, nse_script)
            )
            if not script_abs.startswith(safe_base + os.sep) and script_abs != safe_base:
                return {"Error": "Invalid script path"}
            if not os.path.isfile(script_abs):
                return {"Error": "NSE script not found: {}".format(nse_script)}
            options += " --script={}".format(nse_script)
        else:
            options += " -sV"

        if extra_flags:
            clean_flags, err = _sanitize_nmap_flags(extra_flags)
            if err:
                return {"Error": err}
            if clean_flags:
                options += " " + clean_flags

        self.stderr.write("  Options: {}".format(options))

        nm_result = _run_nmap_with_timeout(ip, options)

        if nm_result["error"] or not nm_result["stdout"]:
            return {
                "Error": nm_result["error"] or "No Nmap output",
                "stderr": nm_result.get("stderr", ""),
            }

        # Parse results
        return_dict = {}
        try:
            u = xmltodict.parse(nm_result["stdout"])
            host = u.get("nmaprun", {}).get("host", {})
            ports_data = host.get("ports", {}).get("port", {})

            if isinstance(ports_data, list):
                for p in ports_data:
                    port_id = p.get("@portid", "")
                    state = p.get("state", {}).get("@state", "")
                    service = p.get("service", {}).get("@name", "")
                    return_dict["port_{}".format(port_id)] = {
                        "state": state,
                        "service": service,
                    }
                    scripts = p.get("script", {})
                    if isinstance(scripts, dict):
                        return_dict["script_{}".format(scripts.get("@id", ""))] = (
                            scripts.get("@output", "")
                        )
                    elif isinstance(scripts, list):
                        for s in scripts:
                            return_dict["script_{}".format(s.get("@id", ""))] = (
                                s.get("@output", "")
                            )
            elif isinstance(ports_data, dict):
                port_id = ports_data.get("@portid", "")
                state = ports_data.get("state", {}).get("@state", "")
                service = ports_data.get("service", {}).get("@name", "")
                return_dict["port_{}".format(port_id)] = {
                    "state": state,
                    "service": service,
                }
        except Exception as e:
            return_dict["parse_error"] = str(e)
            return_dict["raw"] = nm_result["stdout"][:2000]

        return_dict["options_used"] = options
        return return_dict

    def _run_shodan(self, ip):
        """Run a Shodan host lookup and return the result dict."""
        import os

        shodan_key = os.environ.get("SHODAN_API_KEY", "")
        if not shodan_key:
            return {"Error": "SHODAN_API_KEY environment variable not set"}

        try:
            from shodan import Shodan
            from kamerka.tasks import _shodan_with_retry, _log_shodan_credits

            api = Shodan(shodan_key)
            results = _shodan_with_retry(api.host, ip)
            _log_shodan_credits(api)

            return {
                "ip": results.get("ip_str", ip),
                "org": results.get("org", ""),
                "os": results.get("os", ""),
                "ports": results.get("ports", []),
                "vulns": list(results.get("vulns", {}).keys()) if "vulns" in results else [],
                "hostnames": results.get("hostnames", []),
                "country": results.get("country_code", ""),
                "city": results.get("city", ""),
                "isp": results.get("isp", ""),
                "products": list({
                    d["product"]
                    for d in results.get("data", [])
                    if "product" in d
                }),
                "tags": list({
                    tag
                    for d in results.get("data", [])
                    for tag in d.get("tags", [])
                }),
            }
        except Exception as e:
            return {"Error": str(e)}

    def _print_table(self, results):
        """Print results in a human-readable table format."""
        if "nmap" in results:
            nmap = results["nmap"]
            self.stdout.write("")
            self.stdout.write(self.style.SUCCESS("═══ NMAP SCAN RESULTS ═══"))
            if "Error" in nmap:
                self.stdout.write(self.style.ERROR("  Error: {}".format(nmap["Error"])))
                if nmap.get("stderr"):
                    self.stdout.write("  stderr: {}".format(nmap["stderr"]))
            else:
                if "options_used" in nmap:
                    self.stdout.write("  Options: {}".format(nmap["options_used"]))
                for key, val in nmap.items():
                    if key in ("options_used", "raw", "parse_error"):
                        continue
                    if key.startswith("port_"):
                        port_num = key.replace("port_", "")
                        if isinstance(val, dict):
                            self.stdout.write(
                                "  Port {:>5s}  {:8s}  {}".format(
                                    port_num,
                                    val.get("state", ""),
                                    val.get("service", ""),
                                )
                            )
                        else:
                            self.stdout.write("  Port {:>5s}  {}".format(port_num, val))
                    elif key.startswith("script_"):
                        script_name = key.replace("script_", "")
                        self.stdout.write(
                            "  Script [{}]:".format(script_name)
                        )
                        for line in str(val).split("\n"):
                            self.stdout.write("    {}".format(line))

        if "shodan" in results:
            shodan = results["shodan"]
            self.stdout.write("")
            self.stdout.write(self.style.SUCCESS("═══ SHODAN HOST LOOKUP ═══"))
            if "Error" in shodan:
                self.stdout.write(self.style.ERROR("  Error: {}".format(shodan["Error"])))
            else:
                for key in ("ip", "org", "isp", "country", "city", "os"):
                    if shodan.get(key):
                        self.stdout.write(
                            "  {:12s} {}".format(key.title() + ":", shodan[key])
                        )
                if shodan.get("ports"):
                    self.stdout.write(
                        "  Ports:       {}".format(
                            ", ".join(str(p) for p in shodan["ports"])
                        )
                    )
                if shodan.get("products"):
                    self.stdout.write(
                        "  Products:    {}".format(", ".join(shodan["products"]))
                    )
                if shodan.get("hostnames"):
                    self.stdout.write(
                        "  Hostnames:   {}".format(", ".join(shodan["hostnames"]))
                    )
                if shodan.get("vulns"):
                    self.stdout.write(
                        self.style.WARNING(
                            "  Vulns:       {}".format(", ".join(shodan["vulns"]))
                        )
                    )
                if shodan.get("tags"):
                    self.stdout.write(
                        "  Tags:        {}".format(", ".join(shodan["tags"]))
                    )

        self.stdout.write("")
