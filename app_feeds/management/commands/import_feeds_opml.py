"""Import FeedSource records from a Feeder OPML export."""
from pathlib import Path

from django.core.management.base import BaseCommand

from app_feeds.models import FeedSource
from app_feeds.opml import parse_opml

DEFAULT_OPML = Path(__file__).resolve().parents[2] / "data" / "feeder-export.opml"


class Command(BaseCommand):
    help = "Import FeedSource records from an OPML file (default: bundled feeder-export.opml)"

    def add_arguments(self, parser):
        parser.add_argument(
            "opml_path",
            nargs="?",
            default=str(DEFAULT_OPML),
            help="Path to OPML file",
        )
        parser.add_argument(
            "--deactivate-missing",
            action="store_true",
            help="Set active=False on feeds whose URLs are not in this OPML",
        )
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Print counts only; do not write to the database",
        )

    def handle(self, *args, **options):
        opml_path = Path(options["opml_path"])
        if not opml_path.is_file():
            self.stderr.write(self.style.ERROR(f"OPML not found: {opml_path}"))
            return

        feeds = parse_opml(opml_path)
        if not feeds:
            self.stderr.write(self.style.WARNING(f"No feeds found in {opml_path}"))
            return

        imported_urls = {f["url"] for f in feeds}
        created = updated = 0

        if options["dry_run"]:
            self.stdout.write(f"Would import {len(feeds)} feeds from {opml_path}")
            by_folder: dict[str, int] = {}
            for f in feeds:
                by_folder[f["folder"]] = by_folder.get(f["folder"], 0) + 1
            for folder, count in sorted(by_folder.items()):
                self.stdout.write(f"  {folder}: {count}")
            return

        for entry in feeds:
            defaults = {
                "name": entry["name"],
                "category": entry["category"],
                "folder": entry["folder"],
                "active": True,
            }
            _, was_created = FeedSource.objects.update_or_create(
                url=entry["url"],
                defaults=defaults,
            )
            if was_created:
                created += 1
            else:
                updated += 1

        deactivated = 0
        if options["deactivate_missing"]:
            deactivated = (
                FeedSource.objects.exclude(url__in=imported_urls)
                .filter(active=True)
                .update(active=False)
            )

        self.stdout.write(
            self.style.SUCCESS(
                f"Imported {len(feeds)} feeds from {opml_path.name}: "
                f"{created} created, {updated} updated"
                + (f", {deactivated} deactivated" if options["deactivate_missing"] else "")
            )
        )