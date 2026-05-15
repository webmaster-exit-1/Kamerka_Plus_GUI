"""Management command to seed default DataLayer records from layers.json."""
import json
import os

from django.core.management.base import BaseCommand

from app_layers.models import DataLayer


class Command(BaseCommand):
    help = "Seed default DataLayer records from app_layers/config/layers.json"

    def handle(self, *args, **options):
        config_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
            "config",
            "layers.json",
        )
        with open(config_path) as fh:
            layers_cfg = json.load(fh)["layers"]

        created = updated = 0
        for cfg in layers_cfg:
            slug = cfg["slug"]
            defaults = {
                "name": cfg.get("name", slug),
                "layer_type": cfg.get("layer_type", "point"),
                "source_url": cfg.get("source_url", ""),
                "refresh_minutes": cfg.get("refresh_minutes", 60),
                "color": cfg.get("color", "#ffffff"),
                "icon": cfg.get("icon", "●"),
                "enabled": cfg.get("enabled", True),
                "renderer_config": cfg.get("renderer_config", {}),
            }
            _, was_created = DataLayer.objects.update_or_create(slug=slug, defaults=defaults)
            if was_created:
                created += 1
            else:
                updated += 1

        self.stdout.write(
            self.style.SUCCESS(
                f"Seeded layers: {created} created, {updated} updated."
            )
        )
