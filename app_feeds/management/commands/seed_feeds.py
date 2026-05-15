"""Management command to seed default FeedSource records."""
from django.core.management.base import BaseCommand

from app_feeds.feed_sources import SEED_FEEDS
from app_feeds.models import FeedSource


class Command(BaseCommand):
    help = "Seed default FeedSource records from app_feeds/feed_sources.py"

    def handle(self, *args, **options):
        created = updated = 0
        for entry in SEED_FEEDS:
            url = entry["url"]
            defaults = {
                "name": entry.get("name", url),
                "category": entry.get("category", "other"),
                "active": True,
            }
            _, was_created = FeedSource.objects.update_or_create(url=url, defaults=defaults)
            if was_created:
                created += 1
            else:
                updated += 1

        self.stdout.write(
            self.style.SUCCESS(
                f"Seeded feeds: {created} created, {updated} updated."
            )
        )
