"""
app_feeds/models.py — RSS/news feed ingestion and AI brief storage.

Models
------
FeedSource  — a single RSS/Atom feed URL with category and active flag
FeedEntry   — an individual article parsed from a FeedSource
Brief       — AI-generated (or extractive) summary for a region/topic
"""
from django.db import models


class FeedSource(models.Model):
    """A single RSS/Atom feed to be periodically polled."""

    CATEGORY_CHOICES = [
        ("cyber", "Cybersecurity"),
        ("ics", "ICS/SCADA"),
        ("geo", "Geopolitics"),
        ("infra", "Infrastructure"),
        ("other", "Other"),
    ]

    url = models.URLField(max_length=500, unique=True)
    name = models.CharField(max_length=200)
    category = models.CharField(max_length=20, choices=CATEGORY_CHOICES, default="other")
    active = models.BooleanField(default=True)
    last_fetched = models.DateTimeField(null=True, blank=True)
    error_count = models.IntegerField(default=0)

    class Meta:
        ordering = ["category", "name"]

    def __str__(self) -> str:
        return f"[{self.category}] {self.name}"


class FeedEntry(models.Model):
    """A single article from a FeedSource."""

    source = models.ForeignKey(
        FeedSource, on_delete=models.CASCADE, related_name="entries"
    )
    title = models.CharField(max_length=500, default="")
    summary = models.TextField(default="")
    url = models.URLField(max_length=500, blank=True)
    published = models.DateTimeField(null=True, blank=True, db_index=True)
    # Extracted country codes (ISO-2, comma-separated) found in the text
    geo_countries = models.CharField(max_length=500, blank=True, default="")
    # Centroid lat/lon when a single country or location is resolved
    geo_lat = models.FloatField(null=True, blank=True)
    geo_lon = models.FloatField(null=True, blank=True)
    # Stable id from the feed to prevent duplicates
    entry_id = models.CharField(max_length=500, blank=True, db_index=True)
    fetched_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-published"]
        constraints = [
            models.UniqueConstraint(
                fields=["source", "entry_id"],
                condition=models.Q(entry_id__gt=""),
                name="unique_source_entry_id",
            )
        ]

    def __str__(self) -> str:
        return self.title[:80]


class Brief(models.Model):
    """AI-synthesised (or extractive) intelligence brief for a region/topic."""

    region = models.CharField(
        max_length=200,
        help_text="ISO-2 country code, region name, or topic keyword",
    )
    content = models.TextField()
    generated_at = models.DateTimeField(auto_now_add=True)
    # 'ollama' | 'extractive'
    method = models.CharField(max_length=30, default="extractive")

    class Meta:
        ordering = ["-generated_at"]

    def __str__(self) -> str:
        return f"Brief({self.region}, {self.generated_at:%Y-%m-%d})"
