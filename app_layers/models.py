"""
app_layers/models.py — Data layer system for WorldMonitor-inspired map overlays.

Two models:
  DataLayer    — defines a named, toggleable data source (earthquakes, cables …)
  LayerFeature — individual geographic feature belonging to a layer
"""
from django.db import models
from django.utils import timezone


class DataLayer(models.Model):
    """Metadata and configuration for a single toggleable map overlay."""

    slug = models.SlugField(max_length=80, unique=True)
    name = models.CharField(max_length=200)
    # Geometry type hint: point | linestring | polygon
    layer_type = models.CharField(max_length=30, default="point")
    source_url = models.URLField(max_length=500, blank=True)
    refresh_minutes = models.IntegerField(default=60)
    color = models.CharField(max_length=30, default="#00e1ff")
    icon = models.CharField(max_length=10, default="●")
    enabled = models.BooleanField(default=True)
    # Arbitrary JSON blob for renderer-specific filter/style options
    renderer_config = models.JSONField(default=dict, blank=True)
    last_refreshed = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["name"]

    def __str__(self) -> str:
        return self.name

    def mark_refreshed(self) -> None:
        self.last_refreshed = timezone.now()
        self.save(update_fields=["last_refreshed"])


class LayerFeature(models.Model):
    """A single geographic feature belonging to a DataLayer.

    ``geometry`` stores a GeoJSON geometry object (type + coordinates) as JSON.
    For simple point features ``lat`` and ``lon`` are also stored directly for
    fast bounding-box queries without parsing the geometry blob.
    """

    layer = models.ForeignKey(
        DataLayer, on_delete=models.CASCADE, related_name="features"
    )
    # Convenience columns for point features (may be null for line/polygon layers)
    lat = models.FloatField(null=True, blank=True, db_index=True)
    lon = models.FloatField(null=True, blank=True, db_index=True)
    # GeoJSON geometry blob: {"type": "Point", "coordinates": [lon, lat]}
    geometry = models.JSONField(default=dict)
    # Free-form properties (magnitude, cable name, facility type …)
    properties = models.JSONField(default=dict)
    # Stable external identifier to allow upsert without duplication
    external_id = models.CharField(max_length=200, blank=True, db_index=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]
        # Prevent duplicate external_id rows within the same layer
        constraints = [
            models.UniqueConstraint(
                fields=["layer", "external_id"],
                condition=models.Q(external_id__gt=""),
                name="unique_layer_external_id",
            )
        ]

    def __str__(self) -> str:
        return f"{self.layer.slug}:{self.external_id or self.pk}"
