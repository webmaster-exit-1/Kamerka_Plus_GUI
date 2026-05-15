from django.contrib import admin
from app_layers.models import DataLayer, LayerFeature


@admin.register(DataLayer)
class DataLayerAdmin(admin.ModelAdmin):
    list_display = ("name", "slug", "layer_type", "enabled", "last_refreshed")
    list_filter = ("enabled", "layer_type")
    search_fields = ("name", "slug")
    prepopulated_fields = {"slug": ("name",)}


@admin.register(LayerFeature)
class LayerFeatureAdmin(admin.ModelAdmin):
    list_display = ("layer", "external_id", "lat", "lon", "created_at")
    list_filter = ("layer",)
    search_fields = ("external_id",)
