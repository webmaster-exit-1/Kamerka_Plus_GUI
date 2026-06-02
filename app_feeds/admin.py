from django.contrib import admin
from app_feeds.models import FeedSource, FeedEntry, Brief


@admin.register(FeedSource)
class FeedSourceAdmin(admin.ModelAdmin):
    list_display = ("name", "folder", "category", "active", "last_fetched", "error_count")
    list_filter = ("active", "category", "folder")
    search_fields = ("name", "url")


@admin.register(FeedEntry)
class FeedEntryAdmin(admin.ModelAdmin):
    list_display = ("title", "source", "published", "geo_countries")
    list_filter = ("source__category",)
    search_fields = ("title", "summary")
    date_hierarchy = "published"


@admin.register(Brief)
class BriefAdmin(admin.ModelAdmin):
    list_display = ("region", "method", "generated_at")
    list_filter = ("method",)
    search_fields = ("region",)
