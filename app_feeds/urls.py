from django.urls import path
from app_feeds import views

urlpatterns = [
    path("feeds/entries/", views.feed_entries, name="feed_entries"),
    path("feeds/entries/sse/", views.feed_sse, name="feed_sse"),
    path("feeds/brief/<str:region>/", views.brief_view, name="brief_view"),
    path("feeds/brief/<str:region>/generate/", views.brief_generate, name="brief_generate"),
]
