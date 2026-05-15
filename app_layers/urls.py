from django.urls import path
from app_layers import views

urlpatterns = [
    path("layers/", views.layer_list, name="layer_list"),
    path("layers/<slug:slug>/features.json", views.layer_features, name="layer_features"),
    path("layers/<slug:slug>/refresh/", views.layer_refresh, name="layer_refresh"),
    path("layers/import/", views.layer_import, name="layer_import"),
]
