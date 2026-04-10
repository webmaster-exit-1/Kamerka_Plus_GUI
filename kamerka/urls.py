"""kamerka URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/2.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path, include, re_path
from django.contrib.staticfiles.views import serve as staticfiles_serve

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', include('app_kamerka.urls'),

         )
    # the endpoint is configurabl)

]

# Serve static files via Django's staticfiles finders regardless of DEBUG mode.
# This is equivalent to `runserver --insecure` and is safe for a local dev tool.
urlpatterns += [
    re_path(r'^static/(?P<path>.*)$', staticfiles_serve, {'insecure': True}),
]
