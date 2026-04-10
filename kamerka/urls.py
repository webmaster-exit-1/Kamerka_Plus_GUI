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
from django.conf import settings
from django.contrib import admin
from django.urls import path, include, re_path
from django.contrib.staticfiles.urls import staticfiles_urlpatterns
from django.contrib.staticfiles.views import serve as staticfiles_serve

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', include('app_kamerka.urls'),

         )
    # the endpoint is configurabl)

]

if settings.DEBUG:
    # Standard static-file serving when DEBUG is on.
    urlpatterns += staticfiles_urlpatterns()
else:
    # When DEBUG=False the development server skips static files by default.
    # insecure=True re-enables serving via Django's staticfiles finders so the
    # local runserver still works.  In production behind nginx/Apache this route
    # is never reached because the web server handles /static/ directly.
    urlpatterns += [
        re_path(r'^static/(?P<path>.*)$', staticfiles_serve, {'insecure': True}),
    ]
