"""
Django settings for kamerka project.

For more information on this file, see
https://docs.djangoproject.com/en/4.2/topics/settings/

For the full list of settings and their values, see
https://docs.djangoproject.com/en/4.2/ref/settings/
"""

import os
import warnings
from pathlib import Path
from django.core.management.utils import get_random_secret_key

# Build paths inside the project like this: os.path.join(BASE_DIR, ...)
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/4.2/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!
# Set DJANGO_SECRET_KEY in your environment for production deployments.
# If the env var is absent a new random key is generated on each start,
# which invalidates all existing sessions/tokens — acceptable for dev only.
_DEFAULT_SECRET_SENTINEL = "__default__"
_raw_secret_key = os.environ.get('DJANGO_SECRET_KEY', _DEFAULT_SECRET_SENTINEL)
if _raw_secret_key == _DEFAULT_SECRET_SENTINEL:
    SECRET_KEY = get_random_secret_key()
    warnings.warn(
        "DJANGO_SECRET_KEY is not set. A random key will be used, which "
        "invalidates all sessions on restart. Set DJANGO_SECRET_KEY in your "
        "environment for any persistent or production deployment.",
        stacklevel=2,
    )
else:
    SECRET_KEY = _raw_secret_key

# SECURITY WARNING: don't run with debug turned on in production!
# Default is True for the local development server.  Set DEBUG=false (or 0/no)
# via env var when deploying behind a real web server.
DEBUG = os.environ.get('DEBUG', 'True').lower() in ('true', '1', 'yes')

ALLOWED_HOSTS = [h.strip() for h in os.environ.get('ALLOWED_HOSTS', 'localhost,127.0.0.1').split(',') if h.strip()]

# CELERY STUFF (Celery 5.x configuration)
_redis_url = os.environ.get('REDIS_URL', 'redis://localhost:6379')
REDIS_URL = _redis_url
CELERY_BROKER_URL = os.environ.get('CELERY_BROKER_URL', REDIS_URL)
CELERY_RESULT_BACKEND = os.environ.get('CELERY_RESULT_BACKEND', REDIS_URL)
CELERY_ACCEPT_CONTENT = ['application/json']
CELERY_TASK_SERIALIZER = 'json'
CELERY_RESULT_SERIALIZER = 'json'
CELERY_TIMEZONE = os.environ.get('CELERY_TIMEZONE', 'UTC')
CELERY_IMPORTS = ('kamerka.tasks', 'app_layers.tasks', 'app_feeds.tasks')

# ---------------------------------------------------------------------------
# Celery Beat schedule — periodic tasks for layer refresh and feed ingestion
# ---------------------------------------------------------------------------
_LAYER_REFRESH_INTERVAL = int(
    os.environ.get("LAYER_REFRESH_INTERVAL_MINUTES", "60")
) * 60  # convert to seconds

CELERY_BEAT_SCHEDULE = {
    "refresh-feeds-hourly": {
        "task": "app_feeds.tasks.refresh_feeds",
        "schedule": 3600,  # every hour
    },
    "geo-tag-entries-hourly": {
        "task": "app_feeds.tasks.geo_tag_entries",
        "schedule": 3600,
    },
    "refresh-all-layers": {
        "task": "app_layers.tasks.refresh_all_layers",
        "schedule": _LAYER_REFRESH_INTERVAL,
    },
}

# ---------------------------------------------------------------------------
# Cache – backed by the same Redis instance used by Celery.
# Used by the per-IP scan rate limiter (_rate_limit_check in kamerka/tasks.py)
# and any other short-lived shared state.
# ---------------------------------------------------------------------------
CACHES = {
    "default": {
        "BACKEND": "django.core.cache.backends.redis.RedisCache",
        "LOCATION": REDIS_URL,
        "KEY_PREFIX": "kamerka",
        "TIMEOUT": 60,  # default TTL; individual keys override as needed
    }
}
# Application definition
STATIC_URL = '/static/'
MEDIA_URL = '/scans/'
MEDIA_ROOT = os.path.join(BASE_DIR, 'scans')
INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'app_kamerka.apps.AppKamerkaConfig',
    "celery_progress",
    # WorldMonitor integration apps
    "app_layers.apps.AppLayersConfig",
    "app_feeds.apps.AppFeedsConfig",
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.locale.LocaleMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'kamerka.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'kamerka.wsgi.application'

# Database
# https://docs.djangoproject.com/en/3.2/ref/settings/#databases

if os.environ.get("DB_NAME"):
    DATABASES = {
        "default": {
            "ENGINE": "django.db.backends.postgresql",
            "NAME": os.environ.get("DB_NAME", "kamerka"),
            "USER": os.environ.get("DB_USER", "kamerka"),
            "PASSWORD": os.environ.get("DB_PASSWORD", ""),
            "HOST": os.environ.get("DB_HOST", "localhost"),
            "PORT": os.environ.get("DB_PORT", "5432"),
        }
    }
else:
    DATABASES = {
        "default": {
            "ENGINE": "django.db.backends.sqlite3",
            "NAME": os.path.join(BASE_DIR, "db.sqlite3"),
            "OPTIONS": {
                "timeout": 30,  # seconds; reduces "database is locked" under concurrent access
            },
        }
    }

# Password validation
# https://docs.djangoproject.com/en/3.2/ref/settings/#auth-password-validators

AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]

# Internationalization
# https://docs.djangoproject.com/en/3.2/topics/i18n/

LANGUAGE_CODE = 'en-us'

TIME_ZONE = 'UTC'

USE_I18N = True

USE_TZ = True

# Supported UI languages
from django.utils.translation import gettext_lazy as _  # noqa: E402
LANGUAGES = [
    ("en", _("English")),
    ("es", _("Spanish")),
    ("de", _("German")),
    ("fr", _("French")),
    ("zh-hans", _("Simplified Chinese")),
    ("ru", _("Russian")),
]

LOCALE_PATHS = [
    os.path.join(BASE_DIR, "locale"),
]

# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/4.2/howto/static-files/
STATIC_ROOT = os.path.join(BASE_DIR, 'staticfiles')

# Default primary key field type
# https://docs.djangoproject.com/en/4.2/ref/settings/#default-auto-field
DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

# ---------------------------------------------------------------------------
# Production security settings
# These settings are safe and recommended for all deployments.  Some (HSTS,
# secure cookies) only have effect when served over HTTPS; they are harmless
# on HTTP-only development setups.
# ---------------------------------------------------------------------------

# Prevent browsers from MIME-sniffing the content type.
SECURE_CONTENT_TYPE_NOSNIFF = True

# Clickjacking protection — also enforced by XFrameOptionsMiddleware above.
X_FRAME_OPTIONS = 'DENY'

# When behind HTTPS, instruct browsers to only use HTTPS for this origin.
# Set SECURE_HSTS_SECONDS > 0 via env var when deploying over TLS.
SECURE_HSTS_SECONDS = int(os.environ.get('SECURE_HSTS_SECONDS', '0'))
SECURE_HSTS_INCLUDE_SUBDOMAINS = os.environ.get('SECURE_HSTS_INCLUDE_SUBDOMAINS', 'False').lower() in ('true', '1', 'yes')
SECURE_HSTS_PRELOAD = os.environ.get('SECURE_HSTS_PRELOAD', 'False').lower() in ('true', '1', 'yes')

# Redirect plain HTTP to HTTPS (enable via env var when behind TLS).
SECURE_SSL_REDIRECT = os.environ.get('SECURE_SSL_REDIRECT', 'False').lower() in ('true', '1', 'yes')

# Mark session and CSRF cookies as secure (HTTPS-only) when SSL is in use.
SESSION_COOKIE_SECURE = os.environ.get('SESSION_COOKIE_SECURE', 'False').lower() in ('true', '1', 'yes')
CSRF_COOKIE_SECURE = os.environ.get('CSRF_COOKIE_SECURE', 'False').lower() in ('true', '1', 'yes')

# ---------------------------------------------------------------------------
# External tool binary paths
# Imported from kamerka/tool_settings.py so every component (Celery tasks,
# verification pipeline, GUI) reads from a single authoritative source.
# To override, set KAMERKA_NAABU_BIN / KAMERKA_NUCLEI_BIN / KAMERKA_WAPPALYZER_BIN env vars or edit
# kamerka/tool_settings.py directly.
# ---------------------------------------------------------------------------
from kamerka.tool_settings import (  # noqa: E402
    NAABU_BIN,
    NAABU_DEFAULT_PORTS,
    NAABU_DEFAULT_TIMEOUT,
    NAABU_DISCOVERY_PORTS,
    NAABU_DISCOVERY_TIMEOUT,
    NMAP_MAX_RUNTIME,
    NUCLEI_BIN,
    NUCLEI_DEFAULT_TIMEOUT,
    WAPPALYZER_BIN,
)

# ---------------------------------------------------------------------------
# Shodan API key – read once at startup so every component (Django views,
# Celery tasks) shares a single resolved value.  Setting it here means you
# only need the env-var to be present when Django / Celery *start*, not in
# every new terminal that you open afterwards.
#
# Persist it across sessions by adding to ~/.bashrc (or ~/.profile):
#   export SHODAN_API_KEY=your_key_here
#
# For systemd services add an EnvironmentFile or an Environment= line in the
# unit file.  For Docker, use --env-file or -e SHODAN_API_KEY=...
# ---------------------------------------------------------------------------
SHODAN_API_KEY: str = os.environ.get("SHODAN_API_KEY", "")

# ---------------------------------------------------------------------------
# CVE Exploit Execution — disabled by default for safety.
#
# Enabling this setting allows Kamerka to download exploit source code from
# ExploitDB and execute it directly on this host against a target device.
# This is intentionally disabled by default because running untrusted remote
# code is a serious security risk.
#
# Only enable this on a dedicated, isolated, non-production machine and ONLY
# after reviewing what an exploit does.  Consider using a dedicated VM or
# container with restricted network access for running exploits.
#
# To enable, set the environment variable:
#   export KAMERKA_EXPLOIT_EXECUTION_ENABLED=true
# ---------------------------------------------------------------------------
KAMERKA_EXPLOIT_EXECUTION_ENABLED: bool = os.environ.get(
    "KAMERKA_EXPLOIT_EXECUTION_ENABLED", "false"
).lower() in ("true", "1", "yes")

# ---------------------------------------------------------------------------
# WorldMonitor integration settings
# ---------------------------------------------------------------------------

# Optional Ollama host for AI brief generation.
# Leave unset to use the extractive summariser fallback.
# Example: export OLLAMA_HOST=http://localhost:11434
OLLAMA_HOST: str = os.environ.get("OLLAMA_HOST", "")
OLLAMA_MODEL: str = os.environ.get("OLLAMA_MODEL", "llama3")

# Interval (minutes) between automatic layer refresh runs via Celery Beat.
# Defaults to 60 minutes.
LAYER_REFRESH_INTERVAL_MINUTES: int = int(
    os.environ.get("LAYER_REFRESH_INTERVAL_MINUTES", "60")
)

# Maximum number of FeedEntry rows to retain (oldest pruned automatically).
FEED_MAX_ENTRIES: int = int(os.environ.get("FEED_MAX_ENTRIES", "500"))
