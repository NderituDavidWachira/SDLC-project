"""Django settings for SDLC Guard.

Secure defaults: DEBUG is off unless DJANGO_DEBUG=1, the secret key must come
from the environment in production, and HTTPS-only cookies/headers are enabled
whenever DEBUG is off.
"""
import os
import sys
from pathlib import Path

from django.core.exceptions import ImproperlyConfigured

BASE_DIR = Path(__file__).resolve().parent.parent

DEBUG = os.environ.get('DJANGO_DEBUG', '0') == '1'
TESTING = 'test' in sys.argv

SECRET_KEY = os.environ.get('DJANGO_SECRET_KEY')
if not SECRET_KEY:
    if DEBUG or TESTING:
        SECRET_KEY = 'dev-only-insecure-key-do-not-use-in-production'  # nosec B105
    else:
        raise ImproperlyConfigured('Set the DJANGO_SECRET_KEY environment variable.')

ALLOWED_HOSTS = [h.strip() for h in
                 os.environ.get('DJANGO_ALLOWED_HOSTS', 'localhost,127.0.0.1').split(',')
                 if h.strip()]

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'accounts',
    'scanner',
    'dashboard',
    'audit',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'whitenoise.middleware.WhiteNoiseMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'config.urls'
WSGI_APPLICATION = 'config.wsgi.application'

TEMPLATES = [{
    'BACKEND': 'django.template.backends.django.DjangoTemplates',
    'DIRS': [BASE_DIR / 'templates'],
    'APP_DIRS': True,
    'OPTIONS': {'context_processors': [
        'django.template.context_processors.request',
        'django.contrib.auth.context_processors.auth',
        'django.contrib.messages.context_processors.messages',
    ]},
}]

DATABASES = {'default': {
    'ENGINE': 'django.db.backends.sqlite3',
    'NAME': os.environ.get('DJANGO_DB_PATH', str(BASE_DIR / 'db.sqlite3')),
}}

AUTH_USER_MODEL = 'accounts.User'
AUTH_PASSWORD_VALIDATORS = [
    {'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator'},
    {'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
     'OPTIONS': {'min_length': 10}},
    {'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator'},
    {'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator'},
]

LOGIN_URL = 'login'
LOGIN_REDIRECT_URL = 'dashboard'
LOGOUT_REDIRECT_URL = 'login'

LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'Africa/Nairobi'
USE_I18N = True
USE_TZ = True

STATIC_URL = 'static/'
STATICFILES_DIRS = [BASE_DIR / 'static']
STATIC_ROOT = BASE_DIR / 'staticfiles'
DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

# Login brute-force protection (see accounts/views.py)
LOGIN_MAX_ATTEMPTS = 5
LOGIN_LOCKOUT_SECONDS = 900

# Browser / transport hardening
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = 'Lax'
SESSION_COOKIE_AGE = 60 * 60  # one-hour sessions
CSRF_COOKIE_SAMESITE = 'Lax'
SECURE_CONTENT_TYPE_NOSNIFF = True
SECURE_REFERRER_POLICY = 'same-origin'
X_FRAME_OPTIONS = 'DENY'

if not DEBUG and not TESTING:
    SECURE_SSL_REDIRECT = os.environ.get('DJANGO_SSL_REDIRECT', '1') == '1'
    SESSION_COOKIE_SECURE = True
    CSRF_COOKIE_SECURE = True
    SECURE_HSTS_SECONDS = 31536000
    SECURE_HSTS_INCLUDE_SUBDOMAINS = True
    SECURE_HSTS_PRELOAD = True

# ---- Scanner settings -------------------------------------------------------
# Folders to scan (os.pathsep-separated). Defaults to this project only.
_raw_paths = os.environ.get('SDLCGUARD_SCAN_PATHS', '')
SDLCGUARD_SCAN_PATHS = [Path(p) for p in _raw_paths.split(os.pathsep) if p] or [BASE_DIR]
# Also inspect this computer: shell history, VS Code settings/extensions, environment.
SDLCGUARD_SCAN_MACHINE = os.environ.get('SDLCGUARD_SCAN_MACHINE', '1') == '1'
# Optional GitHub API check (needs a read-only token). Leave empty to stay offline.
SDLCGUARD_GITHUB_REPO = os.environ.get('SDLCGUARD_GITHUB_REPO', '')
SDLCGUARD_GITHUB_TOKEN = os.environ.get('SDLCGUARD_GITHUB_TOKEN', '')
SDLCGUARD_TRUSTED_VSCODE_PUBLISHERS = (
    'microsoft', 'ms-python', 'ms-vscode', 'ms-toolsai', 'ms-azuretools', 'ms-dotnettools',
    'github', 'redhat', 'esbenp', 'dbaeumer', 'eamodio', 'batisteo', 'tamasfe', 'hashicorp',
    'golang', 'rust-lang', 'vscjava', 'gitlab', 'pkief', 'bradlc', 'mikestead',
    'visualstudioexptteam', 'donjayamanne', 'formulahendry', 'oderwat', 'ritwickdey')
