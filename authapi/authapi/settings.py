# This file is part of authapi.
# Copyright (C) 2014-2020  Agora Voting SL <contact@nvotes.com>

# authapi is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License.

# authapi  is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.

# You should have received a copy of the GNU Affero General Public License
# along with authapi.  If not, see <http://www.gnu.org/licenses/>.

"""
Django settings for authapi project.

For more information on this file, see
https://docs.djangoproject.com/en/1.7/topics/settings/

For the full list of settings and their values, see
https://docs.djangoproject.com/en/1.7/ref/settings/
"""

import os
from datetime import timedelta

# Build paths inside the project like this: os.path.join(BASE_DIR, ...)
BASE_DIR = os.path.dirname(os.path.dirname(__file__))

class CeleryConfig:
    broker_url = "amqp://guest:guest@localhost:5672//"
    timezone = 'Europe/Madrid'
    beat_schedule = {
        'review_tallies': {
            'task': 'tasks.process_tallies',
            'schedule': timedelta(seconds=10),
            'args': [],
            'options': {
                'expires': 10
            }
        }
    }
    result_backend = 'django-db'

CELERY_CONFIG = CeleryConfig

CELERY_ANNOTATIONS = {
    'tasks.process_tallies': {
        'time_limit': 10
    }
}

# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/1.7/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = 'zct2c=hlij$^0xu0i8o6c^phjc!=m)r(%h90th0yyx9r5dm))+'

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = True

ALLOWED_HOSTS = []

ADMIN_AUTH_ID = 1

TIMEOUT = 300

ADMIN_TIMEOUT = 3000

ALLOW_ADMIN_AUTH_REGISTRATION = False

ALLOW_DEREGISTER = True

# If this option is true, when an user tries to register and the user is
# already registered, authapi will return an error with the 'user_exists'
# codename. Otherwise, on error, authapi will always return the same generic
# error with 'invalid_credentials' codename.
SHOW_ALREADY_REGISTERED = False

# Application definition

INSTALLED_APPS = (
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',

    # custom
    'api',
    'authmethods',
    'captcha',
    'tasks',

    #3rd party
    'django_celery_results',
    'corsheaders',
    'django_nose',
)

PLUGINS = (
    # Add plugins here
)

if PLUGINS:
    INSTALLED_APPS += PLUGINS

MIDDLEWARE = (
    'django.contrib.sessions.middleware.SessionMiddleware',
    'corsheaders.middleware.CorsMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
)

# change the test runner to the one provided by celery so that the tests that
# make use of celery work when ./manage.py test is executed
TEST_RUNNER = 'django_nose.NoseTestSuiteRunner'

ROOT_URLCONF = 'authapi.urls'
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

WSGI_APPLICATION = 'authapi.wsgi.application'


# Database
# https://docs.djangoproject.com/en/1.7/ref/settings/#databases

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': os.path.join(BASE_DIR, 'db.sqlite3'),
    }
}

# Internationalization
# https://docs.djangoproject.com/en/1.7/topics/i18n/

LANGUAGE_CODE = 'en-us'

TIME_ZONE = 'UTC'

USE_I18N = True

USE_L10N = True

USE_TZ = True

# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/1.7/howto/static-files/

STATIC_URL = '/static/'
STATIC_ROOT = os.path.join(BASE_DIR, 'static')

# cors
CORS_ORIGIN_ALLOW_ALL = False
CORS_ORIGIN_WHITELIST = (
        'http://localhost:9001',
)

ENABLE_CAPTCHA = True
PREGENERATION_CAPTCHA = 100

SMS_PROVIDER = "console"
SMS_DOMAIN_ID = ""
SMS_LOGIN = ""
SMS_PASSWORD = ""
SMS_URL = ""
SMS_SENDER_ID = ""
SMS_SENDER_NUMBER = ""
SMS_VOICE_LANG_CODE = ""

MAX_AUTH_MSG_SIZE = {
  "sms": 120,
  "sms-otp": 120,
  "email": 10000,
  "email-otp": 10000
}

SMS_BASE_TEMPLATE = "__MESSAGE__ -- nVotes"

EMAIL_BASE_TEMPLATE = "__MESSAGE__\n\n -- nVotes https://nvotes.com"

EMAIL_BASE_TITLE_TEMPLATE = "__TITLE__ - nVotes"

HOME_URL = "https://agoravoting.example.com/#/election¡/__EVENT_ID__/public/home"
SMS_AUTH_CODE_URL = "https://agoravoting.example.com/#/election/__EVENT_ID__/public/login/__RECEIVER__"
EMAIL_AUTH_CODE_URL = "https://agoravoting.example.com/#/election/__EVENT_ID__/public/login/__RECEIVER__"

AGORA_ELECTIONS_BASE = ["http://127.0.0.1:14443"]

SIMULATE_AGORA_ELECTIONS_CALLBACKS = False

SIZE_CODE = 8
MAX_GLOBAL_STR = 512
MAX_EXTRA_FIELDS = 15
MAX_ADMIN_FIELDS = 15
MAX_SIZE_NAME_EXTRA_FIELD = 1024

MAX_IMAGE_SIZE = 5 * 1024 * 1024 # 5 MB
IMAGE_STORE_PATH = os.path.join(BASE_DIR, 'imgfields')

# List of OpenID Connect providers. Example:
#
# OPENID_CONNECT_PROVIDERS = [
#   dict(
#     public_info = dict(
#       id="example",
#       title="Example Org",
#       description="Some description",
#       icon="https://example.com/image.png"
#     ),
#     private_config=dict(
#       version="1.0",
#       issuer="https://example.org/OP/1",
#       authorization_endpoint="https://example.org/OP/1/authz",
#       token_endpoint="https://example.org/OP/1/token"
#     )
#   )
# ]
OPENID_CONNECT_PROVIDERS_CONF = [
]

# When a task is performed by launching a subprocess, the output of this process
# is going to be written to the database. We use this setting to prevent too
# many updates per second, by setting a minimum elapsed time between DB updates.
TASK_PROCESS_UPDATE_DEBOUNCE_SECS = 2.0

# This is the command to be executed to launch a self-test
TASK_SELF_TEST_COMMAND = ["/home/authapi/launch_selftest.sh"]

# Default maximum amount of time in seconds that a task should last. After this,
# amount of time, the task is killed
TASK_DEFAULT_TIMEOUT_SECS = 60

if not os.path.exists(IMAGE_STORE_PATH):
    os.mkdir(IMAGE_STORE_PATH)

if PLUGINS:
    import importlib
    for plugin in PLUGINS:
        mod = importlib.import_module("%s.settings" % plugin)
        to_import = [name for name in dir(mod) if not name.startswith('_')]
        locals().update({name: getattr(mod, name) for name in to_import})

# Auth api settings
from auth_settings import *

try:
    from custom_settings import *
except:
    pass
