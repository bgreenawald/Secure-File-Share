"""
Django settings for SecureFileShare project.

Generated by 'django-admin startproject' using Django 1.8.7.

For more information on this file, see
https://docs.djangoproject.com/en/1.8/topics/settings/

For the full list of settings and their values, see
https://docs.djangoproject.com/en/1.8/ref/settings/
"""

# Build paths inside the project like this: os.path.join(BASE_DIR, ...)
import os
from os.path import expanduser

home = expanduser("~")
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/1.8/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = '(=qjt#g(lo(e4g$&uklpe32keb!lt1r1q_%*$k6&-o6w3#!i02'

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = True

ALLOWED_HOSTS = []

EMAIL_USE_TLS = True
DEFAULT_FROM_EMAIL = 'test@gmail.com'
SERVER_EMAIL = 'test@gmail.com'
EMAIL_HOST = 'smtp.gmail.com'
EMAIL_PORT = 587
EMAIL_HOST_USER = 'test@gmail.com'
EMAIL_HOST_PASSWORD = 'test123##'
EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'

# Application definition

INSTALLED_APPS = (
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'signup',
    'fileupload',
    'groups',
    'bootstrap3',
    'widget_tweaks',
)

MIDDLEWARE_CLASSES = (
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.auth.middleware.SessionAuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    'django.middleware.security.SecurityMiddleware',
)

ROOT_URLCONF = 'SecureFileShare.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': ['templates', os.path.join(BASE_DIR, 'templates'),
                'templates/login', os.path.join(BASE_DIR, 'templates/login'),
                'templates/reports', os.path.join(BASE_DIR, 'templates/reports'),
                'templates/folders', os.path.join(BASE_DIR, 'templates/folders') ],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
                'django.core.context_processors.static',
            ],
        },
    },
]

WSGI_APPLICATION = 'SecureFileShare.wsgi.application'


# Database
# https://docs.djangoproject.com/en/1.8/ref/settings/#databases

DATABASES = {
	'default': {
		'ENGINE': 'django.db.backends.postgresql_psycopg2',
		'NAME': 'df3ont4q5gv759',
		'USER': 'ndxrnxwwzbnpkc',
		'PASSWORD': 'bxIuTfgzIYB0bKfLyMCmFLaces',
		'HOST': 'ec2-54-243-185-123.compute-1.amazonaws.com'
		#~ 'PORT': '5432'
	}
}

if os.environ.get('DATABASE_URL'):
	import dj_database_url
	db_from_env = dj_database_url.config(conn_max_age=500)
	DATABASES['default'].update(db_from_env)


# Internationalization
# https://docs.djangoproject.com/en/1.8/topics/i18n/

LANGUAGE_CODE = 'en-us'

TIME_ZONE = 'EST'

USE_I18N = True

USE_L10N = True

USE_TZ = True


# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/1.8/howto/static-files/

# STATIC_ROOT = os.path.join(BASE_DIR, 'staticfiles')
STATIC_ROOT = os.path.join(os.path.dirname(__file__), '..', 'static').replace('\\', '/')
STATIC_URL = '/static/'
STATICFILES_DIRS = (
    #~ os.path.join(BASE_DIR, 'static'),
)


MEDIA_ROOT = home
MEDIA_URL = '/media/'

# Change the login redirect url
LOGIN_REDIRECT_URL = '/index/'
