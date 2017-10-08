
"""SecureFileShare URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/1.8/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  url(r'^$', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  url(r'^$', Home.as_view(), name='home')
"""

from django.contrib.auth import views as auth_views
from django.views.generic.base import TemplateView
from django.conf.urls import patterns, include, url
from django.contrib import admin
from django.conf.urls.static import static
from django.conf import settings
from django.views.generic import RedirectView
from signup.views import *

urlpatterns = [
    url(r'^admin/', include(admin.site.urls)),
    url(r'index/', 'signup.views.index', name='index'), 
    url(r'^fileupload/',include('fileupload.urls', namespace="fileupload")),
    url(r'^fda/',include('fda.urls', namespace="fda")),
    url(r'^groups/',include('groups.urls',namespace='groups')),
    url(r'^$', 'signup.views.index'),
    url(r'^signup/', include('signup.urls', namespace='signup')),
    url(r'^manager/', 'signup.views.manager', name='manager'),
    url(r'^recover/', 'signup.views.recover', name='recover'),
    url(r'^FAQ/', 'signup.views.FAQ', name='FAQ'),
] + static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
