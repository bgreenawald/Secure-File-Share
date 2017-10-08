from django.contrib.auth import views as auth_views
from django.views.generic.base import TemplateView
from django.conf.urls import patterns, include, url
from django.contrib import admin
from django.conf.urls.static import static
from django.conf import settings
from django.views.generic import RedirectView
from fda.views import *

app_name='fda'
urlpatterns = [
	url(r'^auth/$', 'fda.views.auth', name='auth'),
	url(r'^list-reports/$', 'fda.views.list_reports', name='list-reports'),
	url(r'^list-public-reports/$', 'fda.views.list_public_reports', name='list-public-reports'),
	url(r'^list-group-reports/$', 'fda.views.list_group_reports', name='list-group-reports'),
	url(r'^view-report/$', 'fda.views.view_report', name='view-report'),
	url(r'^upload-fda/$', 'fda.views.upload_fda', name='upload-fda'),
	url(r'^get-public-key/$', 'fda.views.get_public_key', name='get-public-key'),
	url(r'^get-sha256-sum/$', 'fda.views.get_sha256_sum', name='get-sha256-sum')
]
