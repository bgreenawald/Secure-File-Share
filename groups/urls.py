from django.contrib.auth import views as auth_views
from django.views.generic.base import TemplateView
from django.conf.urls import patterns, include, url
from django.contrib import admin
from django.conf.urls.static import static
from django.conf import settings
from django.views.generic import RedirectView
from groups.views import *

app_name='groups'
urlpatterns = [
	url(r'^$', 'groups.views.index'),
	url(r'^home/', 'groups.views.home', name='home'),
	url(r'^my_groups/', 'groups.views.my_groups', name='my_groups'),
	url(r'^make_group/', 'groups.views.make_group', name='make_group'),
	url(r'^(?P<group_name>[\w.@+-]+)/$', 'groups.views.group_details', name='details'),
]