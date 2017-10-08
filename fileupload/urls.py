from django.contrib.auth import views as auth_views
from django.views.generic.base import TemplateView
from django.conf.urls import patterns, include, url
from django.contrib import admin
from django.conf.urls.static import static
from django.conf import settings
from django.views.generic import RedirectView
from fileupload.views import *

app_name='fileupload'
urlpatterns = [
    #~ url(r'^list/$', 'fileupload.views.list_files', name='list'),
    url(r'^create_report/', 'fileupload.views.create_report', name='create_report'),
    url(r'^(?P<report_id>[0-9]+)/', 'fileupload.views.view_report', name='view_report'),
    url(r'^browse/$', 'fileupload.views.browse', name='browse'),
    url(r'^user_reports/(?P<id>[0-9]+)/$', 'fileupload.views.user_reports', name='user_reports'),
    url(r'^inbox/$', 'fileupload.views.inbox', name='inbox'),
    url(r'^create_message/$', 'fileupload.views.create_message', name='create_message'),
    url(r'^trash/$', 'fileupload.views.trash', name='trash'),
    url(r'^delete_report/(?P<report_id>[0-9]+)/$', 'fileupload.views.delete_report', name='delete_report'),
    url(r'^edit_report/(?P<report_id>[0-9]+)/$', 'fileupload.views.edit_report', name='edit_report'),
    url(r'^view_message/(?P<message_id>[0-9]+)/', 'fileupload.views.view_message', name='view_message'),
    url(r'^reply_message/(?P<message_id>[0-9]+)/', 'fileupload.views.reply_message', name='reply_message'),
    url(r'^create_folder/$', 'fileupload.views.create_folder', name='create_folder'),
    url(r'^edit_folder/(?P<folder_id>[0-9]+)/', 'fileupload.views.edit_folder', name='edit_folder'),
    url(r'^delete_folder/(?P<folder_id>[0-9]+)/', 'fileupload.views.delete_folder', name='delete_folder'),
]
