from django.contrib.auth import views as auth_views
from django.views.generic.base import TemplateView
from django.conf.urls import patterns, include, url
from django.contrib import admin
from django.conf.urls.static import static
from django.conf import settings
from django.views.generic import RedirectView
from signup.views import *

app_name='signup'
urlpatterns = [
	url(r'^login/$', 'signup.views.login', name='login'),
    url(r'^logout/$', 'signup.views.logout', name='logout'),
    url(r'^auth/$', 'signup.views.auth_view'),
    url(r'^loggedin/$', 'signup.views.loggedin'),
    url(r'^invalid/$', 'signup.views.invalid_login'),
    url(r'^user/(?P<username>[\w.@+-]+)/$', 'signup.views.user_details', name='user_details'),
    url(r'^register/$', 'signup.views.register_user', name='register'),
    url(r'^register/register_success$', 'signup.views.register_success', name='register_success'),
]