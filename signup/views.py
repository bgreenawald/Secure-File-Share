from django.shortcuts import render, render_to_response
from django.contrib.auth.forms import UserCreationForm
from django.core.context_processors import csrf
from django.contrib import auth
from django.contrib.auth.models import Group, User
from signup.models import User_Profile
from fileupload.models import Message
from signup.forms import UserInfoForm
from django.http import HttpResponseRedirect, HttpResponse
from Crypto.PublicKey import RSA
from django.conf import settings
from django.core.servers.basehttp import FileWrapper
import mimetypes
import os
from django.utils.encoding import smart_str
import random
from django.core.files.base import ContentFile
from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger
from django.contrib.auth.decorators import login_required


def suspend(request):
	suspended = Group.objects.get(name="suspended")
	if suspended in request.user.groups.all():
		auth.logout(request)
		return render_to_response('logged_out.html')
	else:
		return


def index(request):
	args = {}

	try:
		super_user = User.objects.get(username='manager')
	except (User.DoesNotExist):
		super_user = User.objects.create_user(username='manager', password='root')
		super_user.save()
		profile = User_Profile(id=super_user, email='')
		profile.save()

	(manager, created) = Group.objects.get_or_create(name='manager')

	if created:
		manager.save()
		manager.user_set.add(super_user)
		

	(suspended, created2) = Group.objects.get_or_create(name='suspended')
	
	messages = []
	
	if created2:
		suspended.save()

	suspend(request)
	args['is_manager'] = is_manager(request.user)

	messages = []
	if request.user.is_authenticated():
		messages = Message.objects.filter(receiver=request.user)

		if messages is not None:
			messages = messages.filter(is_viewed=False)
			args['user'] = request.user
			args['message'] = "You have {0} unread messages".format(len(messages))

	

	args['user'] = request.user
	args['num_message'] = len(messages)
	return render_to_response('base.html', args)

def is_manager(user):
	groups = user.groups.all()
	manager = Group.objects.get(name="manager")
	if manager in groups:
		return True
	else: 
		return False

@login_required(login_url='/signup/login/')
def manager(request):
	args = {}
	user = request.user
	suspend(request)
	groups = user.groups.all()
	manager = Group.objects.get(name="manager")
	if manager in groups:
		is_manager = True
	else: 
		is_manager = False

	args['user'] = request.user
	args['is_manager'] = is_manager
	args['name'] = ""
	messages = []
	if request.user.is_authenticated():
		messages = Message.objects.filter(receiver=request.user)

		if messages is not None:
			messages = messages.filter(is_viewed=False)
			args['user'] = request.user

	args['user'] = request.user
	args['num_message'] = len(messages)

	args.update(csrf(request))
	if not is_manager:
		args['error_message'] = "You do not have authorization to view this page"
		return render_to_response('base.html', args)
	else:
		users = User.objects.all()

		if request.method == "POST":
			username = request.POST.get('short_desc', '')
			args['name'] = username
			users = list(users)
			users = [x for x in users if username.lower() in x.username.lower()]


		paginator = Paginator(users, 10)
		page = request.GET.get('page')
		try:
			users = paginator.page(page)
		except PageNotAnInteger:
			users = paginator.page(1)
		except EmptyPage:
			users = paginator.page(paginator.num_pages)
		user_info = []
		for usr in users:
			suspended = Group.objects.get(name='suspended')
			manager = Group.objects.get(name='manager')

			is_suspended = ""
			is_manager = ""
			if suspended in usr.groups.all():
				is_suspended = "Suspended"
			else:
				is_suspended = "Not suspended"

			if manager in usr.groups.all():
				is_manager = "Manager"
			else:
				is_manager = "Not a manager"

			user_info.append((usr, is_suspended, is_manager))
		args['user_info'] = user_info
		return render_to_response("manager.html", args)


@login_required(login_url='/signup/login/')
def recover(request):
	args = {}
	suspend(request)
	args.update(csrf(request))
	args['is_manager'] = is_manager(request.user)
	messages = []
	if request.user.is_authenticated():
		messages = Message.objects.filter(receiver=request.user)

		if messages is not None:
			messages = messages.filter(is_viewed=False)
			args['user'] = request.user

	args['user'] = request.user
	args['num_message'] = len(messages)

	if request.method=="POST":
		new_key = RSA.generate(2048, e=65537)
		public_key = new_key.publickey().exportKey("PEM")

		file_name = "{0}_privateKey".format(request.user.username)
		private_key = new_key.exportKey("PEM")
		args['private_key'] = private_key 

		profile = User_Profile.objects.get(id=request.user)
		profile.public_key = public_key	 
		profile.save()

		messages = Message.objects.filter(receiver=request.user)
		messages = messages.filter(is_encrypted=True)
		for message in messages:
			message.is_deleted = True
			message.is_viewed = True
			message.save()

		args['path'] = settings.MEDIA_ROOT

		return render_to_response("recovery_confirm.html", args)

	args['confirm_message'] = "Are you sure you want to proceed? Generating a new public/private key pair will invalidate all old encrypted messages and all such messages will be automatically moved to trash. Encrypted files may also be invalidated"
	return render_to_response("recover.html", args)	

def login(request):
	c = {}
	c['is_manager'] = is_manager(request.user)
	c.update(csrf(request))
	return render_to_response('login.html', c)


def auth_view(request):
	username = request.POST.get('username', '')
	password = request.POST.get('password', '')

	user = auth.authenticate(username=username, password=password)

	if user is not None:
		is_suspended = Group.objects.get(name='suspended') in user.groups.all()

	if user is not None and not is_suspended:

		auth.login(request, user)
		args = {}
		args['is_manager'] = is_manager(request.user)
		args['user'] = request.user
		args['full_name'] = request.user.username
		messages = []
		if request.user.is_authenticated():
			messages = Message.objects.filter(receiver=request.user)

			if messages is not None:
				messages = messages.filter(is_viewed=False)
				args['user'] = request.user

		args['user'] = request.user
		args['num_message'] = len(messages)
		return render_to_response("loggedin.html", args)
	elif user is not None and is_suspended:
		args = {}
		args.update(csrf(request))
		args['error'] = "Your account has been suspended"
		return render_to_response('login.html', args)
	else:
		args = {}
		args.update(csrf(request))
		args['error'] = "Your login info is invalid"
		return render_to_response('login.html', args)


def loggedin(request):
	return render_to_response("loggedin.html", {
		'full_name': request.user.username,
		'user': request.user
	})


def invalid_login(request):
	return render_to_response('invalid_login.html')


def logout(request):
	auth.logout(request)
	return render_to_response('logged_out.html')


def register_user(request):
	args = {}
	if request.method == 'POST':
		form = UserCreationForm(request.POST)

		if form.is_valid():
			form.save()

			user = User.objects.get(username=form.cleaned_data['username'])
			new_key = RSA.generate(2048, e=65537)
			public_key = new_key.publickey().exportKey("PEM")

			file_name = "{0}_privateKey".format(form.cleaned_data['username'])
			private_key = new_key.exportKey("PEM")

			args['private_key'] = private_key
			profile = User_Profile(id=user, email="", public_key=public_key)

			profile.save()
			messages = []
			if request.user.is_authenticated():
				messages = Message.objects.filter(receiver=request.user)

				if messages is not None:
					messages = messages.filter(is_viewed=False)
					args['user'] = request.user

				args['user'] = request.user
				args['num_message'] = len(messages)
			return render_to_response('register_success.html', args)
		else:
			args['errors'] = form.errors
			args['form'] = UserCreationForm()

	else:
		args['form'] = UserCreationForm()

	args.update(csrf(request))
	args['user'] = request.user
	return render_to_response('register.html', args)


def register_success(request):
	return render_to_response('register_success.html')


def user_details(request, username):
	args = {}
	args['is_manager'] = is_manager(request.user)
	second_user = User.objects.get(username=username)
	args['second_user'] = second_user
	args['user'] = request.user
	args['manager'] = Group.objects.get(name='manager')
	suspended = Group.objects.get(name='suspended')

	button_value = request.POST.get('submit', '')
	args['btn_value'] = button_value
	if button_value == "Suspend":
		suspended.user_set.add(second_user)
	elif button_value == "Restore":
		suspended.user_set.remove(second_user)
	elif button_value == "Add" or button_value == "Remove":
		group_name = request.POST.get('group', '')
		try:
			group = Group.objects.get(name=group_name)
		except Group.DoesNotExist:
			group = None

		if group is None:
			args['group_error_message'] = "Group does not exist"
		elif button_value == "Add" and group not in second_user.groups.all():
			group.user_set.add(second_user)
			args['group_error_message'] = "Added succesfully"
		elif button_value == "Add":
			args['group_error_message'] = "User already in group"
		elif button_value == "Remove" and group in second_user.groups.all():
			group.user_set.remove(second_user)
			args['group_error_message'] = "User removed succesfully"
		elif button_value == "Remove":
			args['group_error_message'] = "Could not remove, user not in group"

	if suspended in second_user.groups.all():
		args['is_suspended'] = True
	else:
		args['is_suspeneded'] = False

	args.update(csrf(request))
	messages = []
	if request.user.is_authenticated():
		messages = Message.objects.filter(receiver=request.user)

		if messages is not None:
			messages = messages.filter(is_viewed=False)
			args['user'] = request.user

	args['user'] = request.user
	args['num_message'] = len(messages)
	return render_to_response('user_details.html', args)

def FAQ(request):
	args = {}
	args['user'] = request.user
	suspend(request)
	args.update(csrf(request))
	args['is_manager'] = is_manager(request.user)
	messages = []
	if request.user.is_authenticated():
		messages = Message.objects.filter(receiver=request.user)

		if messages is not None:
			messages = messages.filter(is_viewed=False)
			args['user'] = request.user

	args['user'] = request.user
	args['num_message'] = len(messages)

	return render_to_response('FAQ.html', args)