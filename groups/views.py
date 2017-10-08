from django.shortcuts import render, render_to_response
from django.contrib import auth
from django.contrib.auth.models import Group, User
from django.core.context_processors import csrf
from django.http import HttpResponseRedirect
from django.contrib.auth.decorators import login_required
from fileupload.models import Message
import re


# Create your views here.
def index(request):
	args = {}
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

@login_required(login_url='/signup/login/')
def home(request):
	args = {}
	suspend(request)
	args['is_manager'] = is_manager(request.user)
	messages = []
	if request.user.is_authenticated():
		messages = Message.objects.filter(receiver=request.user)

		if messages is not None:
			messages = messages.filter(is_viewed=False)
			args['user'] = request.user

	args['user'] = request.user
	args['num_message'] = len(messages)
	return render_to_response('group_home.html', args)

@login_required(login_url='/signup/login/')
def my_groups(request):
	args = {}
	suspend(request)
	args['is_manager'] = is_manager(request.user)
	messages = []
	if request.user.is_authenticated():
		messages = Message.objects.filter(receiver=request.user)

		if messages is not None:
			messages = messages.filter(is_viewed=False)
			args['user'] = request.user

	args['user'] = request.user
	args['num_message'] = len(messages)
	return render_to_response('my_groups.html', args)

@login_required(login_url='/signup/login/')
def make_group(request):
	args = {}
	suspend(request)
	args['is_manager'] = is_manager(request.user)
	if request.method == 'POST':
		group_name = request.POST.get('group_name', '')
		valid_name = group_name.replace(' ', '_')
		if re.match("^[a-zA-Z0-9_]*$", valid_name):
			(group, created) = Group.objects.get_or_create(name=valid_name)
			if created:
				group.save()
				group.user_set.add(request.user)
				args = {}
				args['user'] = request.user
				args['group_success'] = "Your group has been created"
				args.update(csrf(request))
				messages = []
				if request.user.is_authenticated():
					messages = Message.objects.filter(receiver=request.user)

					if messages is not None:
						messages = messages.filter(is_viewed=False)
						args['user'] = request.user

				args['user'] = request.user
				args['num_message'] = len(messages)
				return render_to_response('my_groups.html', args)
			else:
				args = {}
				args['error_message'] = "A group with that name already exists"
				args.update(csrf(request))
				messages = []
				if request.user.is_authenticated():
					messages = Message.objects.filter(receiver=request.user)

					if messages is not None:
						messages = messages.filter(is_viewed=False)
						args['user'] = request.user

				args['user'] = request.user
				args['num_message'] = len(messages)
				return render_to_response('make_group.html', args)
		else:
			args = {}
			args['error_message'] = "Please only use letters, numbers, underscores, and spaces"
			args.update(csrf(request))
			messages = []
			if request.user.is_authenticated():
				messages = Message.objects.filter(receiver=request.user)

				if messages is not None:
					messages = messages.filter(is_viewed=False)
					args['user'] = request.user

			args['user'] = request.user
			args['num_message'] = len(messages)
			return render_to_response('make_group.html', args)

	args.update(csrf(request))
	args['user'] = request.user
	messages = []
	if request.user.is_authenticated():
		messages = Message.objects.filter(receiver=request.user)

		if messages is not None:
			messages = messages.filter(is_viewed=False)
			args['user'] = request.user

	args['user'] = request.user
	args['num_message'] = len(messages)
	return render_to_response('make_group.html', args)

@login_required(login_url='/signup/login/')
def group_details(request, group_name):

	group = Group.objects.get(name=group_name)
	args = {}
	suspend(request)
	args['is_manager'] = is_manager(request.user)
	args['group_name'] = group.name
	args['users'] = group.user_set.all()

	if request.method == 'POST':
		user_name = request.POST.get('username', '')
		try:
			add_user = User.objects.get(username=user_name)
		except (User.DoesNotExist):
			add_user = None

		if add_user is None:
			args['error'] = "User does not exist"
		elif add_user in group.user_set.all():
			args['error'] = "User is already in group"
		else:
			group.user_set.add(add_user)
			args['error'] = "Add successful"
	
	args['user'] = request.user
	args.update(csrf(request))
	messages = []
	if request.user.is_authenticated():
		messages = Message.objects.filter(receiver=request.user)

		if messages is not None:
			messages = messages.filter(is_viewed=False)
			args['user'] = request.user

	args['user'] = request.user
	args['num_message'] = len(messages)
	return render_to_response('group_details.html', args)

def is_manager(user):
	groups = user.groups.all()
	manager = Group.objects.get(name="manager")
	if manager in groups:
		return True

	return False

def suspend(request):
	suspended = Group.objects.get(name="suspended")
	if suspended in request.user.groups.all():
		auth.logout(request)
		return render_to_response('logged_out.html')