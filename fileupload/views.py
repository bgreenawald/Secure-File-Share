from django.shortcuts import render_to_response
from django.template import RequestContext
from fileupload.models import TheFile, Report, Message, Folder
from fileupload.forms import ReportForm, MessageForm
from django.core.context_processors import csrf
from django.contrib import auth
import datetime
from django.contrib.auth.models import Group, User
from django.http import HttpResponseRedirect
from fileupload.forms import *
from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from SecureFileShare.settings import MEDIA_ROOT, MEDIA_URL
from signup.models import User_Profile
from django.core.files.base import ContentFile
import os
import random
from django.db.models import Q
from django.contrib.auth.decorators import login_required

# Create your views here.

def hash_code(filename):
	#~ f = open(filename,"rb")
	hash = SHA256.new()
	while True:
		chunk = filename.read()
		if (len(chunk) == 0):
			break
		hash.update(chunk)
	return hash.hexdigest()

# For to create a report
@login_required(login_url='/signup/login/')
def create_report(request):
	args = {}
	suspend(request)
	messages = []
	args['is_manager'] = is_manager(request.user)
	if request.method == 'POST':
		form = ReportForm(request.POST)
		if form.is_valid():
			short_desc = form.cleaned_data['short_description']
			long_desc = form.cleaned_data['long_description']
			public = form.cleaned_data['is_public']
			#~ now = datetime.datetime.now()
			owner = request.user
			report = Report(short_description=short_desc, long_description=long_desc, is_public=public, owner_id=owner, owner_name=owner.username)
			report.save()
			for the_file in request.FILES.getlist('upload'):
				hash = hash_code(the_file)
				newfile = TheFile(afile=the_file, hashcode=hash, filename=str(the_file))
				newfile.save()
				report.files.add(newfile)

			for the_file in request.FILES.getlist('upload_enc'):
				hash = hash_code(the_file)
				newfile = TheFile(afile=the_file, is_encrypted=True, hashcode = hash, filename=str(the_file))
				newfile.save()
				report.files.add(newfile)
				
			#~ report.commit()
			args.update(csrf(request))
			args['error_message'] = "Report created"
			if request.user.is_authenticated():
				messages = Message.objects.filter(receiver=request.user)

			if messages is not None:
				messages = messages.filter(is_viewed=False)
				args['user'] = request.user

			args['user'] = request.user
			args['num_message'] = len(messages)
			return render_to_response("base.html", args)

	args.update(csrf(request))
	args['user'] = request.user
	args['form'] = ReportForm()

	if request.user.is_authenticated():
		messages = Message.objects.filter(receiver=request.user)

		if messages is not None:
			messages = messages.filter(is_viewed=False)
			args['user'] = request.user
			args['message'] = "You have {0} unread messages".format(len(messages))

	args['user'] = request.user
	args['num_message'] = len(messages)

	return render_to_response('create_report.html', args)

# Form to view an individual report and if you are the owner, add new groups to the report 
@login_required(login_url='/signup/login/')
def view_report(request, report_id):
	args = {}
	suspend(request)
	messages = []
	report = Report.objects.get(report_id=report_id)
	args['report'] = report
	owner = report.owner_id
	args['owner'] = owner
	args['user'] = request.user
	args['is_owner'] = owner == request.user
	args['is_manager'] = Group.objects.get(name='manager') in request.user.groups.all()
	can_view = False
	# Check to see if the user has the proper credentials
	manager = Group.objects.get(name='manager')
	if manager in request.user.groups.all() or request.user == report.owner_id or report.is_public:
		can_view = True
	else:
		for group in report.groups.all():
			if group in request.user.groups.all():
				can_view = True
	   
	if not can_view:
		args['message'] = "You do not have permission to view this report"
		if request.user.is_authenticated():
			messages = Message.objects.filter(receiver=request.user)

			if messages is not None:
				messages = messages.filter(is_viewed=False)
				args['user'] = request.user

		args['user'] = request.user
		args['num_message'] = len(messages)
		return render_to_response('base.html', args)
  
	if request.method == 'POST':
		group_name = request.POST.get('value', '')

		try:
			group = Group.objects.get(name=group_name)
		except (Group.DoesNotExist):
			group = None

		if group is not None and group not in report.groups.all():
			report.groups.add(group)
			args['report_message'] = "Add succesful"
		else:
			args['report_message'] = "Could not add"

	args['groups'] = report.groups.all()
	args['groups2'] = request.user.groups.all()
	args.update(csrf(request))
	report.num_views += 1
	report.save()

	if request.user.is_authenticated():
		messages = Message.objects.filter(receiver=request.user)

		if messages is not None:
			messages = messages.filter(is_viewed=False)
			args['user'] = request.user

	args['user'] = request.user
	args['num_message'] = len(messages)

	return render_to_response('view_report.html', args)

@login_required(login_url='/signup/login/')
def inbox(request):
	args = {}
	suspend(request)
	args['user'] = request.user
	args['is_manager'] = is_manager(request.user)
	messages = Message.objects.filter(receiver=request.user, is_deleted=False)

	message_info = []
	groups = request.user.groups.all()
	short = ''
	owner = ''
	read = "read"
	args['read'] = read

	if request.method == "POST":
		checks = request.POST.getlist('checks')

		short = request.POST.get('short_desc', '')
		owner = request.POST.get('owner', '')
		read = request.POST.get('read', '')
		print(read)
		for check in checks:
			mes = Message.objects.get(message_id=check)
			mes.is_deleted = True
			mes.is_viewed = True
			mes.save()

		messages = Message.objects.filter(receiver=request.user, is_deleted=False)
		messages = list(messages)
		if short:
			messages = [x for x in messages if short.lower() in x.subject.lower()]
		if owner:
			messages = [x for x in messages if owner == x.sender.username]
		if read:
			messages = [x for x in messages if x.is_viewed == False]

	args['short_desc']= short
	args['owner'] = owner
	args['read'] = read

	messages = list(reversed(sorted(messages, key=lambda x: x.timestamp)))
	for message in messages:
		message_info.append((message, message.sender.username))

	args['message_info'] = message_info

	messages = []
	if request.user.is_authenticated():
		messages = Message.objects.filter(receiver=request.user)

		if messages is not None:
			messages = messages.filter(is_viewed=False)
			args['user'] = request.user

	args['user'] = request.user
	args['num_message'] = len(messages)

	return render_to_response('inbox.html', args, context_instance=RequestContext(request))

@login_required(login_url='/signup/login/')
def sent(request):
	args = {}
	suspend(request)
	args['user'] = request.user
	args['is_manager'] = is_manager(request.user)
	messages = Message.objects.filter(sender=request.user, is_deleted=False)

	message_info = []
	groups = request.user.groups.all()

	for message in messages:
		message_info.append((message, message.receiver.username))

	args['message_info'] = message_info

	if request.user.is_authenticated():
		messages = Message.objects.filter(receiver=request.user)

		if messages is not None:
			messages = messages.filter(is_viewed=False)
			args['user'] = request.user

	args['user'] = request.user
	args['num_message'] = len(messages)

	return render_to_response('sent.html', args, context_instance=RequestContext(request))

	messages = []
	if request.user.is_authenticated():
		messages = Message.objects.filter(receiver=request.user)

		if messages is not None:
			messages = messages.filter(is_viewed=False)
			args['user'] = request.user

	args['user'] = request.user
	args['num_message'] = len(messages)

	return render_to_response('sent.html', args, context_instance=RequestContext(request))

@login_required(login_url='/signup/login/')
def create_message(request):
	args = {}
	suspend(request)
	temp = request.user
	args['user'] = temp
	args['groups'] = request.user.groups.all()
	args['is_manager'] = is_manager(temp)
	if request.method == 'POST':
		form = MessageForm(request.POST)
		if form.is_valid():
			subject = form.cleaned_data['subject']
			msg_content = form.cleaned_data['msg_content']
			now = datetime.datetime.now()
			sender = request.user
			receiver = request.POST.get('recipient', '')
			is_encrypted = form.cleaned_data['is_encrypted']
			value = request.POST.get('value', '')
			try:
				group = Group.objects.get(name=value)
			except (Group.DoesNotExist):
				group = None

		
			# next step: use username to search for the user in the database, then use that as receiver object
			try:
				recipient = User.objects.get(username=receiver)
			except (User.DoesNotExist):
				recipient = None

			try:
				profile = User_Profile.objects.get(id=recipient)
			except User_Profile.DoesNotExist:
				profile = None

			if (recipient is not None and profile is not None) or group is not None:
				if is_encrypted == True and group:
					
					for user in group.user_set.all():
						recipient = user

						try:
							profile = User_Profile.objects.get(id=recipient)
						except User_Profile.DoesNotExist:
							continue
						key = RSA.importKey(profile.public_key)
						msg_encrypt = key.publickey().encrypt(msg_content.encode("utf-8"), K=32)
					
						message = Message(subject=subject, sender=sender, receiver=recipient, is_encrypted=True)
						message.save()
						filename = "{0}^%$%{1}".format(message.message_id, random.random())
						
						file = TheFile()
						file.save()

						file.afile.save(filename, ContentFile(msg_encrypt[0]))
						file.save()
						message.msg_file.add(file)
						message.save()

					args.update(csrf(request))
					args['error_message'] = "Message sent"
					if request.user.is_authenticated():
						messages = Message.objects.filter(receiver=request.user)

						if messages is not None:
							messages = messages.filter(is_viewed=False)
							args['user'] = request.user

					args['user'] = request.user
					args['num_message'] = len(messages)
					return render_to_response("base.html", args)
				elif is_encrypted == False and value:
					group = Group.objects.get(name=value)
					for user in group.user_set.all():
						recipient = user
						message = Message(subject=subject, timestamp=now, sender=sender, receiver=recipient, is_encrypted=False, msg_content=msg_content)
						message.save()

					args.update(csrf(request))
					args['error_message'] = "Message sent"
					messages = []
					if request.user.is_authenticated():
						messages = Message.objects.filter(receiver=request.user)

						if messages is not None:
							messages = messages.filter(is_viewed=False)
							args['user'] = request.user

					args['user'] = request.user
					args['num_message'] = len(messages)
					return render_to_response("base.html", args)
				elif is_encrypted == True:
					key = RSA.importKey(profile.public_key)
					msg_encrypt = key.publickey().encrypt(msg_content.encode("utf-8"), K=32)
		
					message = Message(subject=subject, timestamp=now, sender=sender, receiver=recipient, is_encrypted=True)
					message.save()
					filename = "{0}^%$%{1}".format(message.message_id, random.random())
					
					file = TheFile()
					file.save()

					file.afile.save(filename, ContentFile(msg_encrypt[0]))
					file.save()
					message.msg_file.add(file)
					message.save()

					args.update(csrf(request))
					args['error_message'] = "Message sent"
					messages = []
					if request.user.is_authenticated():
						messages = Message.objects.filter(receiver=request.user)

						if messages is not None:
							messages = messages.filter(is_viewed=False)
							args['user'] = request.user

					args['user'] = request.user
					args['num_message'] = len(messages)
					return render_to_response("base.html", args)
				else:
					message = Message(subject=subject, sender=sender, receiver=recipient, is_encrypted=False, msg_content=msg_content)
					message.save()
					args.update(csrf(request))
					args['error_message'] = "Message sent"
					messages = []
					if request.user.is_authenticated():
						messages = Message.objects.filter(receiver=request.user)

						if messages is not None:
							messages = messages.filter(is_viewed=False)
							args['user'] = request.user

					args['user'] = request.user
					args['num_message'] = len(messages)
					return render_to_response("base.html", args)

			else:
				args['error_message'] = "User not found"
				args.update(csrf(request))
				args['user'] = request.user
				args['form'] = MessageForm()
				messages = []
				if request.user.is_authenticated():
					messages = Message.objects.filter(receiver=request.user)

					if messages is not None:
						messages = messages.filter(is_viewed=False)
						args['user'] = request.user

				args['user'] = request.user
				args['num_message'] = len(messages)
				return  render_to_response("create_message.html", args)

	args.update(csrf(request))
	args['form'] = MessageForm()
	messages = []
	if request.user.is_authenticated():
		messages = Message.objects.filter(receiver=request.user)

		if messages is not None:
			messages = messages.filter(is_viewed=False)
			args['user'] = request.user

	args['user'] = request.user
	args['num_message'] = len(messages)
	
	return render_to_response('create_message.html', args)

@login_required(login_url='/signup/login/')
def reply_message(request, message_id):
	args = {}
	suspend(request)
	old_message = Message.objects.get(message_id=message_id)
	receiver = old_message.sender.username
	args['user'] = request.user
	args['other'] = receiver
	args['is_manager'] = is_manager(request.user)
	if request.method == 'POST':
		form = MessageForm2(request.POST)
		if form.is_valid():
			subject = form.cleaned_data['subject']
			msg_content = form.cleaned_data['msg_content']
			now = datetime.datetime.now()
			sender = request.user
	
			is_encrypted = form.cleaned_data['is_encrypted']


			# next step: use username to search for the user in the database, then use that as receiver object
			try:
				recipient = User.objects.get(username=receiver)
			except (User.DoesNotExist):
				recipient = None

			try:
				profile = User_Profile.objects.get(id=recipient)
			except User_Profile.DoesNotExist:
				profile = None

			if recipient is not None and profile is not None:
		
				if is_encrypted == True:
					key = RSA.importKey(profile.public_key)
					msg_encrypt = key.publickey().encrypt(msg_content.encode("utf-8"), K=32)
					
					message = Message(subject=subject, timestamp=now, sender=sender, receiver=recipient, is_encrypted=True)
					message.save()
					filename = "{0}^%$%{1}".format(message.message_id, random.random())
					
					file = TheFile()
					file.save()

					file.afile.save(filename, ContentFile(msg_encrypt[0]))
					file.save()
					message.msg_file.add(file)
					message.save()

					args.update(csrf(request))
					args['error_message'] = "Message sent"
					messages = []
					if request.user.is_authenticated():
						messages = Message.objects.filter(receiver=request.user)

						if messages is not None:
							messages = messages.filter(is_viewed=False)
							args['user'] = request.user

					args['user'] = request.user
					args['num_message'] = len(messages)
					return render_to_response("base.html", args)
				else:
				
					message = Message(subject=subject, timestamp=now, sender=sender, receiver=recipient, is_encrypted=False, msg_content=msg_content)
					
					message.save()
					args.update(csrf(request))
					args['error_message'] = "Message sent"
					messages = []
					if request.user.is_authenticated():
						messages = Message.objects.filter(receiver=request.user)

						if messages is not None:
							messages = messages.filter(is_viewed=False)
							args['user'] = request.user

					args['user'] = request.user
					args['num_message'] = len(messages)
					return render_to_response("base.html", args)

			else:
				args['error_message'] = "User not found"
				args.update(csrf(request))
				args['user'] = request.user
				args['form'] = MessageForm2()
				messages = []
				if request.user.is_authenticated():
					messages = Message.objects.filter(receiver=request.user)

					if messages is not None:
						messages = messages.filter(is_viewed=False)
						args['user'] = request.user

				args['user'] = request.user
				args['num_message'] = len(messages)
				return  render_to_response("reply_message.html", args)

	args.update(csrf(request))
	args['form'] = MessageForm2()
	messages = []
	if request.user.is_authenticated():
		messages = Message.objects.filter(receiver=request.user)

		if messages is not None:
			messages = messages.filter(is_viewed=False)
			args['user'] = request.user

	args['user'] = request.user
	args['num_message'] = len(messages)
	return render_to_response('reply_message.html', args)

@login_required(login_url='/signup/login/')
def view_message(request, message_id):
	args = {}
	suspend(request)
	message = Message.objects.get(message_id=message_id)
	if message.is_encrypted:
		content = message.msg_file.all()[0].afile.read()
	else:
		content = message.msg_content

	args['message'] = message
	args['is_manager'] = is_manager(request.user)
	sender = message.sender
	args['id'] = message.message_id
	args['sender'] = message.sender
	args['receiver'] = message.receiver
	args['user'] = request.user
	args['is_sender'] = sender == request.user
	args['title'] = message.subject
	args['content'] = str(content)
	args['encrypted'] = message.is_encrypted
	can_view = False
	# Check to see if the user has the proper credentials
	if request.user ==  message.receiver:
		can_view = True
		message.is_viewed = True
		message.save()
	elif request.user == message.sender:
		can_view = True
	else:
		pass

	if not can_view:
		args['error_message'] = "You do not have permission to view this message"
		messages = []
		if request.user.is_authenticated():
			messages = Message.objects.filter(receiver=request.user)

			if messages is not None:
				messages = messages.filter(is_viewed=False)
				args['user'] = request.user

		args['user'] = request.user
		args['num_message'] = len(messages)
		return render_to_response('base.html', args)

	if request.method == 'POST':

		file = request.FILES.get('upload')
		if file:
			private_key = file.read()

			private_key_2 = RSA.importKey(private_key)
		
			msg = private_key_2.decrypt(content).decode("utf-8")
		
			args['content'] = msg

	args['groups'] = message.groups.all()
	args.update(csrf(request))
	messages = []
	if request.user.is_authenticated():
		messages = Message.objects.filter(receiver=request.user)

		if messages is not None:
			messages = messages.filter(is_viewed=False)
			args['user'] = request.user
			args['message'] = "You have {0} unread messages".format(len(messages))

	args['user'] = request.user
	args['num_message'] = len(messages)
	return render_to_response('view_message.html', args)

@login_required(login_url='/signup/login/')
def trash(request):
	args = {}
	suspend(request)
	args['user'] = request.user
	args['is_manager'] = is_manager(request.user)
	messages = Message.objects.filter(receiver=request.user, is_deleted=True)

	message_info = []
	groups = request.user.groups.all()

	if request.method == "POST":
		checks = request.POST.getlist('checks')
		for check in checks:
			Message.objects.get(message_id=check).delete()

	for message in messages:
		message_info.append((message, message.sender.username))

	args['message_info'] = message_info
	messages = []
	if request.user.is_authenticated():
		messages = Message.objects.filter(receiver=request.user)

		if messages is not None:
			messages = messages.filter(is_viewed=False)
			args['user'] = request.user

	args['user'] = request.user
	args['num_message'] = len(messages)

	return render_to_response('trash.html', args, context_instance=RequestContext(request))

# Browse public reports
@login_required(login_url='/signup/login/')
def browse(request):
    args = {}
    suspend(request)
    args['is_manager'] = is_manager(request.user)
    if request.method=="POST":
        checks = request.POST.get('checks')
        if checks is not None:
            for check in checks:
                Report.objects.get(report_id=check).delete()

    manager = Group.objects.get(name='manager')
    if manager in request.user.groups.all():
        args['is_manager'] = True
        reports_all = list(Report.objects.all())
    else:
        args['is_manager'] = False
        reports_all = list(Report.objects.filter(Q(is_public=True) | Q(owner_id=request.user)))
        reports_group = []
        groups = request.user.groups.all()
     

        for group in groups:
            temp = list(Report.objects.filter(groups__name__exact=group.name))
            for rep in temp:
            	reports_group.append(rep)

 
        if reports_all is not None:
            for report in reports_group:
                if report not in reports_all:
                	reports_all.append(report)

    args['short_desc'] = ""
    args['long_desc'] = ""
    args['owner'] = ""
    args['date_before'] = ""
    args['date_since'] = ""
    args['num'] = ""

    reports_all = list(reversed(sorted(reports_all, key=lambda x: x.timestamp)))
    
    if request.method == "POST":
        short = request.POST.get('short_desc', '')
        longer = request.POST.get('long_desc', '')
        owner = request.POST.get('owner', '')
    
        value = request.POST.get('value', '')
        sort = request.POST.get('value_sort', '')
        

    
        args['short_desc'] = short
        args['long_desc'] = longer
        args['owner'] = owner
      
        args['num'] = value
        args['value_sort'] = sort

        # Search the list based on user input
        if short:
            reports_all = [x for x in reports_all if short.lower() in x.short_description.lower()]
        if longer:
            reports_all = [x for x in reports_all if short.lower() in x.long_description.lower()]
        if owner:
            reports_all = [x for x in reports_all if owner.lower() == x.owner_name]
        if value:
	        if value=='small':
	            args['num'] = "Just a few (0-10)"
	            reports_all = [x for x in reports_all if x.num_views <= 10]
	        elif value=='medium':
	        	args['num'] = "A fair amount (11-25)"
	        	reports_all = [x for x in reports_all if x.num_views > 10 and x.num_views <= 25]
	        else:
	        	args['num'] = "Lots of views (26+)"
	        	reports_all = [x for x in reports_all if x.num_views > 26]
	    
	    # Sort the list based on user input
        if sort:
	        if sort=="newest":
	        	args['value_sort'] = "Newest"
	        	reports_all = list(reversed(sorted(reports_all, key=lambda x: x.timestamp)))
	        elif sort=="oldest":
	        	args['value_sort'] = "Oldest"
	        	reports_all = sorted(reports_all, key=lambda x: x.timestamp)
	        elif sort=="most_viewed":
	        	args['value_sort'] = "Most Viewed"
	        	reports_all = list(reversed(sorted(reports_all, key=lambda x: x.num_views)))
	        elif sort=="least_viewed":
	        	args['value_sort'] = "Least Viewed"
	        	reports_all = sorted(reports_all, key=lambda x: x.num_views)
	        elif sort=="owner_forward":
	        	args['value_sort'] = "Owner Alphabetical"
	        	reports_all = sorted(reports_all, key=lambda x: x.owner_id.username.lower())
	        elif sort=="title_forward":
	        	args['value_sort'] = "Title Alphabetical"
	        	reports_all = sorted(reports_all, key=lambda x: x.short_description.lower())
	        elif sort=="owner_backward":
	        	args['value_sort'] = "Owner Backward Alphabetical"
	        	reports_all = list(reversed(sorted(reports_all, key=lambda x: x.owner_id.username.lower())))
	        elif sort=="title_backward":
	        	args['value_sort'] = "Title Backward Alphabetical"
	        	reports_all = list(reversed(sorted(reports_all, key=lambda x: x.short_description.lower())))

    paginator = Paginator(reports_all, 10)
    page = request.GET.get('page')
    try:
        reports = paginator.page(page)
    except PageNotAnInteger:
        reports = paginator.page(1)
    except EmptyPage:
        reports = paginator.page(paginator.num_pages)

  
    args['reports'] = reports
   # for report in reports:
    #    args[str(report.report_id)] = report.owner_id.username
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
    return render_to_response('browse_report.html', args)

# Page to view users individual reports
@login_required(login_url='/signup/login/')
def user_reports(request, id):
	args = {}
	messages = []
	suspend(request)
	args['user'] = request.user
	args['is_manager'] = is_manager(request.user)
	user = User.objects.get(id=id)
	manager =  Group.objects.get(name='manager')
	print(request.user != user)
	print(manager not in request.user.groups.all())
	if request.user != user and manager not in request.user.groups.all():
		print("In")
		if request.user.is_authenticated():
			messages = Message.objects.filter(receiver=request.user)

			if messages is not None:
				messages = messages.filter(is_viewed=False)
				args['user'] = request.user

		args['user'] = request.user
		args['num_message'] = len(messages)
		return render_to_response("base.html", args)

	if request.method=="POST":
		checks = request.POST.getlist('checks')
		checks2 = request.POST.getlist('checks2')
		checks3 = request.POST.getlist('checks3')
		value = request.POST.get('value')
		value2 = request.POST.get('value2')

		if value2 is not None:
			folder = Folder.objects.get(name=value2)
			for check in checks2:
				if Report.objects.get(report_id=check) not in folder.reports.all():
					folder.reports.add(Report.objects.get(report_id=check))

		if value2 is not None:
			folder = Folder.objects.get(name=value2)
			for check in checks3:
				if Report.objects.get(report_id=check) not in folder.reports.all():
					folder.reports.add(Report.objects.get(report_id=check))

		for check in checks:
			Report.objects.get(report_id=check).delete()

	args['my_reports'] = Report.objects.filter(owner_id=user)
	reports = []
	groups = request.user.groups.all()

	for group in groups:
		rep =  Report.objects.filter(groups__name__contains=group.name)
		for r in rep:
			reports.append((r, group.name))
	args['reports'] = reports
	
	if request.user.is_authenticated():
		messages = Message.objects.filter(receiver=request.user)

		if messages is not None:
			messages = messages.filter(is_viewed=False)
			args['user'] = request.user

	args['folders'] = Folder.objects.filter(owner_id=user)
	args['user'] = request.user
	args['num_message'] = len(messages)
	return render_to_response('my_reports.html', args,  context_instance = RequestContext(request))

# Delete a report 
@login_required(login_url='/signup/login/')
def delete_report(request, report_id):
	args = {}
	suspend(request)
	report = Report.objects.get(report_id=report_id)
	manager = Group.objects.get(name='manager')
	args['user'] = request.user
	args['is_manager'] = is_manager(request.user)
	user = request.user
	if user == report.owner_id or manager in user.groups.all():
		report.delete()
		args['report_message'] = "Report succesfully removed"
	else:
		args['report_message'] = "You do have authorization to remove this report"

	messages = []
	if request.user.is_authenticated():
		messages = Message.objects.filter(receiver=request.user)

		if messages is not None:
			messages = messages.filter(is_viewed=False)
			args['user'] = request.user

	args['user'] = request.user
	args['num_message'] = len(messages)

	return render_to_response('delete_report.html', args)

#Edit an existing report
@login_required(login_url='/signup/login/')
def edit_report(request, report_id):
	args = {}
	suspend(request)
	report = Report.objects.get(report_id=report_id)
	manager = Group.objects.get(name='manager')
	args['user'] = request.user
	args['is_manager'] = is_manager(request.user)
	user = request.user
	if user == report.owner_id or manager in user.groups.all():
		args['report_message'] = ""
	else:
		args['report_message'] = "You do have authorization to edit this report"

	if request.method == "POST":
		report.short_description = request.POST.get('short_desc', '')
		report.long_description = request.POST.get('long_desc', '')
		for iden in request.POST.getlist('checks'):
			TheFile.objects.get(file_id=iden).delete()
		for the_file in request.FILES.getlist('upload'):
			hash = hash_code(the_file)
			newfile = TheFile(afile=the_file, hashcode=hash, filename=str(the_file))
			newfile.save()
			report.files.add(newfile)

		for the_file in request.FILES.getlist('upload_enc'):
			hash = hash_code(the_file)
			newfile = TheFile(afile=the_file, is_encrypted=True, hashcode = hash, filename=str(the_file))
			newfile.save()
			report.files.add(newfile)

		report.save()

	args['short_desc'] = report.short_description
	args['long_desc'] = report.long_description
	args['files'] = []
	for file in report.files.all():
		name = str(file.afile)
		args['files'].append(file)
	args.update(csrf(request))
	messages = []
	if request.user.is_authenticated():
		messages = Message.objects.filter(receiver=request.user)

		if messages is not None:
			messages = messages.filter(is_viewed=False)
			args['user'] = request.user

	args['user'] = request.user
	args['num_message'] = len(messages)
	return render_to_response('edit_report.html', args)

# Page to view users folders
@login_required(login_url='/signup/login/')
def my_folders(request):
	args = {}
	suspend(request)
	args['user'] = request.user
	args['is_manager'] = is_manager(request.user)
	args['my_folders'] = Folder.objects.filter(owner_id=request.user)
	messages = []
	if request.user.is_authenticated():
		messages = Message.objects.filter(receiver=request.user)

		if messages is not None:
			messages = messages.filter(is_viewed=False)
			args['user'] = request.user

	args['user'] = request.user
	args['num_message'] = len(messages)
	return render_to_response('my_folders.html', args,  context_instance = RequestContext(request))

@login_required(login_url='/signup/login/')
def create_folder(request):
	args = {}
	suspend(request)
	args['user'] = request.user
	args['is_manager'] = is_manager(request.user)
	messages = []
	if request.user.is_authenticated():
		messages = Message.objects.filter(receiver=request.user)

		if messages is not None:
			messages = messages.filter(is_viewed=False)
			args['user'] = request.user

	args['user'] = request.user
	args['num_message'] = len(messages)	

	if request.method == "POST":
		name=request.POST.get('name', '')
		try:
			folder = Folder.objects.get(name=name)
		except (Folder.DoesNotExist):
			folder = None

		if folder is None:
			new_folder = Folder(name=name.replace(' ', '_').strip(), owner_id=request.user)
			new_folder.save()
			args['error_message'] = "Folder created"
	
		else:
			args['error_message'] = "Folder with this name already exists"

		return render_to_response('base.html', args)

	args.update(csrf(request))
	return render_to_response("create_folder.html", args)

# Delete a folder 
@login_required(login_url='/signup/login/')
def delete_folder(request, folder_id):
	args = {}
	suspend(request)
	folder = Folder.objects.get(folder_id=folder_id)
	manager = Group.objects.get(name='manager')
	args['user'] = request.user
	user = request.user
	args['is_manager'] = is_manager(request.user)
	if user == folder.owner_id or manager in user.groups.all():
		folder.delete()
		args['folder_message'] = "Folder succesfully removed"
	else:
		args['folder_message'] = "You do have authorization to remove this folder"
	messages = []
	if request.user.is_authenticated():
		messages = Message.objects.filter(receiver=request.user)

		if messages is not None:
			messages = messages.filter(is_viewed=False)
			args['user'] = request.user

	args['user'] = request.user
	args['num_message'] = len(messages)
	return render_to_response('delete_folder.html', args)

# Edit a folder
@login_required(login_url='/signup/login')
def edit_folder(request, folder_id):
	args = {}
	suspend(request)
	folder = Folder.objects.get(folder_id=folder_id)
	manager = Group.objects.get(name='manager')
	args['is_manager'] = is_manager(request.user)
	args.update(csrf(request))
	args['user'] = request.user
	messages = []
	if request.user.is_authenticated():
		messages = Message.objects.filter(receiver=request.user)

		if messages is not None:
			messages = messages.filter(is_viewed=False)
			args['user'] = request.user

	args['num_message'] = len(messages)

	user = request.user
	if user == folder.owner_id or manager in user.groups.all():
		args['folder'] = folder

		if request.method == 'POST':
			args['error_message'] = "Update successful"
			folder.name = request.POST.get('name', '')
			checks = request.POST.getlist('checks', '')
			for check in checks:
				folder.reports.remove(Report.objects.get(report_id=check))

			folder.save()
			return render_to_response('base.html', args)
		
		return render_to_response('edit_folder.html', args)

	else:
		args['folder_message'] = "You do have authorization to remove this folder"
		return render_to_response("base.html", args)


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
