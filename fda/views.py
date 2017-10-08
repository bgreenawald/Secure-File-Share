from django.shortcuts import render
#~ from django.contrib import auth
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth import authenticate, login
from django.contrib.auth.models import Group, User
from django.http import JsonResponse
from fileupload.models import *
from fileupload.views import hash_code
from signup.models import User_Profile

# Create your views here.
@csrf_exempt
def auth(request):
	uname = request.POST['username']
	pword = request.POST['password']
	user = authenticate(username=uname, password=pword)
	authenticated = False
	ret = {}
	ret['loggedin'] = 'false'
	if (user is not None):
		login(request, user)
		ret['loggedin'] = 'true'
	return JsonResponse(ret)

@csrf_exempt
def list_reports(request):
	ret = {}
	for report in Report.objects.all():
		if (report.owner_id == request.user):
			ret[str(report.report_id)] = report.short_description
	return JsonResponse(ret)

@csrf_exempt
def list_group_reports(request):
	reports = Report.objects.all()
	ret = {}
	for report in reports:
		for group in report.groups.all():
			for rgroup in request.user.groups.all():
				if (rgroup.id == group.id):
					try:
						ret[group.name][str(report.report_id)] = report.short_description
					except:
						ret[group.name] = {}
						ret[group.name][str(report.report_id)] = report.short_description
	return JsonResponse(ret)

@csrf_exempt
def list_public_reports(request):
	reports = Report.objects.all()
	ret = {}
	for report in reports:
		if (report.is_public):
			ret[str(report.report_id)] = report.short_description
	return JsonResponse(ret)

@csrf_exempt
def view_report(request):
	reports = Report.objects.all()
	ret = {}
	ret['bad_cred'] = True
	for report in reports:
		if (report.report_id == int(request.POST['report_id'])):
			viewable = False
			if (report.owner_id == request.user):
				#~ print("Report is owner's")
				viewable = True
			elif (report.is_public):
				#~ print("Report in public")
				viewable = True
			else:
				for group in report.groups.all():
					for rgroup in request.user.groups.all():
						if (group.id == rgroup.id):
							#~ print("Report is in group " + group)
							viewable = True
							break
					if (viewable):
						break
			if (viewable):
				ret['owner'] = report.owner_id.username
				ret['bad_cred'] = False
				ret['short'] = report.short_description
				ret['long'] = report.long_description
				ret['timestamp'] = str(report.timestamp)
				ret['public'] = str(report.is_public)
				ret['groups'] = []
				for g in report.groups.all():
					ret['groups'].append(g.name)
				ret['files'] = {}
				for f in report.files.all():
					ret['files'][str(f.file_id)] = {"name": str(f.filename), "encrypted": f.is_encrypted, "url": f.afile.name}
	return JsonResponse(ret)

@csrf_exempt
def get_public_key(request):
	username = request.GET['username']
	user_id = -1
	ret = {}
	ret['is_user'] = False
	for user in User.objects.all():
		if user.username == username:
			user_id = user.id
			ret['is_user'] = True
			break
	if user_id is not None:
		profiles = User_Profile.objects.all()
		for profile in profiles:
			if (profile.id_id == user_id):
				print(profile.public_key)
				ret["PUBLIC_KEY"] = str(profile.public_key)
				break 
	return JsonResponse(ret)

@csrf_exempt
def get_sha256_sum(request):
	user = request.user
	file_id = request.POST['file_id']
	ret = {}
	for file in TheFile.objects.all():
		if (file.file_id == int(file_id)):
			ret['sha256sum'] = file.hashcode
			break
	return JsonResponse(ret)

@csrf_exempt
def upload_fda(request):
	ret = {}
	ret['is_staff'] = False
	if (request.user.is_staff):
		#print(str(os.listdir('.')))
		fdas = request.FILES.getlist('fda')
		f = fdas[0]
		hash = hash_code(f)
		fda = TheFile(hashcode=hash,afile=f,filename='fda.py')
		fda.save()
		ret['is_staff'] = True
	return JsonResponse(ret)
