from django.contrib.auth.models import User, Group
from django.db import models
from django import forms
import string
import random

ENG_CHARS = 'abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ'
HEX_CHARS = 'abcdefabcdef0987654321'
CHARS = HEX_CHARS

def get_upload_path(instance, filename):
	print(instance.hashcode)
	r = ''
	for i in range(16):
		r = r + random.choice(CHARS)
	return 'files/' + r + '/' + instance.hashcode[0:16] + '/' + filename

# Create your models here.
class TheFile(models.Model):
	file_id = models.AutoField(primary_key=True)
	is_encrypted = models.BooleanField(default=False)
	hashcode = models.CharField(max_length=65, default="")
	#~ smallhash = models.CharField(max_length=16, default="")
	afile = models.FileField(upload_to=get_upload_path)
	filename = models.CharField(max_length=128, default="")

class Report(models.Model):
	report_id = models.AutoField(primary_key=True)
	short_description = models.CharField(max_length=160)
	long_description = models.CharField(max_length=1000)
	timestamp = models.DateTimeField(auto_now_add=True)
	is_public = models.BooleanField(default=False)
	groups = models.ManyToManyField(Group)
	files = models.ManyToManyField(TheFile)
	owner_id = models.ForeignKey(User)
	owner_name = models.CharField(max_length=1000, default='ben')
	num_views = models.IntegerField(default=0)

class Message(models.Model):
	sender = models.ForeignKey(User, related_name="sender")
	receiver = models.ForeignKey(User, related_name="receiver")
	subject = models.CharField(max_length=100)
	timestamp = models.DateTimeField(auto_now_add=True)
	groups = models.ManyToManyField(Group)
	is_encrypted = models.BooleanField(default=False)
	is_deleted = models.BooleanField(default=False)
	is_viewed = models.BooleanField(default=False)
	msg_content = models.CharField(max_length=5000, default="")
	message_id = models.AutoField(primary_key=True)
	msg_file = models.ManyToManyField(TheFile)

class Folder(models.Model):
	folder_id = models.AutoField(primary_key=True)
	name = models.CharField(max_length=160)
	reports = models.ManyToManyField(Report)
	owner_id = models.ForeignKey(User)
