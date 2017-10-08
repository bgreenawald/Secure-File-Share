from django.contrib.auth.models import User
from django.db import models

"""class User(models.Model):
	uid = models.AutoField(primary_key=True)
	username = models.CharField(max_length=50)
	first_name = models.CharField(max_length=50)
	last_name = models.CharField(max_length=50)
	password = models.CharField(max_length=50)
"""

class User_Profile(models.Model):
	id = models.OneToOneField(User, primary_key=True)
	email = models.EmailField(default='None')
	public_key = models.TextField(max_length=1000)
