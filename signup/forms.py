from django import forms
from django.contrib.auth.models import User

class UserInfoForm(forms.Form):
	email = forms.EmailField(label="Email")

