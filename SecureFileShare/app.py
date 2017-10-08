from django.apps import AppConfig
from django.contrib.auth.models import User, Group
from signup.models import User_Profile

class MyAppConfig(AppConfig):
	name = 'SecureFileShare'
	verbose_name="Secure File Share"
	def ready(self):
		try:
			super = User.objects.get(username='super')
		except (User.DoesNotExist):
			super = User(username='super', password='root')
			super.save()
			profile = User_Profile(id=super)
			profile.save()

		(manager, created) = Group.objects.get_or_create(name='manager')

		if created:
			manager.save()
			manager.add(super)

		(suspended, created2) = Group.objects.get_or_create(name='suspended')
		
		if created2:
		suspended.save()


