from django.contrib import admin
from .models import Report, Message, TheFile, Folder

# Register your models here.
admin.site.register(Report)
admin.site.register(Message)
admin.site.register(TheFile)
admin.site.register(Folder)