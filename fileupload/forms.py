from django import forms

class AFileForm(forms.Form):
    afile = forms.FileField(
        label='Select a file'
    )

class ReportForm(forms.Form):
    short_description = forms.CharField(label="Short report description", max_length=160)
    long_description = forms.CharField(label="Long report description", max_length=1000, widget=forms.Textarea)
    is_public = forms.BooleanField(label="Is this report public?",required=False, initial=False)

class MessageForm(forms.Form):
    subject = forms.CharField(label="Subject", max_length=100)
    msg_content = forms.CharField(label="Message Content", max_length=5000, widget=forms.Textarea)
  #  receiver = forms.CharField(label="Message Recipients", max_length=5000)
    is_encrypted = forms.BooleanField(label="Is this message encrypted?", required=False, initial=False)

class MessageForm2(forms.Form):
    subject = forms.CharField(label="Subject", max_length=100)
    msg_content = forms.CharField(label="Message Content", max_length=5000, widget=forms.Textarea)
    is_encrypted = forms.BooleanField(label="Is this message encrypted?", required=False, initial=False)