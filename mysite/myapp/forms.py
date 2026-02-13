from django import forms
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.models import User

class CustomUserCreationForm(UserCreationForm):
    email = forms.EmailField(required=True)

    class Meta:
        model = User
        fields = ("username", "email", "password1", "password2")

    def save(self, commit=True):
        user = super().save(commit=False)
        user.email = self.cleaned_data["email"]
        if commit:
            user.save()
        return user

class URLScanForm(forms.Form):
    url = forms.URLField(label='Enter URL to scan for phishing')

class EmailScanForm(forms.Form):
    email_subject = forms.CharField(label='Email Subject', max_length=255, required=True)
    email_body = forms.CharField(label='Email Body', widget=forms.Textarea, required=True)
