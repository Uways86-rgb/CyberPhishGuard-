from django import forms
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.models import User
from .models import ScanLog

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

class CustomUserEditForm(forms.ModelForm):
    email = forms.EmailField(required=True)
    password1 = forms.CharField(
        label="New Password",
        required=False,
        widget=forms.PasswordInput,
        help_text="Leave blank to keep the current password."
    )
    password2 = forms.CharField(
        label="Confirm New Password",
        required=False,
        widget=forms.PasswordInput,
        help_text="Enter the same password again for confirmation."
    )

    class Meta:
        model = User
        fields = ("username", "email", "first_name", "last_name")

    def clean_username(self):
        username = self.cleaned_data["username"]
        user_id = self.instance.pk
        if User.objects.exclude(pk=user_id).filter(username=username).exists():
            raise forms.ValidationError("This username is already in use.")
        return username

    def clean(self):
        cleaned_data = super().clean()
        password1 = cleaned_data.get('password1')
        password2 = cleaned_data.get('password2')

        if password1 or password2:
            if password1 != password2:
                raise forms.ValidationError("The two password fields must match.")
            if password1 and len(password1) < 8:
                self.add_error('password1', 'Password must be at least 8 characters long.')
        return cleaned_data

    def save(self, commit=True):
        user = super().save(commit=False)
        password = self.cleaned_data.get('password1')
        if password:
            user.set_password(password)
        if commit:
            user.save()
        return user

class ScanLogForm(forms.ModelForm):
    RESULT_CHOICES = [
        ('CLEAN', 'Clean'),
        ('THREAT', 'Threat')
    ]

    result = forms.ChoiceField(choices=RESULT_CHOICES)

    class Meta:
        model = ScanLog
        fields = ("scan_type", "target", "result")

class URLScanForm(forms.Form):
    url = forms.URLField(label='Enter URL to scan for phishing')

class EmailScanForm(forms.Form):
    email_subject = forms.CharField(label='Email Subject', max_length=255, required=True)
    email_body = forms.CharField(label='Email Body', widget=forms.Textarea, required=True)
