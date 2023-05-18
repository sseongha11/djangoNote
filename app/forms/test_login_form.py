import re

from django import forms
from django.contrib.auth import get_user_model
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.hashers import make_password
from django.contrib.auth.models import User
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError

from app.models import UserDetail


class LoginForm(forms.Form):
    email = forms.EmailField(label='Email', widget=forms.TextInput(attrs={'class': 'form-control'}), error_messages={
        'invalid': 'This is not a correct email~~',
    })
    password = forms.CharField(widget=forms.PasswordInput(attrs={'class': 'form-control'}), label='Password')

    def clean(self):
        email = self.cleaned_data.get("email")

        if email and email.split("@")[1] == "gmail.com":
            self.add_error('email', "Gmail is not available.")


class SignupForm(UserCreationForm):
    username = forms.CharField(
        label="Username",
        widget=forms.TextInput(attrs={"class": "form-control", "placeholder": "Username"}),
    )
    email = forms.EmailField(
        label="Email",
        widget=forms.TextInput(attrs={"class": "form-control", "placeholder": "Email address"}),
        error_messages={
            "invalid": "This is not a valid format.",
        },
    )
    password1 = forms.CharField(
        widget=forms.PasswordInput(attrs={"class": "form-control", "placeholder": "Password"}), label="Password1"
    )
    password2 = forms.CharField(
        widget=forms.PasswordInput(attrs={"class": "form-control", "placeholder": "Confirm Password"}),
        label="Password2",
        error_messages={
            "password_mismatch": "Ths password is not the same one.",
        },
    )

    class Meta:
        model = User
        fields = (
            "username",
            "email",
            "password1",
            "password2",
        )

    def clean(self):
        username = self.cleaned_data.get("username")

        if not re.match("^[a-z0-9_]*$", username):
            self.add_error("username", "lower cases, numbers and _ (underscore) only could be used.")

        if self.cleaned_data.get("password") is not None:
            try:
                validate_password(self.cleaned_data.get("password"))
            except ValidationError as e:
                self.add_error("password1", "Please check your password.")
        email = self.cleaned_data.get("email")
        user = get_user_model()
        if email is not None:
            dupe_date = user.objects.filter(email=email).exists()
            if dupe_date:
                self.add_error("email", "Please check your email.")

        dupe_date = user.objects.filter(username=username).exists()
        if dupe_date:
            self.add_error("username", "Please check your information.")

    def save(self, commit=True):
        user = super().save(commit=False)
        user.password = make_password(self.cleaned_data.get("password1"))
        if commit:
            user.save()
            UserDetail.objects.create(user=user, note_count=0)

        return user
