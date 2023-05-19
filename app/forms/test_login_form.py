import re

from django import forms
from django.contrib.auth import get_user_model
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.hashers import make_password, check_password
from django.contrib.auth.models import User
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from django.db.models import Q

from app.models import UserDetail


class LoginForm(forms.Form):
    email_or_username = forms.CharField(
        label="Email_USERNAME",
        widget=forms.TextInput(attrs={"class": "form-control"}),
    )
    password = forms.CharField(widget=forms.PasswordInput(attrs={"class": "form-control"}), label="Password")


class SignupForm(UserCreationForm):
    username = forms.CharField(
        label="Username",
        widget=forms.TextInput(attrs={"class": "form-control", "placeholder": "Username"}),
    )
    email = forms.EmailField(
        label="Email",
        widget=forms.TextInput(attrs={"class": "form-control", "placeholder": "Email Address"}),
        error_messages={
            "invalid": "This is not correct email address.",
        },
    )
    password1 = forms.CharField(
        widget=forms.PasswordInput(attrs={"class": "form-control", "placeholder": "Password"}), label="Password1"
    )
    password2 = forms.CharField(
        widget=forms.PasswordInput(attrs={"class": "form-control", "placeholder": "Check Password"}),
        label="Password2",
        error_messages={
            "password_mismatch": "The password is not identical.",
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
            self.add_error("username", "Lowercase, number and underscore(_) only can used.")

        if self.cleaned_data.get("password") is not None:
            try:
                validate_password(self.cleaned_data.get("password"))
            except ValidationError as e:
                self.add_error("password1", "This password is not appropriate.")
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
