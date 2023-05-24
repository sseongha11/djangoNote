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
        widget=forms.TextInput(attrs={"class": "form-control", "placeholder": "User Name"}),
    )
    email = forms.EmailField(
        label="Email",
        widget=forms.TextInput(attrs={"class": "form-control", "placeholder": "Email Address"}),
        error_messages={
            "invalid": "This is not an appropriate email.",
        },
    )
    password1 = forms.CharField(
        widget=forms.PasswordInput(attrs={"class": "form-control", "placeholder": "Password"}), label="Password1"
    )
    password2 = forms.CharField(
        widget=forms.PasswordInput(attrs={"class": "form-control", "placeholder": "Check the password"}),
        label="Password2",
        error_messages={
            "password_mismatch": "Please check your information.",
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
            self.add_error("username", "소문자와, 숫자, 언더스코어(_) 만 사용가능!")

        if self.cleaned_data.get("password") is not None:
            try:
                validate_password(self.cleaned_data.get("password"))
            except ValidationError as e:
                self.add_error("password1", "This is not a correct one. Please check the requirements")
        email = self.cleaned_data.get("email")
        user = get_user_model()
        if email is not None:
            dupe_date = user.objects.filter(email=email).exists()
            if dupe_date:
                self.add_error("email", "Please check your information about email or username.")

        dupe_date = user.objects.filter(username=username).exists()
        if dupe_date:
            self.add_error("username", "Please check your information about email or username.")

    def save(self, commit=True):
        user = super().save(commit=False)
        user.password = make_password(self.cleaned_data.get("password1"))
        if commit:
            user.save()
            UserDetail.objects.create(user=user, note_count=0)

        return user
