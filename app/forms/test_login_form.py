from django import forms


class LoginForm(forms.Form):
    email = forms.EmailField(label='Email', widget=forms.TextInput(attrs={'class': 'form-control'}), error_messages={
            'invalid': 'This is not a correct email~~',
        })
    password = forms.CharField(widget=forms.PasswordInput(attrs={'class': 'form-control'}), label='Password')

    def clean(self):
        email = self.cleaned_data.get("email")

        if email and email.split("@")[1] == "gmail.com":
            self.add_error('email', "Gmail is not available.")
