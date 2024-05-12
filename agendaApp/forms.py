from django.forms import ModelForm, DateInput
from .models import Event
from django.contrib.auth import login, authenticate
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.models import User
from django import forms

class EventForm(ModelForm):
  class Meta:
    model = Event
    fields = ["title", "description", "location", "start_time", "end_time"]
    
  def __init__(self, *args, **kwargs):
    super(EventForm, self).__init__(*args, **kwargs)
    self.attrs = {'id': 'formId'}

class RegisterForm(UserCreationForm):
    email = forms.EmailField()

    class Meta:
        model = User
        fields = ["username", "email", "password1", "password2"]

class FriendRequestForm(forms.Form):
    recipient = forms.CharField(max_length=100)

class LoginForm(forms.Form):
    username = forms.CharField(max_length=100)
    password = forms.CharField(widget=forms.PasswordInput)

class SettingForm(forms.Form):
    old_password = forms.CharField(widget=forms.PasswordInput)
    password = forms.CharField(widget=forms.PasswordInput)
    confirm_password = forms.CharField(widget=forms.PasswordInput)