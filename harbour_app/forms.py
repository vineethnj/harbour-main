from django import forms
from .models import Fish,Order

class FishForm(forms.ModelForm):
    class Meta:
        model = Fish
        fields = '__all__'


class OrderForm(forms.ModelForm):
    class Meta:
        model = Order
        fields = "__all__"
        
        
        
from .models import customUser
from django.contrib.auth.forms import UserCreationForm

class CustomUserCreationForm(UserCreationForm):
    email = forms.EmailField(required=True)

    class Meta:
        model = customUser
        fields = ['username', 'email', 'password1', 'password2',]

class LoginForm(forms.Form):
    username = forms.CharField(
        widget=forms.TextInput(attrs={"class": "form-control"})
    )
    password = forms.CharField(
        widget=forms.PasswordInput(attrs={"class": "form-control"})
    )