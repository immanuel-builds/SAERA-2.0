from django import forms
from django.contrib.auth.forms import UserCreationForm
from .models import User

class UserRegistrationForm(UserCreationForm):
    """Custom registration form for the security platform"""
    
    email = forms.EmailField(required=True, help_text="Required. Used for system alerts.")
    organization = forms.CharField(max_length=255, required=False, help_text="Optional. Your security organization.")
    department = forms.CharField(max_length=255, required=False, help_text="Optional. Your security department.")
    
    class Meta(UserCreationForm.Meta):
        model = User
        fields = UserCreationForm.Meta.fields + ('email', 'organization', 'department')
        widgets = {
            'username': forms.TextInput(attrs={'placeholder': 'Choose a unique operative ID'}),
            'email': forms.EmailInput(attrs={'placeholder': 'agent@your-org.com'}),
            'organization': forms.TextInput(attrs={'placeholder': 'e.g., Global Security Corp'}),
            'department': forms.TextInput(attrs={'placeholder': 'e.g., Cyber Intelligence'}),
            'password1': forms.PasswordInput(attrs={'placeholder': 'Enter a strong access key'}),
            'password2': forms.PasswordInput(attrs={'placeholder': 'Verify your access key'}),
        }
