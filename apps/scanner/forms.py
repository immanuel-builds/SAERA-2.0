"""
Forms for scanner app
"""
from django import forms
from crispy_forms.helper import FormHelper
from crispy_forms.layout import Layout, Submit, Row, Column, Div
from .models import ScanTarget, ScanConfiguration
from .validators import validate_scan_target


class ScanTargetForm(forms.ModelForm):
    """Form for creating scan targets"""
    
    class Meta:
        model = ScanTarget
        fields = ['name', 'target', 'target_type', 'description']
        widgets = {
            'name': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'e.g., Production Server'}),
            'target': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'e.g., 192.168.1.1 or example.com'}),
            'target_type': forms.Select(attrs={'class': 'form-control'}),
            'description': forms.Textarea(attrs={'class': 'form-control', 'rows': 3, 'placeholder': 'Optional description'}),
        }
    
    def clean_target(self):
        target = self.cleaned_data.get('target')
        validate_scan_target(target)
        return target


class QuickScanForm(forms.Form):
    """Quick scan form"""
    
    target = forms.CharField(
        max_length=255,
        label='Target IP/Domain',
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': 'Enter IP address, domain, or CIDR range'
        })
    )

    def clean_target(self):
        target = self.cleaned_data.get('target')
        validate_scan_target(target)
        return target
    
    scan_type = forms.ChoiceField(
        label='Scan Type',
        choices=[
            ('quick', 'Quick Scan (Top 100 ports - ~30 sec)'),
            ('standard', 'Standard Scan (Top 1000 ports - ~2 min)'),
            ('deep', 'Deep Scan (All ports - ~10 min)'),
        ],
        initial='standard',
        widget=forms.Select(attrs={'class': 'form-control'})
    )
    
    enable_service_detection = forms.BooleanField(
        label='Enable Service Version Detection',
        required=False,
        initial=True,
        widget=forms.CheckboxInput(attrs={'class': 'form-check-input'})
    )
    
    enable_vuln_detection = forms.BooleanField(
        label='Enable Vulnerability Detection',
        required=False,
        initial=True,
        widget=forms.CheckboxInput(attrs={'class': 'form-check-input'})
    )


class ScanConfigurationForm(forms.ModelForm):
    """Form for detailed scan configuration"""
    
    class Meta:
        model = ScanConfiguration
        fields = ['name', 'scan_type', 'port_range', 'enable_service_detection', 
                 'enable_os_detection', 'enable_vuln_detection', 'timeout']
        widgets = {
            'name': forms.TextInput(attrs={'class': 'form-control'}),
            'scan_type': forms.Select(attrs={'class': 'form-control'}),
            'port_range': forms.TextInput(attrs={'class': 'form-control', 'placeholder': '1-1000 or 80,443,8080'}),
            'timeout': forms.NumberInput(attrs={'class': 'form-control'}),
        }
