from django.shortcuts import render
from rest_framework import status, viewsets, mixins, generics
from rest_framework.exceptions import NotFound
from django.http import Http404
from rest_framework.decorators import api_view
from rest_framework.views import APIView
from django import forms
from django.utils.safestring import mark_safe
from django.contrib.postgres.forms import SimpleArrayField
from django.contrib.auth.forms import AuthenticationForm, UserCreationForm
from django.contrib.auth import get_user_model
import uuid
from ego.models import * 
from ego.serializers import *

class UserProfileForm(forms.ModelForm):
    class Meta:
        model = UserProfile
        fields = ['user', 'email', 'FastPassHost', 'FastPassPort']

class AdminUserProfileForm(forms.ModelForm):
    class Meta:
        model = UserProfile
        fields = ['user', 'email', 'FastPassHost', 'FastPassPort']

class TenantInvitationForm(forms.ModelForm):
    class Meta:
        model = TenantInvitation
        fields = ['email', 'role']

class EGOAgentForm(forms.ModelForm):
    class Meta:
        model = EGOAgent
        fields = ['name', 'hostLocation', 'callBackTime', 'alive', 'scanning']

User = get_user_model()

class OTPAuthenticationForm(AuthenticationForm):
    otp_code = forms.CharField(max_length=6, widget=forms.TextInput(attrs={'autocomplete': 'off'}))

class CustomUserCreationForm(UserCreationForm):
    secret_code = forms.CharField(max_length=100, required=False)
    email = forms.EmailField(required=True)
    tenant = forms.CharField(max_length=100)  # Add this line

    class Meta(UserCreationForm.Meta):
        fields = UserCreationForm.Meta.fields + ('email', 'secret_code', 'tenant',)  # Add 'tenant' here

User = get_user_model()

class SimpleCustomersFormCreate(forms.ModelForm):
    FastPass = forms.BooleanField(required=False)

    class Meta:
        model = Customers
        fields = ['groupingProject', 'nameProject', 'nameCustomer', 'URLCustomer',
                  'notes', 'OutOfScopeString', 'urlScope', 'outofscope', 'domainScope', 'Ipv4Scope', 'Ipv6Scope', 
                  'skipScan', 'FastPass']

class create_egocontrol(forms.ModelForm):
    class Meta:
        model = EgoControl
        fields = [
            'ScanProjectByID', 'ScanGroupingProject', 'ScanProjectByName', 
            'OutOfScope', 'chunk_size', 'Port', 'HostAddress', 'Scan_IPV_Scope_bool', 
            'Scan_DomainName_Scope_bool', 'BruteForce', 'BruteForce_WL', 'scan_records_censys', 
            'crtshSearch_bool', 'Update_RecordsCheck', 'LoopCustomersBool', 
            'Completed', 'Gnaw_Completed', 'failed', 'scan_objects'
        ]
        widgets = {
            'ScanProjectByID': forms.TextInput(attrs={'class': 'form-control', 'style': 'width: 350px;'}),
            'ScanGroupingProject': forms.TextInput(attrs={'class': 'form-control', 'style': 'width: 250px;'}),
            'ScanProjectByName': forms.TextInput(attrs={'class': 'form-control', 'style': 'width: 250px;'}),
            'OutOfScope': forms.TextInput(attrs={'class': 'form-control', 'style': 'width: 450px;'}),
            'chunk_size': forms.NumberInput(attrs={'class': 'form-control', 'style': 'width: 80px;'}),
            #'CoolDown': forms.NumberInput(attrs={'class': 'form-control', 'style': 'width: 80px;'}),
            #'CoolDown_Between_Queries': forms.NumberInput(attrs={'class': 'form-control', 'style': 'width: 120px;'}),
            'Port': forms.NumberInput(attrs={'class': 'form-control', 'style': 'width: 120px;'}),
            'HostAddress': forms.TextInput(attrs={'class': 'form-control', 'style': 'width: 750px;'}),
            #'passiveAttack': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
            #'agressiveAttack': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
            #'portscan_bool': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
            #'versionscan_bool': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
            #'Scan_Scope_bool': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
            'Scan_IPV_Scope_bool': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
            'Scan_DomainName_Scope_bool': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
            #'scriptscan_bool': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
            'BruteForce': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
            'BruteForce_WL': forms.Textarea(attrs={'class': 'form-control', 'style': 'width: 750px;'}),
            'scan_records_censys': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
            'crtshSearch_bool': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
            'Update_RecordsCheck': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
            'LoopCustomersBool': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
            'Completed': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
            'Gnaw_Completed': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
            'failed': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
            'scan_objects': forms.Textarea(attrs={'class': 'form-control', 'style': 'width: 750px;'}),
        }
    def __init__(self, *args, **kwargs):
        super(create_egocontrol, self).__init__(*args, **kwargs)
        self.fields['ScanProjectByID'].initial = 'Unique Identifier'
        #self.fields['internal_scanner'].initial = False
        self.fields['ScanGroupingProject'].initial = 'Group Name'
        self.fields['ScanProjectByName'].initial = 'Project Name'
        self.fields['OutOfScope'].initial = ''
        self.fields['chunk_size'].initial = 12
        #self.fields['CoolDown'].initial = 2
        #self.fields['CoolDown_Between_Queries'].initial = 6
        self.fields['Port'].initial = 9000
        self.fields['HostAddress'].initial = 'http://127.0.0.1'
        #self.fields['passiveAttack'].initial = False
        #self.fields['agressiveAttack'].initial = True
        #self.fields['portscan_bool'].initial = True
        #self.fields['versionscan_bool'].initial = True
        #self.fields['Scan_Scope_bool'].initial = True
        self.fields['Scan_IPV_Scope_bool'].initial = False
        self.fields['Scan_DomainName_Scope_bool'].initial = True
        #self.fields['scriptscan_bool'].initial = True
        self.fields['BruteForce'].initial = False
        self.fields['BruteForce_WL'].initial = list()
        self.fields['scan_records_censys'].initial = False
        self.fields['crtshSearch_bool'].initial = True
        self.fields['Update_RecordsCheck'].initial = False
        self.fields['LoopCustomersBool'].initial = False
        self.fields['Completed'].initial = False
        self.fields['Gnaw_Completed'].initial = False
        self.fields['failed'].initial = False
        self.fields['scan_objects'].initial = list()
        
class update_egocontrol(forms.ModelForm):
    class Meta:
        model = EgoControl
        fields = '__all__'
        
## widgets 

class DateInput(forms.DateInput):
    input_type = 'date'

## end widgets
class FoundVulnFormPK(forms.ModelForm):
    class Meta:
        model = FoundVuln
        fields = [
            'Submitted'
        ]
    def clean(self):
        cleaned_data = super().clean()
        known_secret_key = "known_value"
        if self.user.secret_key != known_secret_key:
            raise ValidationError("Invalid secret key.")
            
class VulnSubmittedForm(forms.Form):
    Submitted = forms.BooleanField(widget=forms.CheckboxInput, label="failed", required=False)
    
severity_CHOICES =(
    ("info", "info"),
    ("low", "low"),
    ("medium", "medium"),
    ("high", "high"),
    ("critical", "critical"),
    ("unknown", "unknown"),
)

class create_gnawcontrol(forms.ModelForm):
    class Meta:
        model = GnawControl
        fields = [
            'NucleiScan', 'Ipv_Scan', 'LoopCustomersBool', 'OutOfScope', 'ScanProjectByID', 
            'ScanGroupingProject', 'ScanProjectByName', 'Customer_chunk_size', 'Record_chunk_size', 
            'Global_Nuclei_CoolDown', 'Global_Nuclei_RateLimit', 'Port', 'HostAddress', 'severity', 
            'Gnaw_Completed', 'failed', 'scan_objects', 'claimed'
        ]
        widgets = {
            'NucleiScan': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
            'Ipv_Scan': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
            'LoopCustomersBool': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
            'OutOfScope': forms.TextInput(attrs={'class': 'form-control', 'style': 'width: 450px;'}),
            'ScanProjectByID': forms.TextInput(attrs={'class': 'form-control', 'style': 'width: 350px;'}),
            'ScanGroupingProject': forms.TextInput(attrs={'class': 'form-control', 'style': 'width: 250px;'}),
            'ScanProjectByName': forms.TextInput(attrs={'class': 'form-control', 'style': 'width: 250px;'}),
            'Customer_chunk_size': forms.NumberInput(attrs={'class': 'form-control', 'style': 'width: 80px;'}),
            'Record_chunk_size': forms.NumberInput(attrs={'class': 'form-control', 'style': 'width: 80px;'}),
            'Global_Nuclei_CoolDown': forms.NumberInput(attrs={'class': 'form-control', 'style': 'width: 80px;'}),
            'Global_Nuclei_RateLimit': forms.NumberInput(attrs={'class': 'form-control', 'style': 'width: 80px;'}),
            'Port': forms.NumberInput(attrs={'class': 'form-control', 'style': 'width: 120px;'}),
            'HostAddress': forms.TextInput(attrs={'class': 'form-control', 'style': 'width: 750px;'}),
            'severity': forms.TextInput(attrs={'class': 'form-control', 'style': 'width: 750px;'}),
            'Gnaw_Completed': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
            'failed': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
            'scan_objects': forms.Textarea(attrs={'class': 'form-control', 'style': 'width: 750px;'}),
            'claimed': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
        }
    def __init__(self, *args, **kwargs):
        super(create_gnawcontrol, self).__init__(*args, **kwargs)
        self.fields['NucleiScan'].initial = True
        self.fields['Ipv_Scan'].initial = False
        self.fields['Ipv_Scan'].initial = False
        self.fields['LoopCustomersBool'].initial = False       
        self.fields['Gnaw_Completed'].initial = False
        self.fields['failed'].initial = False

class customer_pk(forms.ModelForm):
    class Meta:
        model = Customers
        fields = [
            'groupingProject',
            'nameProject',
            'nameCustomer',
            'customDaysUntilNextScan',
            'toScanDate',
            'endToScanDate',
            'URLCustomer',
            'skipScan',
            'reconOnly',
            'passiveAttack',
            'agressiveAttack',
            'notes',
            'OutOfScopeString',
            'EgoReconScan',
            'lastEgoScan',
            'urlScope',
            'outofscope',
            'domainScope',
            'Ipv4Scope',
            'Ipv6Scope'
            ]

### MantisData create 
### MantisData create 
class MantisDataCreate(forms.ModelForm):

    class Meta:
        model = PythonMantis
        fields = [
            'name', 'vulnClass', 'author', 'severity', 'cvss_metrics', 'cvss_score', 'cwe_id', 
            'description', 'impact', 'proof_of_concept', 'remediation', 'references', 'pictures', 
            'Elevate_Vuln', 'searchPort', 'searchHeader', 'searchBody', 'searchNmap', 'callbackServer', 
            'callbackServerKey', 'request_method', 'payloads', 'headers', 'postData', 'ComplexPathPython', 
            'ComplexAttackPython', 'path', 'creds', 'pathDeveloper', 'rawRequest', 'SSL', 
            'timeout_betweenRequest', 'repeatnumb', 'redirect', 'matchers_status', 'matchers_headers', 
            'matchers_bodys', 'matchers_words', 'shodan_query', 'google_dork', 'tags', 'tcpversioning'
        ]

class create_mantisControl(forms.ModelForm):
    class Meta:
        model = PythonMantis
        fields = [
            'name', 'vulnClass', 'author', 'severity', 'cvss_metrics', 'cvss_score', 'cwe_id', 
            'description', 'impact', 'proof_of_concept', 'remediation', 'references', 'pictures', 
            'Elevate_Vuln', 'searchPort', 'searchHeader', 'searchBody', 'searchNmap', 'callbackServer', 
            'callbackServerKey', 'request_method', 'payloads', 'headers', 'postData', 'ComplexPathPython', 
            'ComplexAttackPython', 'path', 'creds', 'pathDeveloper', 'rawRequest', 'SSL', 
            'timeout_betweenRequest', 'repeatnumb', 'redirect', 'matchers_status', 'matchers_headers', 
            'matchers_bodys', 'matchers_words', 'shodan_query', 'google_dork', 'tags', 'tcpversioning'
        ]
        widgets = {
            'name': forms.TextInput(attrs={'class': 'form-control', 'style': 'width: 350px;'}),
            'vulnClass': forms.TextInput(attrs={'class': 'form-control', 'style': 'width: 250px;'}),
            'author': forms.TextInput(attrs={'class': 'form-control', 'style': 'width: 250px;'}),
            'severity': forms.Select(attrs={'class': 'form-control', 'style': 'width: 150px;'}),
            'cvss_metrics': forms.TextInput(attrs={'class': 'form-control', 'style': 'width: 250px;'}),
            'cvss_score': forms.TextInput(attrs={'class': 'form-control', 'style': 'width: 100px;'}),
            'cwe_id': forms.TextInput(attrs={'class': 'form-control', 'style': 'width: 250px;'}),
            'description': forms.Textarea(attrs={'class': 'form-control', 'style': 'width: 750px;'}),
            'impact': forms.Textarea(attrs={'class': 'form-control', 'style': 'width: 750px;'}),
            'proof_of_concept': forms.Textarea(attrs={'class': 'form-control', 'style': 'width: 750px;'}),
            'remediation': forms.Textarea(attrs={'class': 'form-control', 'style': 'width: 750px;'}),
            'references': forms.Textarea(attrs={'class': 'form-control', 'style': 'width: 750px;'}),
            'pictures': forms.ClearableFileInput(attrs={'class': 'form-control', 'style': 'width: 750px;'}),
            'Elevate_Vuln': forms.TextInput(attrs={'class': 'form-control', 'style': 'width: 250px;'}),
            'searchPort': forms.TextInput(attrs={'class': 'form-control', 'style': 'width: 250px;'}),
            'searchHeader': forms.TextInput(attrs={'class': 'form-control', 'style': 'width: 250px;'}),
            'searchBody': forms.TextInput(attrs={'class': 'form-control', 'style': 'width: 250px;'}),
            'searchNmap': forms.TextInput(attrs={'class': 'form-control', 'style': 'width: 250px;'}),
            'callbackServer': forms.TextInput(attrs={'class': 'form-control', 'style': 'width: 750px;'}),
            'callbackServerKey': forms.TextInput(attrs={'class': 'form-control', 'style': 'width: 750px;'}),
            'request_method': forms.TextInput(attrs={'class': 'form-control', 'style': 'width: 100px;'}),
            'payloads': forms.Textarea(attrs={'class': 'form-control', 'style': 'width: 750px;'}),
            'headers': forms.Textarea(attrs={'class': 'form-control', 'style': 'width: 750px;'}),
            'postData': forms.Textarea(attrs={'class': 'form-control', 'style': 'width: 750px;'}),
            'ComplexPathPython': forms.Textarea(attrs={'class': 'form-control', 'style': 'width: 750px;'}),
            'ComplexAttackPython': forms.ClearableFileInput(attrs={'class': 'form-control', 'style': 'width: 750px;'}),
            'path': forms.Textarea(attrs={'class': 'form-control', 'style': 'width: 750px;'}),
            'creds': forms.Textarea(attrs={'class': 'form-control', 'style': 'width: 750px;'}),
            'pathDeveloper': forms.Textarea(attrs={'class': 'form-control', 'style': 'width: 750px;'}),
            'rawRequest': forms.Textarea(attrs={'class': 'form-control', 'style': 'width: 750px;'}),
            'SSL': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
            'timeout_betweenRequest': forms.TextInput(attrs={'class': 'form-control', 'style': 'width: 100px;'}),
            'repeatnumb': forms.TextInput(attrs={'class': 'form-control', 'style': 'width: 100px;'}),
            'redirect': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
            'matchers_status': forms.Textarea(attrs={'class': 'form-control', 'style': 'width: 750px;'}),
            'matchers_headers': forms.Textarea(attrs={'class': 'form-control', 'style': 'width: 750px;'}),
            'matchers_bodys': forms.Textarea(attrs={'class': 'form-control', 'style': 'width: 750px;'}),
            'matchers_words': forms.Textarea(attrs={'class': 'form-control', 'style': 'width: 750px;'}),
            'shodan_query': forms.Textarea(attrs={'class': 'form-control', 'style': 'width: 750px;'}),
            'google_dork': forms.Textarea(attrs={'class': 'form-control', 'style': 'width: 750px;'}),
            'tags': forms.Textarea(attrs={'class': 'form-control', 'style': 'width: 750px;'}),
            'tcpversioning': forms.Textarea(attrs={'class': 'form-control', 'style': 'width: 750px;'}),
        }


class WordListGroupFormCreate(forms.Form):
    groupName = forms.CharField( max_length=256 )
    type = forms.CharField( max_length=32 )
    description = forms.CharField(widget=forms.Textarea(attrs={"rows":"5"}), required=False, initial="It may seem dumb but add some context")
    count = forms.CharField( max_length=20, required=False)

class WordListGroupFormData(forms.ModelForm):
    class Meta:
        model = WordListGroup
        fields = (
            'groupName',
            'type',
            'description',
            'count'
            )


def validate_file_extension(value):
    if not value.name.endswith('.txt'):
        raise ValidationError("Only .txt files are allowed.")

class UploadFileForm(forms.Form):
    uploaded_file = forms.FileField(validators=[validate_file_extension])