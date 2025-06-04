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
        fields = ['user', 'email', 'phone_number']

class AdminUserProfileForm(forms.ModelForm):
    class Meta:
        model = UserProfile
        fields = ['email', 'phone_number', 'FastPassHost', 'FastPassPort']

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

User = get_user_model()

class CustomUserCreationForm(UserCreationForm):
    secret_code = forms.CharField(max_length=100, required=False)  # Pseudo field

    class Meta:
        model = User
        fields = ['username', 'email', 'password1', 'password2']

import random

def generate_unique_pokemon_name():
    POKEMON_NAMES = [
        "Bulbasaur", "Ivysaur", "Venusaur", "Charmander", "Charmeleon", "Charizard",
        "Squirtle", "Wartortle", "Blastoise", "Caterpie", "Metapod", "Butterfree",
        "Weedle", "Kakuna", "Beedrill", "Pidgey", "Pidgeotto", "Pidgeot",
        "Rattata", "Raticate", "Spearow", "Fearow", "Ekans", "Arbok",
        "Pikachu", "Raichu", "Sandshrew", "Sandslash", "Nidoran♀", "Nidorina",
        "Nidoqueen", "Nidoran♂", "Nidorino", "Nidoking", "Clefairy", "Clefable",
        "Vulpix", "Ninetales", "Jigglypuff", "Wigglytuff", "Zubat", "Golbat",
        "Oddish", "Gloom", "Vileplume", "Paras", "Parasect", "Venonat",
        "Venomoth", "Diglett", "Dugtrio", "Meowth", "Persian", "Psyduck",
        "Golduck", "Mankey", "Primeape", "Growlithe", "Arcanine", "Poliwag",
        "Poliwhirl", "Poliwrath", "Abra", "Kadabra", "Alakazam", "Machop",
        "Machoke", "Machamp", "Bellsprout", "Weepinbell", "Victreebel", "Tentacool",
        "Tentacruel", "Geodude", "Graveler", "Golem", "Ponyta", "Rapidash",
        "Slowpoke", "Slowbro", "Magnemite", "Magneton", "Farfetch’d", "Doduo",
        "Dodrio", "Seel", "Dewgong", "Grimer", "Muk", "Shellder",
        "Cloyster", "Gastly", "Haunter", "Gengar", "Onix", "Drowzee",
        "Hypno", "Krabby", "Kingler", "Voltorb", "Electrode", "Exeggcute",
        "Exeggutor", "Cubone", "Marowak", "Hitmonlee", "Hitmonchan", "Lickitung",
        "Koffing", "Weezing", "Rhyhorn", "Rhydon", "Chansey", "Tangela",
        "Kangaskhan", "Horsea", "Seadra", "Goldeen", "Seaking", "Staryu",
        "Starmie", "Mr. Mime", "Scyther", "Jynx", "Electabuzz", "Magmar",
        "Pinsir", "Tauros", "Magikarp", "Gyarados", "Lapras", "Ditto",
        "Eevee", "Vaporeon", "Jolteon", "Flareon", "Porygon", "Omanyte",
        "Omastar", "Kabuto", "Kabutops", "Aerodactyl", "Snorlax", "Articuno",
        "Zapdos", "Moltres", "Dratini", "Dragonair", "Dragonite", "Mewtwo",
        "Mew", "Chikorita", "Bayleef", "Meganium", "Cyndaquil", "Quilava", "Typhlosion",
       "Totodile", "Croconaw", "Feraligatr", "Sentret", "Furret", "Hoothoot", "Noctowl", 
       "Ledyba", "Ledian", "Spinarak", "Ariados", "Crobat", "Chinchou", "Lanturn", "Pichu", 
       "Cleffa", "Igglybuff", "Togepi", "Togetic", "Natu", "Xatu", "Mareep", "Flaaffy", 
       "Ampharos", "Bellossom", "Marill", "Azumarill", "Sudowoodo", "Politoed", "Hoppip", 
       "Skiploom", "Jumpluff", "Aipom", "Sunkern", "Sunflora", "Yanma", "Wooper", "Quagsire", 
       "Espeon", "Umbreon", "Murkrow", "Slowking", "Misdreavus", "Unown", "Wobbuffet", 
       "Girafarig", "Pineco", "Forretress", "Dunsparce", "Gligar", "Steelix", "Snubbull", 
       "Granbull", "Qwilfish", "Scizor", "Shuckle", "Heracross", "Sneasel", "Teddiursa", "Ursaring", 
       "Slugma", "Magcargo", "Swinub", "Piloswine", "Corsola", "Remoraid", "Octillery", "Delibird", 
       "Mantine", "Skarmory", "Houndour", "Houndoom", "Kingdra", "Phanpy", "Donphan", "Porygon2", 
       "Stantler", "Smeargle", "Tyrogue", "Hitmontop", "Smoochum", "Elekid", "Magby", "Miltank", 
       "Blissey", "Raikou", "Entei", "Suicune", "Larvitar", "Pupitar", "Tyranitar", "Lugia", "Ho-Oh",
      "Celebi","Turtwig", "Grotle", "Torterra", "Chimchar", "Monferno", "Infernape", "Piplup", "Prinplup", "Empoleon", "Starly", "Staravia", "Staraptor", "Bidoof",
     "Bibarel", "Kricketot", "Kricketune", "Shinx", "Luxio", "Luxray", "Budew", "Roserade",
     "Cranidos", "Rampardos", "Shieldon", "Bastiodon", "Burmy", "Wormadam", "Mothim", "Combee", "Vespiquen", "Pachirisu", "Buizel", "Floatzel", "Cherubi",
    "Cherrim", "Shellos", "Gastrodon", "Ambipom", "Drifloon", "Drifblim", "Buneary", "Lopunny", "Mismagius", "Honchkrow", "Glameow", "Purugly", "Chingling",
   "Stunky", "Skuntank", "Bronzor", "Bronzong", "Bonsly", "Mime Jr.", "Happiny", "Chatot", "Spiritomb", "Gible", "Gabite", "Garchomp", "Munchlax", "Riolu", "Lucario",
  "Hippopotas", "Hippowdon", "Skorupi", "Drapion", "Croagunk", "Toxicroak", "Carnivine", "Finneon", "Lumineon", "Mantyke", "Snover", "Abomasnow", "Weavile", "Magnezone", 
  "Lickilicky", "Rhyperior", "Tangrowth", "Electivire", "Magmortar", "Togekiss", "Yanmega", "Leafeon", "Glaceon", "Gliscor", "Mamoswine", "Porygon-Z", "Gallade", 
  "Probopass", "Dusknoir", "Froslass", "Rotom", "Uxie", "Mesprit", "Azelf", "Dialga", "Palkia", "Heatran", "Regigigas", "Giratina", "Cresselia", "Phione", "Manaphy",
 "Darkrai", "Shaymin", "Arceus"
    ]

    
    # Get all existing project names from the Customers model
    existing_names = set(Customers.objects.values_list('nameProject', flat=True))
    
    # Filter Pokémon names to exclude those already in use
    available_names = [name for name in POKEMON_NAMES if name not in existing_names]
    
    if not available_names:
        raise ValueError("No unique Pokémon names available.")
    
    # Randomly select a name from the available names
    return random.choice(available_names)

class SimpleCustomersFormCreate(forms.ModelForm):
    FastPass = forms.BooleanField(required=False)

    class Meta:
        model = Customers
        fields = [
            'groupingProject', 'nameProject', 'nameCustomer', 'URLCustomer',
            'notes', 'OutOfScopeString', 'urlScope', 'outofscope', 'domainScope',
            'Ipv4Scope', 'Ipv6Scope', 'skipScan', 'FastPass'
        ]
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)


        generated_name = generate_unique_pokemon_name()
        self.fields['nameProject'].initial = generated_name
        self.instance.nameProject = generated_name


class SimplePKCustomersFormCreate(forms.ModelForm):
    FastPass = forms.BooleanField(required=False)

    class Meta:
        model = Customers
        fields = [
            'groupingProject', 'nameProject', 'nameCustomer', 'URLCustomer',
            'notes', 'OutOfScopeString', 'urlScope', 'outofscope', 'domainScope',
            'Ipv4Scope', 'Ipv6Scope', 'skipScan', 'FastPass'
        ]


class create_egocontrol(forms.ModelForm):
    ScanProjectByID = forms.ModelChoiceField(
        queryset=EgoControl.objects.all(),
        widget=forms.Select(attrs={'class': 'form-control', 'style': 'width: 350px;'}),
        empty_label="Select a Scan Project ID"
    )
    ScanGroupingProject = forms.ModelChoiceField(
        queryset=EgoControl.objects.values_list('ScanGroupingProject', flat=True).distinct(),
        widget=forms.Select(attrs={'class': 'form-control', 'style': 'width: 250px;'}),
        empty_label="Select a Grouping Project"
    )
    ScanProjectByName = forms.ModelChoiceField(
        queryset=EgoControl.objects.values_list('ScanProjectByName', flat=True).distinct(),
        widget=forms.Select(attrs={'class': 'form-control', 'style': 'width: 250px;'}),
        empty_label="Select a Project Name"
    )

    class Meta:
        model = EgoControl
        fields = [
            'ScanProjectByID', 'ScanGroupingProject', 'ScanProjectByName', 
            'OutOfScope', 'chunk_size', 'Port', 'HostAddress', 'Scan_IPV_Scope_bool', 
            'Scan_DomainName_Scope_bool', 'BruteForce', 'BruteForce_WL', 'scan_records_censys', 
            'crtshSearch_bool', 'Update_RecordsCheck', 'LoopCustomersBool', 
            'Completed', 'claimed', 'failed', 'scan_objects'
        ]
        widgets = {
            'OutOfScope': forms.TextInput(attrs={'class': 'form-control', 'style': 'width: 450px;'}),
            'chunk_size': forms.NumberInput(attrs={'class': 'form-control', 'style': 'width: 80px;'}),
            'Port': forms.NumberInput(attrs={'class': 'form-control', 'style': 'width: 120px;'}),
            'HostAddress': forms.TextInput(attrs={'class': 'form-control', 'style': 'width: 750px;'}),
            'Scan_IPV_Scope_bool': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
            'Scan_DomainName_Scope_bool': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
            'BruteForce': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
            'scan_records_censys': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
            'crtshSearch_bool': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
            'Update_RecordsCheck': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
            'LoopCustomersBool': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
            'Completed': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
            'claimed': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
            'failed': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
            'scan_objects': forms.Textarea(attrs={'class': 'form-control', 'style': 'width: 750px;'}),
        }

    def __init__(self, *args, **kwargs):
        super(create_egocontrol, self).__init__(*args, **kwargs)
        self.fields['OutOfScope'].initial = ''
        self.fields['chunk_size'].initial = 12
        self.fields['Port'].initial = 9000
        self.fields['HostAddress'].initial = 'http://127.0.0.1'
        self.fields['Scan_IPV_Scope_bool'].initial = False
        self.fields['Scan_DomainName_Scope_bool'].initial = True
        self.fields['BruteForce'].initial = False
        self.fields['scan_records_censys'].initial = False
        self.fields['crtshSearch_bool'].initial = True
        self.fields['Update_RecordsCheck'].initial = False
        self.fields['LoopCustomersBool'].initial = False
        self.fields['Completed'].initial = False
        self.fields['claimed'].initial = False
        self.fields['failed'].initial = False
        self.fields['scan_objects'].initial = list()

class PKcreate_egocontrol(forms.ModelForm):
    class Meta:
        model = EgoControl
        fields = [
            'ScanProjectByID', 'ScanGroupingProject', 'ScanProjectByName', 
            'OutOfScope', 'chunk_size', 'Port', 'HostAddress', 'Scan_IPV_Scope_bool', 
            'Scan_DomainName_Scope_bool', 'BruteForce', 'BruteForce_WL', 'scan_records_censys', 
            'crtshSearch_bool', 'Update_RecordsCheck', 'LoopCustomersBool', 
            'Completed', 'claimed', 'failed', 'scan_objects'
        ]
        widgets = {
            'OutOfScope': forms.TextInput(attrs={'class': 'form-control', 'style': 'width: 450px;'}),
            'chunk_size': forms.NumberInput(attrs={'class': 'form-control', 'style': 'width: 80px;'}),
            'Port': forms.NumberInput(attrs={'class': 'form-control', 'style': 'width: 120px;'}),
            'HostAddress': forms.TextInput(attrs={'class': 'form-control', 'style': 'width: 750px;'}),
            'Scan_IPV_Scope_bool': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
            'Scan_DomainName_Scope_bool': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
            'BruteForce': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
            'scan_records_censys': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
            'crtshSearch_bool': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
            'Update_RecordsCheck': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
            'LoopCustomersBool': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
            'Completed': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
            'claimed': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
            'failed': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
            'scan_objects': forms.Textarea(attrs={'class': 'form-control', 'style': 'width: 750px;'}),
        }

    def __init__(self, *args, **kwargs):
        super(PKcreate_egocontrol, self).__init__(*args, **kwargs)  # Corrected the class name
        self.fields['OutOfScope'].initial = ''
        self.fields['chunk_size'].initial = 12
        self.fields['Port'].initial = 9000
        self.fields['HostAddress'].initial = 'http://127.0.0.1'
        self.fields['Scan_IPV_Scope_bool'].initial = False
        self.fields['Scan_DomainName_Scope_bool'].initial = True
        self.fields['BruteForce'].initial = False
        self.fields['scan_records_censys'].initial = False
        self.fields['crtshSearch_bool'].initial = True
        self.fields['Update_RecordsCheck'].initial = False
        self.fields['LoopCustomersBool'].initial = False
        self.fields['Completed'].initial = False
        self.fields['claimed'].initial = False
        self.fields['failed'].initial = False
        self.fields['scan_objects'].initial = list()

from django.forms import ModelForm, MultipleChoiceField, CheckboxSelectMultiple
from django.db.models import F

class EgoControlUpdateForm(forms.ModelForm):
    # Pseudo field for listing all EgoControl objects
    targets = MultipleChoiceField(
        choices=[],  # Choices will be populated dynamically
        widget=CheckboxSelectMultiple(attrs={'class': 'form-check-input'}),
        required=False
    )

    class Meta:
        model = EgoControl
        fields = [
            'HostAddress', 'Port', 'BruteForce', 'BruteForce_WL',
            'Update_RecordsCheck', 'LoopCustomersBool', 'Completed',
            'claimed', 'failed', 'scan_records_censys', 'crtshSearch_bool',
        ]
        widgets = {
            'Port': forms.NumberInput(attrs={'class': 'form-control', 'style': 'width: 120px;'}),
            'HostAddress': forms.TextInput(attrs={'class': 'form-control', 'style': 'width: 750px;'}),
            'BruteForce': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
            'scan_records_censys': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
            'crtshSearch_bool': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
            'Update_RecordsCheck': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
            'LoopCustomersBool': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
            'Completed': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
            'claimed': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
            'failed': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Set all checkbox fields to unchecked by default
        for field_name in self.fields:
            if isinstance(self.fields[field_name].widget, forms.CheckboxInput):
                self.fields[field_name].initial = False

        # Dynamically populate the choices for the `targets` field with ScanProjectByName
        self.fields['targets'].choices = [
            (obj.id, obj.ScanProjectByName) for obj in EgoControl.objects.all() if obj.ScanProjectByName
        ]

def update_egocontrol_instances(form_data):
    """
    Updates all EgoControl model instances with the data from the form.
    """
    if not form_data.is_valid():
        raise ValueError("Invalid form data")

    # Extract cleaned data from the form
    cleaned_data = form_data.cleaned_data

    # Enumerate and update all EgoControl instances
    for instance in EgoControl.objects.all():
        for field, value in cleaned_data.items():
            setattr(instance, field, value)
        instance.save()


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

class bulk_create_gnawcontrol(forms.ModelForm):
    class Meta:
        model = GnawControl
        fields = [
            ]


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
class MantisDataCreate(forms.ModelForm):
    vulnCard_id = forms.ModelChoiceField(queryset=VulnCard.objects.all(), to_field_name="name")

    class Meta:
        model = MantisControls
        fields = [
            'Ipv_Scan', 'LoopCustomersBool', 'OutOfScope', 'ScanProjectByID', 
            'ScanGroupingProject', 'ScanProjectByName', 'Customer_chunk_size', 'Record_chunk_size', 
            'Global_CoolDown', 'Global_RateLimit', 'Port', 'HostAddress', 'severity', 
            'Elavate', 'Mantis_Completed', 'failed', 'scan_objects'
        ]

class VulnCardForm(forms.ModelForm):
    class Meta:
        model = VulnCard
        fields = [
            'name', 'vulnClass', 'author', 'severity', 'cvss_metrics', 'cvss_score', 
            'description', 'proof_of_concept', 'remediation', 'references', 'pictures'
        ]
        widgets = {
            'name': forms.TextInput(attrs={'class': 'form-control', 'style': 'width: 350px;'}),
            'vulnClass': forms.TextInput(attrs={'class': 'form-control', 'style': 'width: 350px;'}),
            'author': forms.TextInput(attrs={'class': 'form-control', 'style': 'width: 350px;'}),
            'severity': forms.Select(attrs={'class': 'form-control', 'style': 'width: 350px;'}),
            'cvss_metrics': forms.TextInput(attrs={'class': 'form-control', 'style': 'width: 350px;', 'title': 'cvss vector'}),
            'cvss_score': forms.TextInput(attrs={'class': 'form-control', 'style': 'width: 350px;'}),
            'description': forms.Textarea(attrs={'class': 'form-control', 'style': 'width: 750px;'}),
            'proof_of_concept': forms.Textarea(attrs={'class': 'form-control', 'style': 'width: 750px;'}),
            'remediation': forms.Textarea(attrs={'class': 'form-control', 'style': 'width: 750px;'}),
            'references': forms.URLInput(attrs={'class': 'form-control', 'style': 'width: 750px;'}),
            'pictures': forms.ClearableFileInput(attrs={'class': 'form-control', 'style': 'width: 750px;'}),
        }

    cvss_metrics = forms.CharField(required=False, widget=forms.TextInput(attrs={'class': 'form-control', 'style': 'width: 350px;', 'title': 'cvss vector'}))
    cvss_score = forms.CharField(required=False, widget=forms.TextInput(attrs={'class': 'form-control', 'style': 'width: 350px;'}))
    proof_of_concept = forms.CharField(required=False, widget=forms.Textarea(attrs={'class': 'form-control', 'style': 'width: 750px;'}))
    remediation = forms.CharField(required=False, widget=forms.Textarea(attrs={'class': 'form-control', 'style': 'width: 750px;'}))
    references = forms.URLField(required=False, widget=forms.URLInput(attrs={'class': 'form-control', 'style': 'width: 750px;'}))
    pictures = forms.ImageField(required=False, widget=forms.ClearableFileInput(attrs={'class': 'form-control', 'style': 'width: 750px;'}))


class VulnCardForm(forms.ModelForm):
    class Meta:
        model = VulnCard
        fields = [
            'name', 'vulnClass', 'author', 'severity', 'cvss_metrics', 'cvss_score', 
            'cwe_id', 'description', 'impact', 'proof_of_concept', 'remediation', 
            'references', 'pictures'
        ]
        widgets = {
            'name': forms.TextInput(attrs={'class': 'form-control', 'style': 'width: 350px;'}),
            'vulnClass': forms.TextInput(attrs={'class': 'form-control', 'style': 'width: 350px;'}),
            'author': forms.TextInput(attrs={'class': 'form-control', 'style': 'width: 350px;'}),
            'severity': forms.Select(attrs={'class': 'form-control', 'style': 'width: 350px;'}),
            'cvss_metrics': forms.TextInput(attrs={'class': 'form-control', 'style': 'width: 350px;'}),
            'cvss_score': forms.TextInput(attrs={'class': 'form-control', 'style': 'width: 350px;'}),
            'cwe_id': forms.TextInput(attrs={'class': 'form-control', 'style': 'width: 350px;'}),
            'description': forms.Textarea(attrs={'class': 'form-control', 'style': 'width: 750px;'}),
            'impact': forms.Textarea(attrs={'class': 'form-control', 'style': 'width: 750px;'}),
            'proof_of_concept': forms.Textarea(attrs={'class': 'form-control', 'style': 'width: 750px;'}),
            'reme+diation': forms.Textarea(attrs={'class': 'form-control', 'style': 'width: 750px;'}),
            'references': forms.URLInput(attrs={'class': 'form-control', 'style': 'width: 750px;'}),
            'pictures': forms.ClearableFileInput(attrs={'class': 'form-control', 'style': 'width: 750px;'}),
        }

class PythonMantisForm(forms.ModelForm):
    class Meta:
        model = PythonMantis
        fields = [
            'vulnCard_id',
            'Elevate_Vuln',
            'name',
            'searchPort',
            'searchHeader',
            'searchBody',
            'searchNmap',
            'callbackServer',
            'callbackServerKey',
            'request_method',
            'payloads',
            'headers',
            'postData',
            'ComplexPathPython',
            'ComplexAttackPython',
            'path',
            'creds',
            'pathDeveloper',
            'rawRequest',
            'SSL',
            'timeout_betweenRequest',
            'repeatnumb',
            'redirect',
            'matchers_status',
            'matchers_headers',
            'matchers_bodys',
            'matchers_words',
            'shodan_query',
            'google_dork',
            'tags',
            'tcpversioning'
        ]
        widgets = {
            'vulnCard_id': forms.Select(),
            'Elevate_Vuln': forms.TextInput(attrs={'class': 'form-control'}),
            'name': forms.TextInput(attrs={'class': 'form-control'}),
            'searchPort': forms.TextInput(attrs={'class': 'form-control'}),
            'searchHeader': forms.TextInput(attrs={'class': 'form-control'}),
            'searchBody': forms.TextInput(attrs={'class': 'form-control'}),
            'searchNmap': forms.TextInput(attrs={'class': 'form-control'}),
            'callbackServer': forms.URLInput(attrs={'class': 'form-control'}),
            'callbackServerKey': forms.TextInput(attrs={'class': 'form-control'}),
            'request_method': forms.TextInput(attrs={'class': 'form-control'}),
            'payloads': forms.Textarea(attrs={'class': 'form-control'}),
            'headers': forms.Textarea(attrs={'class': 'form-control'}),
            'postData': forms.Textarea(attrs={'class': 'form-control'}),
            'ComplexPathPython': forms.Textarea(attrs={'class': 'form-control'}),
            'ComplexAttackPython': forms.FileInput(attrs={'class': 'form-control'}),
            'path': forms.TextInput(attrs={'class': 'form-control'}),
            'creds': forms.TextInput(attrs={'class': 'form-control'}),
            'pathDeveloper': forms.Textarea(attrs={'class': 'form-control'}),
            'rawRequest': forms.Textarea(attrs={'class': 'form-control'}),
            'SSL': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
            'timeout_betweenRequest': forms.TextInput(attrs={'class': 'form-control'}),
            'repeatnumb': forms.TextInput(attrs={'class': 'form-control'}),
            'redirect': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
            'matchers_status': forms.TextInput(attrs={'class': 'form-control'}),
            'matchers_headers': forms.TextInput(attrs={'class': 'form-control'}),
            'matchers_bodys': forms.TextInput(attrs={'class': 'form-control'}),
            'matchers_words': forms.TextInput(attrs={'class': 'form-control'}),
            'shodan_query': forms.TextInput(attrs={'class': 'form-control'}),
            'google_dork': forms.Textarea(attrs={'class': 'form-control'}),
            'tags': forms.TextInput(attrs={'class': 'form-control'}),
            'tcpversioning': forms.TextInput(attrs={'class': 'form-control'}),
        }
    def __init__(self, *args, **kwargs):
        super(PythonMantisForm, self).__init__(*args, **kwargs)
        self.fields['vulnCard_id'].queryset = VulnCard.objects.all()
        self.fields['vulnCard_id'].label_from_instance = self.label_from_instance

    def label_from_instance(self, obj):
        #return f"{obj.id} - {obj.name} - {obj.date}"
        return f"{obj.id} - {obj.name}"

class create_mantisControl(forms.ModelForm):
    class Meta:
        model = MantisControls
        fields = [
            'NucleiScan', 'Ipv_Scan', 'LoopCustomersBool', 'OutOfScope', 'ScanProjectByID', 
            'ScanGroupingProject', 'ScanProjectByName', 'Customer_chunk_size', 'Record_chunk_size', 
            'Global_CoolDown', 'Global_RateLimit', 'Port', 'HostAddress', 'severity', 
            'Elavate', 'Mantis_Completed', 'failed', 'scan_objects'
        ]
        widgets = {
            'NucleiScan': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
            'Ipv_Scan': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
            'LoopCustomersBool': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
            'OutOfScope': forms.TextInput(attrs={'class': 'form-control', 'style': 'width: 450px;'}),
            'ScanProjectByID': forms.TextInput(attrs={'class': 'form-control', 'style': 'width: 350px;'}),
            'ScanGroupingProject': forms.TextInput(attrs={'class': 'form-control', 'style': 'width: 250px;'}),
            'ScanProjectByName': forms.TextInput(attrs={'class': 'form-control', 'style': 'width: 250px;'}) ,
            'Customer_chunk_size': forms.NumberInput(attrs={'class': 'form-control', 'style': 'width: 80px;'}),
            'Record_chunk_size': forms.NumberInput(attrs={'class': 'form-control', 'style': 'width: 80px;'}),
            'Global_CoolDown': forms.NumberInput(attrs={'class': 'form-control', 'style': 'width: 80px;'}),
            'Global_RateLimit': forms.NumberInput(attrs={'class': 'form-control', 'style': 'width: 80px;'}),
            'Port': forms.NumberInput(attrs={'class': 'form-control', 'style': 'width: 120px;'}),
            'HostAddress': forms.TextInput(attrs={'class': 'form-control', 'style': 'width: 750px;'}),
            'severity': forms.TextInput(attrs={'class': 'form-control', 'style': 'width: 750px;'}),
            'Elavate': forms.TextInput(attrs={'class': 'form-control', 'style': 'width: 750px;'}),
            'Mantis_Completed': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
            'failed': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
            'scan_objects': forms.Textarea(attrs={'class': 'form-control', 'style': 'width: 750px;'}),
        }

class WordListGroupFormCreate(forms.Form):
    groupName = forms.CharField( max_length=256 )
    type = forms.ChoiceField(choices=[('DNS', 'DNS'), ('TLD','TLD'), ('PATHS', 'Paths'),
        ('OTHER', 'Other')])  # Replace with your actual choices
    description = forms.CharField(widget=forms.Textarea(attrs={"rows":"5"}), required=False, initial="It may seem dumb but add some context")

class WordListGroupFormData(forms.ModelForm):
    class Meta:
        model = WordListGroup
        fields = (
            'groupName',
            'type',
            'description',

            )


def validate_file_extension(value):
    if not value.name.endswith('.txt'):
        raise ValidationError("Only .txt files are allowed.")

class UploadFileForm(forms.Form):
    uploaded_file = forms.FileField(validators=[validate_file_extension])