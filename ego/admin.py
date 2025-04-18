from django.contrib import admin
from ego.models import * 
from ego.forms import *
from ego.serializers import *
# Register your models here.

admin.site.register(whois)
admin.site.register(FoundVulnDetails)
admin.site.register(Customers)
admin.site.register(Record)
admin.site.register(RequestMetaData)
admin.site.register(ThreatModeling)
admin.site.register(TldIndex)
admin.site.register(Nmap)
admin.site.register(GnawControl)
admin.site.register(EgoControl)
admin.site.register(MantisControls)
admin.site.register(FindingMatrix)
admin.site.register(apiproviders)
admin.site.register(api)
admin.site.register(Credential)
admin.site.register(Certificate)
admin.site.register(DNSQuery)
admin.site.register(DNSAuthority)
admin.site.register(Template)
admin.site.register(External_Internal_Checklist)
admin.site.register(WordListGroup)
admin.site.register(WordList)
admin.site.register(Nuclei)
admin.site.register(FoundVuln)
admin.site.register(PythonMantis)
admin.site.register(UserProfile)
admin.site.register(TenantInvitation)
admin.site.register(Tenant)