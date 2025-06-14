import codecs
import json
import re
import requests
import time
import uuid
from collections import deque
from datetime import datetime, timedelta
from statistics import mode
from django.contrib import messages
from django.contrib.auth import logout
from django.core.paginator import EmptyPage
import folium
import fuzzywuzzy
import numpy as np
import pandas as pd
import pycountry
import tldextract
from django import VERSION
from .token_generator import invitation_token_generator
from django.conf import settings
from django.contrib.auth import authenticate, login, get_user_model
from django.contrib.auth.decorators import login_required, permission_required
from django.contrib.auth.forms import AuthenticationForm, UserCreationForm, PasswordResetForm, SetPasswordForm
from django.contrib.auth.models import ContentType, Group, User
from django.contrib.auth.views import PasswordResetView, PasswordResetDoneView, PasswordResetConfirmView, PasswordResetCompleteView
from django.contrib.auth.tokens import default_token_generator
from django.contrib.sites.shortcuts import get_current_site
from django.core.files import File
from django.core.files.storage import FileSystemStorage
from django.core.mail import send_mail
from django.core.paginator import Paginator
from django.db import transaction
from django.db.models import Q, Count, Sum
from django.http import HttpResponse, HttpResponseForbidden, HttpResponseServerError, HttpResponseRedirect, JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.template import loader
from django.template.loader import render_to_string
from django.template.response import TemplateResponse
from django.urls import reverse, reverse_lazy
from django.utils.decorators import method_decorator
from django.utils.encoding import force_bytes, force_str
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.views import View, generic
from django.views.decorators.csrf import csrf_exempt
from django_otp.plugins.otp_static.models import StaticDevice as PhoneDevice
from django_otp.plugins.otp_totp.models import TOTPDevice
from ego.authentication import *
from ego.forms import *
from ego.models import *
from ego.serializers import *
from ego.services import *
from fuzzywuzzy import fuzz, process
from geopy.geocoders import Nominatim
from rest_framework.authentication import TokenAuthentication
from rest_framework.authtoken.models import Token
from rest_framework.decorators import api_view, permission_classes
from rest_framework.exceptions import AuthenticationFailed
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.status import HTTP_200_OK, HTTP_400_BAD_REQUEST, HTTP_404_NOT_FOUND
from rest_framework.views import APIView
from twilio.twiml.messaging_response import MessagingResponse
from .mixins import RoleRequiredMixin
from collections import Counter

class UserProfilePasswordResetForm(PasswordResetForm):
    def get_users(self, email):
        """Return a User object for the given email."""
        user_profiles = UserProfile.objects.filter(email__iexact=email, user__is_active=True)
        return (user_profile.user for user_profile in user_profiles)

class UserProfilePasswordResetView(PasswordResetView):
    form_class = UserProfilePasswordResetForm
    success_url = reverse_lazy('password_reset_done')

    def form_valid(self, form):
        opts = {
            'use_https': self.request.is_secure(),
            'token_generator': default_token_generator,
            'from_email': self.from_email,
            'email_template_name': self.email_template_name,
            'subject_template_name': self.subject_template_name,
            'request': self.request,
            'html_email_template_name': self.html_email_template_name,
            'extra_email_context': self.extra_email_context,
        }
        form.save(**opts)
        return super().form_valid(form)

class UserProfilePasswordResetDoneView(PasswordResetDoneView):
    template_name = 'registration/password_reset_done.html'

class UserProfilePasswordResetConfirmView(PasswordResetConfirmView):
    template_name = 'registration/password_reset_confirm.html'
    form_class = SetPasswordForm

    def form_valid(self, form):
        form.save()
        return super().form_valid(form)

class UserProfilePasswordResetCompleteView(PasswordResetCompleteView):
    template_name = 'registration/password_reset_complete.html'

from django.contrib.auth.decorators import login_required
from django.utils.decorators import method_decorator

@method_decorator(login_required, name='dispatch')
class UserProfileView(View):
    def get(self, request, *args, **kwargs):
        if request.user.is_authenticated:
            user_profile = get_object_or_404(UserProfile, user=request.user)
            if user_profile.role == 'ADMIN':
                form = AdminUserProfileForm(instance=user_profile)
                tenant_invitation_form = TenantInvitationForm()
                # Query all users in the admin group
                admin_users = UserProfile.objects.filter(role='ADMIN')
                # Query all group invitations
                try:
                    tenant_invitations = TenantInvitation.objects.all()
                except TenantInvitation.DoesNotExist:
                    tenant_invitations = []
                fastpass_host = user_profile.FastPassHost
                fastpass_port = user_profile.FastPassPort
            else:
                form = UserProfileForm(instance=user_profile)
                tenant_invitation_form = TenantInvitationForm()
                admin_users = user_profile
                tenant_invitations = []
                fastpass_host = None
                fastpass_port = None
            return TemplateResponse(request, 'Account/account.html', {
                'form': form, 
                'tenant_invitation_form': tenant_invitation_form,
                'admin_users': admin_users,
                'tenant_invitations': tenant_invitations,
                'fastpass_host': fastpass_host,
                'fastpass_port': fastpass_port
            })
        else:
            return HttpResponseRedirect(reverse_lazy('user_profile'))

    @transaction.atomic
    def post(self, request, *args, **kwargs):
        user_profile = get_object_or_404(UserProfile, user=request.user)
        if user_profile.role == 'ADMIN':
            form = AdminUserProfileForm(request.POST, instance=user_profile)
        else:
            form = UserProfileForm(request.POST, instance=user_profile)
        
        if form.is_valid():
            form.save()
            messages.success(request, 'Profile updated successfully.')
            return HttpResponseRedirect(reverse_lazy('user_profile'))
        else:
            return TemplateResponse(request, 'Account/update_profile.html', {'form': form})

@transaction.atomic
def createUser(self, request, *args, **kwargs):
        
    user_profile = get_object_or_404(UserProfile, user=request.user)
    tenant_invitation_form = None
    if user_profile.role == 'ADMIN':
        tenant_invitation_form = TenantInvitationForm(request.POST)  # Assuming you have a TenantInvitationForm
        tenant_update_form = UserProfileForm(request.POST, instance=user_profile)
        if tenant_invitation_form.is_valid():
            tenant_invitation = tenant_invitation_form.save(commit=False)  # Don't save the TenantInvitation instance yet
            tenant_invitation.tenant = user_profile.tenant  # Set the tenant field to the tenant of the user who is creating the invitation
            tenant_invitation.save()  # Now save the TenantInvitation instance

            tenant = tenant_invitation.tenant  # assuming 'tenant' is a property of TenantInvitation

            # Get the current site (domain)
            current_site = get_current_site(request)
            # Generate a token with the user's information
            token = default_token_generator.make_token(user_profile.user)
            uid = urlsafe_base64_encode(force_bytes(tenant_invitation.pk))

            invitation_url = f"http://{current_site.domain}{reverse('invitation_view', kwargs={'uidb64': uid, 'token': token})}"

            # Create the email message
            message = render_to_string('invitation_email.html', {
                'user': user_profile.user,
                'domain': current_site.domain,
                'uid': uid,
                'token': token,
            })
            # Send the email
            send_mail(
                'You are invited to join our tenant',
                message,
                'from@example.com',
                [tenant_invitation.email],
                fail_silently=False,
            )
            return HttpResponseRedirect(reverse_lazy('user_profile'))
        elif tenant_update_form.is_valid():
            tenant_update_form.save()
            return HttpResponseRedirect(reverse_lazy('user_profile'))
        else:
            return TemplateResponse(request, 'Account/account.html', {'tenant_invitation_form': tenant_invitation_form})
    else:
        return HttpResponseForbidden("You are not authorized to perform this action.")


@login_required
def InvitationDeleteView(self, request, *args, **kwargs):
    print('aaaaaaaaaaaa')
    if request.method == 'POST':
        user_profile = UserProfile.objects.get(user=request.user)
        if user_profile.role not in ['WRITE', 'ADMIN']:
            return HttpResponseForbidden('You do not have permission to perform this action')
        else:
            try:
                invitation = TenantInvitation.objects.get(id=kwargs['pk'])
                invitation.delete()
                return HttpResponse(status=204)
            except TenantInvitation.DoesNotExist:
                return HttpResponse(status=404)

import base64
from io import BytesIO

def getQRCodeService(user_profile):
    # Generate the QR code image
    qr_code_image = generate_qr_code(user_profile)  # Replace with your QR code generation logic

    # Convert the image to a base64 string
    buffered = BytesIO()
    qr_code_image.save(buffered, format="JPEG")
    qr_code_base64 = base64.b64encode(buffered.getvalue()).decode('utf-8')

    return qr_code_base64

from django.views import generic
from django.http import JsonResponse
from django.template.response import TemplateResponse
from django.contrib.auth import login
from .models import UserProfile
from .services import getQRCodeService, getUserService

from .services import getQRCodeService, getUserService
from django.contrib.auth import login

class Set2FAView(generic.CreateView):
    """
    Get the image of the QR Code
    """
    def get(self, request, code):
        try:
            user_profile = UserProfile.objects.get(twofactorsetupcode=code)
        except UserProfile.DoesNotExist:
            return JsonResponse(
                {
                    "status": "fail", 
                    "message": "No user with the corresponding code exists"
                }, 
                status=404
            )

        try:
            qr_code_url = getQRCodeService(user_profile)  # Pass the UserProfile object
            if qr_code_url is None:
                # Handle the case where getQRCodeService returns None
                return JsonResponse(
                    {
                        "status": "fail", 
                        "message": "Failed to generate QR code"
                    }, 
                    status=500
                )
        except Exception as e:
            # Handle any exceptions that occur during QR code generation
            return JsonResponse(
                {
                    "status": "fail", 
                    "message": f"An error occurred: {str(e)}"
                }, 
                status=500
            )

        # Log the user in to create a session
        login(request, user_profile.user)

        print(user_profile.__dict__)
        return TemplateResponse(request, 'auth/two_fa_register_page.html', {"qr_code": qr_code_url})


# auth_app/views.py
class Login_View(generic.CreateView):
    def post(self, request, *args, **kwargs):
        otp_code = request.POST.get('otp_code', None)
        user = getLoginUserService(request, otp_code)
        if user is None:
            return JsonResponse(
                {
                    "status": "Login failed", 
                    "message": "No user with the corresponding username and password exists"
                }, 
                status=status.HTTP_404_NOT_FOUND
            )
        
        return HttpResponseRedirect('/Customers/')

    def get(self, request, *args, **kwargs):
        form = OTPAuthenticationForm()
        return TemplateResponse(request, 'auth/login.html', {'form': form})
 
    

# auth_app/views.py
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from django.http import HttpResponseRedirect
from django.contrib.auth import login

class Verify2FAView(APIView):

    def post(self, request):
        otp = request.POST.get('otp', None)
        if otp is None:
            return Response(
                {
                    "status": "Verification failed", 
                    "message": "OTP code is missing"
                }, 
                status=status.HTTP_400_BAD_REQUEST
            )

        user = getUserService(request)
        if user is None:
            return Response(
                {
                    "status": "Verification failed", 
                    "message": "User not found"
                }, 
                status=status.HTTP_404_NOT_FOUND
            )

        valid_otp = getOTPValidityService(user, otp)
        if not valid_otp:
            return Response(
                {
                    "status": "Verification failed", 
                    "message": "OTP is invalid or already used"
                }, 
                status=status.HTTP_400_BAD_REQUEST
            )
        

        
        return HttpResponseRedirect('/Customers/')

from django.db import transaction
from django.contrib.auth import login
from django.contrib.sites.shortcuts import get_current_site
from django.core.mail import send_mail
from django.shortcuts import render, redirect
from django.urls import reverse
from django.utils.http import urlsafe_base64_encode
from django.template.loader import render_to_string
from django.contrib import messages
from .forms import CustomUserCreationForm
from .models import UserProfile, Tenant, TenantInvitation
from django.contrib.auth.tokens import default_token_generator
from django.utils.encoding import force_bytes

def register(request):
    if request.method == 'POST':
        form = CustomUserCreationForm(request.POST)
        if form.is_valid():
            email = form.cleaned_data.get('email')
            if UserProfile.objects.filter(email=email).exists():
                messages.error(request, 'Registration Failed: Email already in use.')
                return render(request, 'auth/register.html', {'form': form})
            else:
                token = request.GET.get('token', None)
                tenant_invitation = None
                if token:
                    tenant_invitation = TenantInvitation.objects.filter(invite_code=token).first()
                secret_code = form.cleaned_data.get('secret_code')
                if secret_code == settings.SECRET_CODE or tenant_invitation:
                    user = None  # Initialize user variable
                    try:
                        with transaction.atomic():
                            user = form.save(commit=False)
                            user.set_password(form.cleaned_data.get('password1'))
                            user.save()
                            user_profile = UserProfile.objects.create(
                                user=user,
                                email=email,
                                phone_number=form.cleaned_data.get('phone_number'),
                                role='ADMIN',
                                email_invite_code=form.cleaned_data.get('email_invite_code')
                            )
                            if tenant_invitation:
                                tenant = Tenant.objects.create(name=tenant_invitation.tenant.name)
                                tenant_invitation.delete()
                            else:
                                tenant_name = form.cleaned_data.get('tenant')
                                if not tenant_name:
                                    tenant_name = user.username
                                tenant = Tenant.objects.create(name=tenant_name)
                            user_profile.tenant = tenant
                            user_profile.save()

                        # Move login outside the transaction block
                        login(request, user)

                        messages.success(request, 'Registration Succeeded')
                        current_site = get_current_site(request)
                        current_user_object = UserProfile.objects.get(user=user)
                        mfa_url = f"http://{current_site.domain}{reverse('set2fa', kwargs={'code': current_user_object.twofactorsetupcode})}"
                        message = render_to_string('auth/mfa_email.html', {
                            'user': user.username,
                            'mfa_url': mfa_url,
                        })
                        send_mail(
                            'Multi-Factor Authentication Setup',
                            message,
                            settings.DEFAULT_FROM_EMAIL,
                            [current_user_object.email],
                            fail_silently=False,
                        )
                        return redirect(reverse('set2fa', kwargs={'code': current_user_object.twofactorsetupcode}))
                    except Exception as e:
                        print(f"Error: {str(e)}")
                        if user:
                            user.delete()  # Remove the newly created user record
                        messages.error(request, f'Registration Failed: {str(e)}')
                        return render(request, 'auth/register.html', {'form': form})
                else:
                    messages.error(request, 'Registration Failed: Invalid secret code.')
                    print('failed')
                    return render(request, 'auth/register.html', {'form': form})
        else:
            messages.error(request, 'Registration Failed: Please fix form errors.')

    else:
        form = CustomUserCreationForm()
        print('failed2')
    return render(request, 'auth/register.html', {'form': form})

class InvitationView(View):
    def get(self, request, uidb64, token):
        try:
            uid = force_str(urlsafe_base64_decode(uidb64))
            invitation = TenantInvitation.objects.get(id=uid)
        except (TypeError, ValueError, OverflowError, TenantInvitation.DoesNotExist):
            invitation = None

        if invitation is not None and invitation_token_generator.check_token(invitation, token):
            # Create a form instance and populate it with data from the invitation:
            form = CustomUserCreationForm(initial={'email': invitation.email})
            # Render the form with the user's information:
            return render(request, 'registration/register.html', {'form': form})
        else:
            messages.error(request, 'Invitation Failed: Invalid token.')
            return redirect('login')

#registration two_factor 
def two_fa_register_page(request):
    user_id = request.COOKIES.get('user_id')
    if not user_id:
        messages.error(request, "Can't enter this page")
        return redirect('login')

    try:
        user = User.objects.get(id=user_id)
    except User.DoesNotExist:
        messages.error(request, "User does not exist")
        return redirect('login')

    qr_code_link = getQRCodeService(user)

    if request.method == 'POST':
        # Handle form submission here
        pass

    return render(request, 'two_fa_register_page.html', {'qr_code_link': qr_code_link})

class LoginApiView(APIView):
    def post(self, request):
        auth_header = request.META.get('HTTP_AUTHORIZATION')
        if auth_header and auth_header.startswith('Bearer '):
            bearer_token = auth_header
        else:
            bearer_token = None

        if bearer_token:
            try:
                token = bearer_token[7:]  # Extract the token part
                ego_agent = EGOAgent.objects.get(bearer_token=token)
                return Response({"Authorization": f"{bearer_token}", "message": "Success"}, status=status.HTTP_200_OK)
            except EGOAgent.DoesNotExist:
                return Response({"error": "Invalid token"}, status=status.HTTP_400_BAD_REQUEST)
        else:
            return Response({"error": "No token provided"}, status=status.HTTP_400_BAD_REQUEST)

class LogOutView(generic.FormView):
    def get(request):
        logout(request)
        return redirect('login')  # Redirect to 'login' after logout

@login_required
def Accountprofile(request):
    data = UserProfile.objects.get()
    return TemplateResponse(request, 'userprofile_form.html', {'content': data})

@login_required
def get_domain_values(domain):
    domain = domain['subDomain']
    tldExtracted= tldextract.extract(domain)
    SUFFIX= tldExtracted.suffix
    DOMAIN= tldExtracted.domain
    SUBDOMAIN= tldExtracted.subdomain
    return {"suffix": SUFFIX, "DOMAIN": DOMAIN,"SUBDOMAIN": SUBDOMAIN}

@login_required
def WordClassBulkCreate(request, pk):
    print("WordClassBulkCreate called with pk:", pk)
    word_list_group = get_object_or_404(WordListGroup, pk=pk)
    if request.method == 'POST':
        form = UploadFileForm(request.POST, request.FILES)
        if form.is_valid():
            uploaded_file = request.FILES['uploaded_file']

            # Read the file directly from the UploadedFile object
            lines = uploaded_file.readlines()

            # Create a WordList for each line in the file
            for line in lines:
                line_content = line.strip().decode('utf-8')  # Decode bytes to string
                print(line_content)
                word_list = WordList.objects.create(
                    wordlists=word_list_group,  # Associate with the WordListGroup
                    type='DNS',
                    Value=line_content,  # Remove trailing newline
                    Occurance=1,
                    foundAt=[line_content]  # Remove trailing newline
                )
                print("Created WordList:", word_list)

            return redirect('WordClassCreate')
        else:
            return HttpResponseBadRequest('No file was uploaded')
    else:
        form = UploadFileForm()
        return render(request, 'WordList/WordClassCreate.html', {'form': form})



from django.db import transaction

@login_required
def WordListGroupDeleteView(request):
    if request.method == 'POST':
        WordListGroup.objects.all().delete()

        return HttpResponseRedirect(f"/WordList/")

    else:
        return HttpResponse("Method Not Allowed", status=405)


@login_required
def WordClass(request):
    # Query all WordListGroup objects
    wordlist_groups = WordListGroup.objects.all()
    wordlist_groups = WordListGroup.objects.annotate(
        count =Count('wordlists'),

)

    form = WordListGroupFormCreate()
    return TemplateResponse(request, "WordList/WordClass.html", {"WordList": wordlist_groups, "form": form})

@login_required
def WordClassCreate(request):
    # Only users with the 'WRITE' or 'ADMIN' role can use the POST method
    user_profile = UserProfile.objects.get(user=request.user)
    if user_profile.role not in ['WRITE', 'ADMIN']:
        return HttpResponseForbidden('You do not have permission to perform this action')
    else:
        WordList = WordListGroup.objects.all()
        
        if request.method == 'POST':
            form = WordListGroupFormData(request.POST or None)
            if form.is_valid():
                # Create the WordListGroup instance but don't save it yet
                wordlistgroup = form.save(commit=False)
                
                # Set the user field to the logged-in user's UserProfile's user
                user_profile = get_object_or_404(UserProfile, user=request.user)
                wordlistgroup.user = user_profile.id
                
                # Save the WordListGroup instance
                wordlistgroup.save()
                
                return HttpResponseRedirect(f"/WordList/")
                
        return HttpResponseRedirect(f"/WordList/")

@login_required
def CustomerVIEW(request):
    search_query = request.GET.get('search', '')
    customers = Customers.objects.all() 
    server_set = set()


    request_meta_qs = RequestMetaData.objects.filter(
        record_id__in=Record.objects.filter(customer_id__in=customers)
    )

    # Get all non-null 'server' header values
    server_list = [
        req_meta['headers'].get('server')
        for req_meta in request_meta_qs.values('headers')
        if req_meta['headers'] and req_meta['headers'].get('server')
    ]

    server_counter = Counter(server_list)


    customer_count = customers.count()
    customers = customers.annotate(record_count=Count('customerrecords'))
    total_record_count = customers.aggregate(total=Count('customerrecords'))['total'] or 0
    return TemplateResponse(request, 'Customers/customers.html', {"Customers": customers,
                                                                 "total_record_count":total_record_count,
                                                                 "customer_count":customer_count,
                                                                 "server_counter": dict(server_counter)
                                                                 })


@login_required
def CustomersDelete(request, pk):
    Control = Customers.objects.get(pk=pk)
    Control.delete() 
    return HttpResponseRedirect('/Customers/')

@login_required
def VulnSubmitted(request, pk):
    results = FoundVuln.objects.get(pk=pk)
    if request.POST == 'POST':
        # Only users with the 'WRITE' or 'ADMIN' role can use the POST method
        user_profile = UserProfile.objects.get(user=request.user)
        if user_profile.role not in ['WRITE', 'ADMIN']:
            return HttpResponseForbidden('You do not have permission to perform this action')
        else:
            form = FoundVulnFormPK(request.POST, instance=results)
            if form.is_valid():
                form.Submitted = True
                form.save()
    
            return HttpResponseRedirect(request.META.get('HTTP_REFERER', '/'))

from django.http import JsonResponse
from ego.models import EgoControl

@login_required
def get_scan_project_data(request):
    scan_project_id = request.GET.get('scan_project_id')
    scan_project_name = request.GET.get('scan_project_name')

    if scan_project_id:
        ego_control = EgoControl.objects.filter(id=scan_project_id).first()
    elif scan_project_name:
        ego_control = EgoControl.objects.filter(ScanProjectByName=scan_project_name).first()
    else:
        return JsonResponse({'error': 'Invalid request'}, status=400)

    if ego_control:
        return JsonResponse({
            'ScanGroupingProject': ego_control.ScanGroupingProject,
            'ScanProjectByName': ego_control.ScanProjectByName,
        })
    return JsonResponse({'error': 'No data found'}, status=404)


# create a customer record    
# Get country information from 2 character country code EN US FR GR
@login_required
def get_country_location(country_code):
    
    try:
        country_info = pycountry.countries.get(alpha_2=country_code.upper())
        # You would need to replace this with a method to get the actual latitude and longitude of the country
        return country_info.name
    except AttributeError:
        print(f"Invalid country code: {country_code}")
        return None

#rretrieves latitude and lonogitufe   from country name
@login_required
def get_latitude_location(country_name, city):
    
    if str(country_name) != 'REDACTED FOR PRIVACY' and country_name != None:
        #location = geolocator.geocode(str(country_name))
        geolocator = Nominatim(user_agent="geopy get country")
        location = geolocator.geocode(str(get_country_location(country_name)))
        return [location.latitude, location.longitude]
    elif str(city) != 'REDACTED FOR PRIVACY' and city != None:
        #location = geolocator.geocode(str(country_name))
        geolocator = Nominatim(user_agent="Geopy Library")
        location = geolocator.geocode(str(city))
        return [location.latitude, location.longitude]
    else:
        pass
    return None

@login_required
def CustomersCreateurl(request, format=None):
    if request.method == 'POST':
        # Only users with the 'WRITE' or 'ADMIN' role can use the POST method
        user_profile = UserProfile.objects.get(user=request.user)
        if user_profile.role not in ['WRITE', 'ADMIN']:
            return HttpResponseForbidden('You do not have permission to perform this action')
        else:
            form = SimpleCustomersFormCreate(request.POST)
            if form.is_valid():
                # Create the customer instance but don't save it yet
                customer = form.save(commit=False)
                
                # Set the tenant field on the customer instance
                customer.tenant = user_profile.tenant
                
                # Save the customer instance to the database
                customer.save()
                
                # If FastPass is enabled, create an EgoControl object
                if form.cleaned_data.get('FastPass'):
                    EgoControl.objects.create(
                        ScanGroupingProject=customer.groupingProject,
                        ScanProjectByName=customer.nameProject,
                        ScanProjectByID=customer.id,
                        HostAddress=user_profile.FastPassHost,
                        Port=user_profile.FastPassPort,
                        Scan_DomainName_Scope_bool='True',
                        crtshSearch_bool='True',
                    )
                return HttpResponseRedirect('/Customers/Create')
    else:
        form = SimpleCustomersFormCreate()

    return TemplateResponse(request, 'Customers/customersCreate.html', {'form': form})

@login_required
def CustomerPkDelete(request, pk, format=None):
    if request.method == 'GET':
        customer = get_object_or_404(Customers, pk=pk)
        records = Record.objects.filter(customer_id=customer)
        records.delete()
        return JsonResponse({'status': 'success'}, status=204)  
    
#retrieve customer record
@login_required
def CustomerPk(request, pk, format=None):
    if request.method == 'GET':
        customer = get_object_or_404(Customers, pk=pk)
        form = SimplePKCustomersFormCreate(instance=customer)
        serializer = CustomerRecordSerializer(customer)
        data = serializer.data

        template_info_name = [ ]
        found_vuln_info_name = []
        setFoundVuln = []
        setTemplate = []
        WebAppParm = request.GET.get('WebAppParm', None)
        paginatorParmSize = request.GET.get('paginatorSize', None)
        if paginatorParmSize:
            paginatorSize = paginatorParmSize   
        else:
            paginatorSize = 100
        if WebAppParm:
            # Filter the records where 'alive' is True
            aliving_records = [record for record in data['customerrecords'] if bool(record['RecRequestMetaData']) ==  True]

            paginator = Paginator(aliving_records, paginatorSize )  # Show 20 records per page
            page_number = request.GET.get('page', 1)
            try:
                page_obj = paginator.page(page_number)
            except EmptyPage:
                page_obj = paginator.page(paginator.num_pages)    
            data['customerrecords'] = [record for record in page_obj.object_list]
            return TemplateResponse(request, "Customers/customersPK.html", {
                "Customer": data, 
                "form": form, 
                'page_obj': page_obj,
                "Vulns": setFoundVuln, 
                "Template": setTemplate, 
                "template_info_name": template_info_name, 
                "found_vuln_info_name": found_vuln_info_name, 
            })            
        for y in customer.customerrecords.all():
            if y == 'Templates_record':
                for x in y:
                    print(x.name)
                    template_info_name.append(x.name)

            found_vuln_info_name.append(y)

        # Continue with the rest of the CustomerPk logic
        Map_Generation = request.GET.get('mapcreate', None)
        if Map_Generation:
            whois_customers= whois.objects.filter(customer_id=pk)
            print('whois_customers', whois_customers)
            for x in whois_customers:
                    print(x.map_image)
                    print('map')
                    location = get_latitude_location(x.country, x.city)
                    if location != None:
                        map = folium.Map(location=location, zoom_start=5)
                        name = f"img{x.id}.html"
                        map.save(name)
                        with open(name, 'rb') as f:
                            file_data = File(f)
                            x.map_image = file_data
                            # Assuming `customer` is a Django model instance
                            x.map_image.save(name, file_data, save=True)


        search_query = request.GET.get('search', None)
        if search_query:
            alive_records = [x for x in data['customerrecords'] if search_query in str(x)]
        else:
            alive_records = data['customerrecords']

        paginator = Paginator(alive_records, 100)  # Show 20 records per page
        page_number = request.GET.get('page', 1)
        try:
            page_obj = paginator.page(page_number)
        except EmptyPage:
            page_obj = paginator.page(paginator.num_pages)

        data['customerrecords'] = [record for record in page_obj.object_list]
        print('template_info_name1',template_info_name)
        return TemplateResponse(request, "Customers/customersPK.html", {
            "Customer": data, 
            "form": form, 
            'page_obj': page_obj,
            "Vulns": setFoundVuln, 
            "Template": setTemplate, 
            "template_info_name": template_info_name, 
            "found_vuln_info_name": found_vuln_info_name, 
        })

    elif request.method == 'POST':
        # Only users with the 'WRITE' or 'ADMIN' role can use the POST method
        user_profile = UserProfile.objects.get(user=request.user)
        if user_profile.role not in ['WRITE', 'ADMIN']:
            return HttpResponseForbidden('You do not have permission to perform this action')
        else:        
            customer = get_object_or_404(Customers, pk=pk)
            form = SimpleCustomersFormCreate(request.POST, instance=customer)
            if form.is_valid():
                results = form.save()
                return HttpResponseRedirect(f'/Customers/{results.pk}/')
            else:
                return HttpResponse("Form is not valid", status=400)
    else:
        form = SimpleCustomersFormCreate(instance=customer)
    return TemplateResponse(request, 'Customers/customersPK.html', {'form': form})


@login_required
def Interconneciton(request, pk):
    results = get_object_or_404(Customers, pk=pk)
    #record = CustomersViewSet(results)
    queryset = CustomerRecordSerializer(results)

    customers_ = queryset.data['customer_records']
    dic = {}
    for x in customers_:

        ipaddr = x.get('ip', {})
        print(ipaddr)
        if ipaddr == 0:
            pass
        else:
            try:
                if bool(ipaddr) == False:
                       pass
                else:
                    #print('ipaddr',ipaddr)
                    dic.update({ ipaddr : f"{int(dic[ipaddr]) + 1}" })
            except:
                dic.update({ ipaddr : "1" })
    data = []
    labels = []
    for d in dic:
        valuenew = str(dic[d])
        if valuenew == "0":
            pass
        else:
            data.append(valuenew)
            labels.append(d)
    if request.method == 'GET':
        return JsonResponse(data={"data": data, "labels": labels})

@login_required
def VulnsBoardChartPK(request, pk):
    results = get_object_or_404(Customers, pk=pk)
    #record = CustomersViewSet(results)
    queryset = CustomerRecordSerializer(results)
    customers_ = queryset.data['customer_records']
    sev_score = {"info": "0", "low": "0", "medium": "0", "high": "0" , "critical": "0", "unknown": "0"}
    for x in customers_:
        print('x')
        querysetTemplate = x['Templates_record']
        queryset = x['foundVuln_record']
        count = len(queryset)
        for s in querysetTemplate:
            print('s',s)
            s.items()
            ocr = s['info']
            ocr = ocr['severity']
            value = sev_score[ocr]
            new_value = int(value) + 1
            print(new_value)
            sev_score.update({ocr: new_value})
        for s in queryset:
            s.items()
            ocr = s['severity']
            value = sev_score[ocr]
            new_value = int(value) + 1
            print(new_value)
            sev_score.update({ocr: new_value})
    data = []
    labels = []
    for d in sev_score:
        valuenew = str(sev_score[d])
        data.append(valuenew)
        labels.append(d)
    if request.method == 'GET':
        return JsonResponse(data={"data": data, "labels": labels})

@login_required
def RecordDelete(request, pk):
    # Only users with the 'WRITE' or 'ADMIN' role can use the POST method
    user_profile = UserProfile.objects.get(user=request.user)
    if user_profile.role not in ['WRITE', 'ADMIN']:
        return HttpResponseForbidden('You do not have permission to perform this action')
    else:
        results = get_object_or_404(Record, pk=pk)
        #record = CustomersViewSet(results)
        queryset = TotalRecords(results)
        queryset.delete() 
        return HttpResponseRedirect(f'/Customers/{results.pk}')

## GNAW
@login_required
def GnawControlBoards(request):
    gnaw = GnawControl.objects.all()
    customers = Customers.objects.all()
    form = create_gnawcontrol()
    create = GnawControlCreateViewSet()
    return TemplateResponse(request, 'GnawControl/gnawControlBoards.html', {"gnaw": gnaw, "customers": customers, "create":create, "form": form})

@login_required
def GnawControlBoardDelete(request, pk):
    Control = get_object_or_404(GnawControl, pk=pk)
    Control.delete() 
    return HttpResponseRedirect('/GnawControlBoard/')

@login_required
def GnawControlBoardsCreate(request):
    if request.method == 'GET':
        form = create_gnawcontrol()
        return TemplateResponse(request, f'GnawControl/gnawControlBoardsCreate.html', {"form": form})
    
    if request.method == 'POST':
        form = create_gnawcontrol(request.POST or None)
        if form.is_valid():
            form.cleaned_data['HostAddress'] = form.cleaned_data['HostAddress'].rstrip('/')  # Remove trailing slash
            form.save()
            return HttpResponseRedirect('/GnawControlBoard/')
        else:
            # Handle the case where the form is not valid 
            pass

@login_required
def GnawControlBoardsPK(request, pk):
    results = GnawControl.objects.get(pk=pk)
    form = create_mantisControl()
    if request.method == 'GET':
        form = create_gnawcontrol(instance=results)
        return TemplateResponse(request, f'GnawControl/gnawControlBoardsPk.html', {"control": results, "form": form})
    if request.method == 'POST':
        form = create_gnawcontrol(request.POST, instance=results or None)
        if form.is_valid():
            form.save()
        return HttpResponseRedirect(f'/GnawControlBoard/{results.pk}')

@login_required
def GnawControlBulkDelete(request):
    if request.method == 'POST':
        deleted, _ = GnawControl.objects.all().delete()
        messages.success(request, f'{deleted} GnawControl records deleted.')
    return redirect('GnawControlBoards')

@login_required
def GnawControlBulkImport(request):
    if not request.user.is_authenticated:
        messages.error(request, "You must be logged in to perform this action.")
        return redirect('GnawControlBoards')

    user_profile = UserProfile.objects.get(user=request.user)
    default_host = user_profile.FastPassHost or '127.0.0.1'
    default_port = user_profile.FastPassPort or 80

    # Get all project names already claimed in GnawControl
    claimed_projects = set(GnawControl.objects.values_list('ScanProjectByName', flat=True))

    created_count = 0
    for customer in Customers.objects.all():
        project_name = getattr(customer, 'nameProject', '')
        if project_name and project_name not in claimed_projects:
            GnawControl.objects.create(
                ScanGroupingProject=getattr(customer, 'groupingProject', ''),
                ScanProjectByName=project_name,
                ScanProjectByID=getattr(customer, 'id', ''),
                HostAddress=default_host,
                Port=default_port, 
                Record_chunk_size='5',  
                Gnaw_Completed=False,
                failed=False,
                severity = 'high, critical'
            )
            created_count += 1

    messages.success(request, f'Bulk import completed. {created_count} new GnawControl objects created.')
    return redirect('GnawControlBoards')



## EGO
@login_required
def EgoControlBoard(request):
    if request.method == 'POST':
        form = EgoControlUpdateForm(request.POST)
        if form.is_valid():
            # Get the selected EgoControl IDs from the `targets` field
            selected_targets = form.cleaned_data.get('targets', [])
            
            # Update only the selected EgoControl instances
            for target_id in selected_targets:
                instance = EgoControl.objects.get(id=target_id)
                # Create a form instance for the specific EgoControl object
                instance_form = EgoControlUpdateForm(request.POST, instance=instance)
                if instance_form.is_valid():
                    instance_form.save()

            # Redirect after successful update
            return redirect('EgoControlBoard')

    # For GET requests, render the form and data
    response = EgoControl.objects.all()
    customers = Customers.objects.all()
    form = EgoControlUpdateForm()
    return TemplateResponse(request, 'EgoControl/EgoControlBoard.html', {"controls": response, "customers": customers, "form": form})

@login_required
def update_egocontrol(request, pk):
    egocontrol = get_object_or_404(EgoControl, pk=pk)
    if request.method == 'POST':
        form = EgoControlUpdateForm(request.POST, instance=egocontrol)
        if form.is_valid():
            form.save()  # Save the updated values, including the checkbox state
            return redirect('egocontrol_list')  # Redirect to a list or detail view
    else:
        form = EgoControlUpdateForm(instance=egocontrol)
    return render(request, 'ego/update_egocontrol.html', {'form': form})

@login_required
def EgoControlCreate(request):
    if request.method == 'POST':
        form = create_egocontrol(request.POST)
        if form.is_valid():
            egocontrol = form.save(commit=False)
            if not egocontrol.BruteForce_WL.exists():
                egocontrol.BruteForce_WL.set([])  # Set to an empty list or appropriate default value
            egocontrol.save()
            form.save_m2m()  # Save the many-to-many relationships
            return HttpResponseRedirect('/EgoControlBoard/create')
    else:
        form = create_egocontrol()
    return render(request, 'EgoControl/EgoControlBoardCreate.html', {'form': form})

from django.contrib.auth.decorators import login_required
from django.template.response import TemplateResponse
from django.shortcuts import redirect

@login_required
def update_egocontrol_view(request):
    if request.method == 'POST':
        # Get the selected targets from the POST data
        selected_targets = request.POST.getlist('targets')  # List of selected IDs
        host_address = request.POST.get('HostAddress')  # Get HostAddress from the form
        port = request.POST.get('Port')  # Get Port from the form

        # Update only the selected EgoControl instances
        for target_id in selected_targets:
            try:
                instance = EgoControl.objects.get(id=target_id)
                instance.HostAddress = host_address
                instance.Port = port
                instance.save()
            except EgoControl.DoesNotExist:
                # Handle case where the instance does not exist
                pass

        # Redirect to EgoControlBoard after updating
        return redirect('EgoControlBoard')  # Ensure 'EgoControlBoard' matches the URL name in urls.py

    return redirect('EgoControlBoard')


@login_required
def EgoControlBoardDelete(request, pk):
    Control = get_object_or_404(EgoControl, pk=pk)
    Control.delete() 
    return HttpResponseRedirect('/EgoControlBoard/')

@login_required
def EgoControlBoardpk(request, pk):
    results = EgoControl.objects.get(pk=pk)
    if request.method == 'POST':
        form = PKcreate_egocontrol(request.POST, instance=results)
        if form.is_valid():
            results= form.save()
            return HttpResponseRedirect(f'/EgoControlBoard/{results.pk}')
        else:
            return HttpResponse("Form is not valid", status=400)
    else:
        form = PKcreate_egocontrol(instance=results)
    return TemplateResponse(request, 'EgoControl/EgoControlBoardpk.html', {"control": results, "form":form})

class BucketValidationBulkDeleteView(View):
    def post(self, request, *args, **kwargs):
        BucketValidation.objects.all().delete()
        messages.success(request, "All BucketValidation objects have been deleted.")
        return redirect('Mantis')

#VULNS 
# list vulns found
@login_required
def Mantis(request):
    query = request.GET.get("q")
    print(query)
    if query:
        querysetTemplate = Template.objects.filter(info__name__icontains=query)
        querysetFoundVuln = FoundVuln.objects.filter(name__icontains=query)
        querysetBucketValidation = BucketValidation.objects.filter(is_valid=True,bucket_name=query)
    else:
        querysetTemplate = Template.objects.all()
        querysetFoundVuln = FoundVuln.objects.all()
        querysetBucketValidation = BucketValidation.objects.all()

    count = len(querysetFoundVuln) + len(querysetTemplate)
   
    template_info_name = set([ (obj.info['name'], obj.info['severity']) for obj in querysetTemplate])
    found_vuln_info_name = set([ (obj.name, obj.severity)  for obj in querysetFoundVuln])
    if request.method == 'GET':
        return TemplateResponse(request, "Mantis/Mantis.html", {
                "Buckets": querysetBucketValidation,
                                                                   "Vulns": querysetFoundVuln[::-1], 
                                                                   "Template": querysetTemplate[::-1], 
                                                                   "template_info_name": template_info_name, 
                                                                   "found_vuln_info_name": found_vuln_info_name, 
                                                                   "count": count
                                                                   })

#VULNS 
# list vulns found
@login_required
def MantisSearch(request):
    data = PythonMantis.objects.all()
    return TemplateResponse(request, f'Mantis/Mantis.html', {"data":data})

def MantisDelete(request, pk):
    Control = PythonMantis.objects.get(pk=pk)
    Control.delete() 
    return HttpResponseRedirect('/Mantis/search/')

# create mantis controls
@login_required
def MantisCreate(request):
    context = {}
    mantis = PythonMantis.objects.all()
    cards = VulnCard.objects.all()
    form = MantisDataCreate()
    if request.method == 'GET':
        form = MantisDataCreate(request.POST or None)
        context['form'] = form
        return TemplateResponse(request, f'Mantis/MantisCreate.html', {"mantis": mantis, "cards": cards, "form": form})
    if request.method == 'POST':
        form = MantisDataCreate(request.POST)
        if form.is_valid():
            mantis = form.save()
        else:
            print('FORM NOT VALID')
            messages.error(request, 'Form is not valid.')
        context['form'] = form
        return TemplateResponse(request, f'Mantis/MantisCreate.html', {"mantis": mantis, "cards": cards, "form": form})


@login_required
def MantisDeletePK(request, pk):
    Control = PythonMantis.objects.get(pk=pk)
    Control.delete() 
    return HttpResponseRedirect(f'/Mantis/create/')

@login_required
def mantiscreatePK(request, pk):
    context ={}
    mantis = PythonMantis.objects.get(pk=pk)
    form = MantisDataCreate()
    #cards = VulnCard.objects.get(pk=uuid.UUID(mantis.vulnCard_id))
    if request.method == 'GET':
        form = MantisDataCreate(instance=mantis)
        return TemplateResponse(request, f'Mantis/MantisPK.html', {"results": mantis, "form": form})
    if request.method == 'POST':
        form = MantisDataCreate(request.POST  or None, instance=mantis)
        if form.is_valid():
            form.save()
        context['form']=form
        return HttpResponseRedirect(f'/Mantis/{pk}')

## vulncards 
@login_required
def VulnCardCreate(request):
    queryset = VulnCard.objects.all()
    formCard = VulnCardForm()
    form = PythonMantisForm()
    last_formCard = VulnCard.objects.last()  # Get the last created formCard

    if request.method == 'GET':
        return TemplateResponse(request, "Mantis/MantisVulnCard.html", {"results": queryset, "form": form, "formCard": formCard })
    
    if request.method == 'POST':
        formCard = VulnCardForm(request.POST or None)
        if formCard.is_valid():
            vuln_card = formCard.save()
            formVuln = PythonMantisForm(request.POST or None, initial={'vulnCard_id': vuln_card.id, 'id': last_formCard.id if last_formCard else None})
            if formVuln.is_valid():
                formVuln.save()
            return HttpResponseRedirect(reverse('VulnCardCreate') + '?step=2')
        else:
            formVuln = PythonMantisForm(request.POST or None)
        return TemplateResponse(request, "Mantis/MantisVulnCard.html", {"results": queryset, "form": formVuln, "formCard": formCard })

@login_required
def VulnCardPK(request, pk):
    queryset = VulnCard.objects.get(pk=pk)
    form = VulnCardForm(instance=queryset)
    if request.method == 'GET':
        return TemplateResponse(request, "Mantis/MantisVulnCard.html", {"results": queryset, "form": form})
    if request.method == 'POST':
        form = VulnCardForm(request.POST  or None, instance=queryset)
        if form.is_valid():
            form.save()
        return HttpResponseRedirect(f'/Mantis/MantisVulnCardPk/{pk}')

@login_required
def view_vulncardANDpythonmantis(request):
    queryset = VulnCard.objects.all()
    formCard = VulnCardForm()
    form = PythonMantisForm()
    if request.method == 'GET':
        return TemplateResponse(request, "Mantis/MantisVulnCard.html", {"results": queryset, "form": form, "formCard": formCard })

@login_required
def create_vulncard(request):
    if request.method == 'POST':
        form = VulnCardForm(request.POST, request.FILES)
        if form.is_valid():
            form.save()
            return redirect('vulncard_list')  # Redirect to a list or detail view
    else:
        form = VulnCardForm()
    return render(request, 'create_vulncard.html', {'form': form})

@login_required
def create_pythonmantis(request):
    if request.method == 'POST':
        form = PythonMantisForm(request.POST, request.FILES)
        if form.is_valid():
            pythonmantis = form.save(commit=False)
            vulncard_id = request.POST.get('vulnCard_id')
            pythonmantis.vulnCard_id = get_object_or_404(VulnCard, id=vulncard_id)
            pythonmantis.save()
            return redirect('pythonmantis_list')  # Redirect to a list or detail view
    else:
        form = PythonMantisForm()
    return render(request, 'create_pythonmantis.html', {'form': form, 'vulncards': VulnCard.objects.all()})

@login_required
def VulnsBoardChart(request):
    querysetTemplate = Template.objects.all()
    queryset = FoundVuln.objects.all()
    count = len(queryset)
    sev_score = {"info": "0", "low": "0", "medium": "0", "high": "0" , "critical": "0", "unknown": "0"}
    for s in querysetTemplate:
        ###print('s',s)
        ocr = s.info['severity']
        value = sev_score[ocr]
        new_value = int(value) + 1
        ###print(new_value)
        sev_score.update({ocr: new_value})
    for s in queryset:
        ###print(s)
        ocr = s.severity
        value = sev_score[ocr]
        new_value = int(value) + 1
        ###print(new_value)
        sev_score.update({ocr: new_value})
    data = []
    labels = []
    for d in sev_score:
        valuenew = str(sev_score[d])
        data.append(valuenew)
        labels.append(d)
    if request.method == 'GET':
        return JsonResponse(data={"data": data, "labels": labels})

@login_required
def AliveOrDeadChartPk(request, pk):
    results = get_object_or_404(Customers, pk=pk)
    #record = CustomersViewSet(results)
    queryset = CustomerRecordSerializer(results)

    customers_ = queryset.data['customer_records']
    
    aliveordead = {"dead": "0", "alive": "0"}
    hostalive = [x['alive'] for x in customers_  if x['alive'] == True]
    hostdead = [x['alive'] for x in customers_  if x['alive'] == False]
    count_alive = len(hostalive)
    count_dead = len(hostdead)
    aliveordead.update({"dead": count_dead})
    aliveordead.update({"alive": count_alive})
    data = []
    labels = []
    for d in aliveordead:
        valuenew = str(aliveordead[d])
        data.append(valuenew)
        labels.append(d)
    if request.method == 'GET':
        return JsonResponse(data={"labels": labels, "data": data})

@login_required
def PortChartPk(request, pk):
    results = get_object_or_404(Customers, pk=pk)
    #record = CustomersViewSet(results)

    queryset = CustomerRecordSerializer(results)
    customers_ = queryset.data['customer_records']
    ports_store = {}
    for x in customers_:
        ports = x.get('OpenPorts',[])
        
        for p in ports:
            try:
                ports_store.update({f"{p}": f"{ int(ports_store[p]) + 1 }"})
            except:
                ports_store.update({f"{p}": "1" })
    data = []
    labels = []
    for d in ports_store:
        valuenew = str(ports_store[d])
        data.append(valuenew)
        labels.append(d)
    if request.method == 'GET':
        return JsonResponse(data={"data": data, "labels": labels})

@login_required
def Vulnerabilty(request):
    Templates = Template.objects.all()
    #convert reponse data into json
    DIC = {}
    out_vulns = []
    for users in Templates:
        #record_id = `s['record_id']
        #rjson = response.json()
        #users['customer'] = rjson.get('customer',{})MantisControls
        sevrity= users['info']
        if sevrity['severity'] == 'low':
            out_vulns.append(users)
        elif sevrity['severity'] == 'medium':
            out_vulns.append(users)
        elif sevrity['severity'] == 'high':
            out_vulns.append(users)
        elif sevrity['severity'] == 'critical':
            out_vulns.append(users)
    if out_vulns:
        out=[]
        for out_vuln in out_vulns:
            out_vuln_time= out_vuln['date']
            current_date = (out_vuln_time.replace("T", " ").replace(".000Z", "")).split(" ")[0]
            out_vuln.update({'date':current_date})
            out.append(out_vuln)
        return render(request, "Vuln/VulnerabilitiesApp.html", {'out_vuln': out})
    else:
        return render(request, "Vuln/VulnerabilitiesApp.html", {'out_vuln': out})

#def MantisControlsApp(requests):
class MantisControlClass():
    def get(self, request): 
        form = create_mantisControl()
        data = MantisControls
        return TemplateResponse(request, 'MantisControls/MantisControl.html', {'form': form,'data':data})
    
    def post(self, request):
        # Only users with the 'WRITE' or 'ADMIN' role can use the POST method
        user_profile = UserProfile.objects.get(user=request.user)
        if user_profile.role not in ['WRITE', 'ADMIN']:
            return HttpResponseForbidden('You do not have permission to perform this action')
        else:
            form = create_mantisControl(request.POST)
            if form.is_valid():
                form.save()
            return HttpResponseRedirect('/MantisControls/')


def check_totalcpe_in_vulnerability(TOTALCPE, vulnerability):
    for configuration in vulnerability.configurations.all():
        for node in configuration.nodes.all():
            for cpe_match in node.cpeMatch.all():
                if cpe_match.cpe23Uri == TOTALCPE:
                    return True
    return False

@login_required
def TotalVulnApp(request, pk):
    # Only users with the 'WRITE' or 'ADMIN' role can use the POST method
    user_profile = UserProfile.objects.get(user=request.user)
    if user_profile.role not in ['WRITE', 'ADMIN']:
        return HttpResponseForbidden('You do not have permission to perform this action')    
    else:
        index = [
            ('info, low, medium, high, critical, unknown'),
         ('info'),
         ('low'),
         ('medium'),
         ('high'),
         ('critical'),
         ('unknown')
         ]  

        response = requests.get(f'http://127.0.0.1:10000/api/customers/{pk}')
        #convert reponse data into json
        rjson = response.json()
        Records_here = rjson['customer_records']
        services_nmap_out = []

        ports_out= []
        set_sorted_ports=[]
        single_ports_out= set()
        newcpeseen=[]
        for n in Records_here:
            domain = n.get('subDomain')
            ###print(domain)
            nmap = n.get('Nmaps_record',[])
            nmap_ports = {"ports" : []} 
            nmap_products = {"products" : [] }
            nmap_services = {"services" : [] }
            nmap_protocols = {"protocols" : [] }
            listed_services = []
            for map in nmap:
                if n['alive'] == False:
                    pass
                else:
                    ports = map.get('port', {})
                    if ports:
                        nmap_ports['ports'].append(ports)
                        ports_out.append(ports)
                        set_sorted_ports.append(ports)
                        single_ports_out.add(ports)
                    
                    try:
                        product = map.get('product')
                        nmap_products['products'].append(product)
                        protocol = map.get('protocol')
                        nmap_protocols['protocols'].append(protocol)
                        service = map.get('name')
                        nmap_services['services'].append(service)
                        servicefp = map['servicefp']
                        regex = re.compile("(?<=,\")(.*?)(?=\"\))")
                        print(servicefp['servicefp'])
                        found = re.search(regex, str(servicefp))
                        grouping = found.group(1)
                        spaces = grouping.replace('\\x20' , ' ')
                        macsnewline = spaces.replace('\\r', '')
                        period = macsnewline.replace('\\.', '.')
                        results = period.split('\\n')
                        request_formated_dict = dict.fromkeys(['results'], results)
                        DIC = {}
                        DIC.update(request_formated_dict)
                    except:
                        DIC = {}
                    
                    
                    record_dict = dict.fromkeys(['record'], n)

                    
                    nmap_dict = dict.fromkeys(['map'], map)
                    cpe = map.get('cpe')
                    nist_dict=[]
                    print('service',service)
                    if len(cpe)>0:
                        try:
                            if cpe in newcpeseen:
                                pass
                            else:


                                newcpeseen.append(cpe)
                                newcpe=cpe.replace('cpe:/','')
                                print(newcpe)
                                time.sleep(1)
                                nisturl = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName=cpe:2.3:{newcpe}:{service}"
                                print(nisturl)
                                response = requests.get(
                                    url=nisturl
                                )
                                print(response.status_code)
                                print('above')
                                nist_rjson = response.json()
                                vulns = (nist_rjson.get('vulnerabilities'))
                                
                                for vuln in vulns:
                                    print(vuln)
                                    cve=vuln.get('cve')
                                    for k in cve:
                                        print(k)
                                        if k == 'descriptions':
                                            DICnist_rjson ={}
                                            descript= cve.get('descriptions')
                                            descout = descript[0]
                                            DESCRIPT= dict.fromkeys(['descriptions'], descout)
                                            DICnist_rjson.update(DESCRIPT)
                                            references=cve.get('references')
                                            refeDict= dict.fromkeys(['references'], references)
                                            DICnist_rjson.update(refeDict)
                                            for d in descript:
                                                print(d)
                                                metrics = (cve.get('metrics'))
                                                print(metrics)
                                                cvs = metrics.get('cvssMetricV2', {})
                                                
                                                print(cvs)
                                                for score in cvs:
                    
                                                    s = score.get('cvssData')
                                                    DICnist_rjson.update(s)
                                                    nist_dict.append(DICnist_rjson)
                        except:
                            pass
                    nist_dict = dict.fromkeys(['nist'], nist_dict) 
                    dict_cpe = dict.fromkeys(['cpe'], str(cpe))
                    print('#')
                   # ###print(nist_dict)
                    print('#')
                    subdomain = dict.fromkeys(['domain'], domain)
                    DIC.update(nmap_ports)
                    DIC.update(nist_dict)
                    DIC.update(subdomain)
                    DIC.update(dict_cpe)
                    DIC.update(record_dict)
                    DIC.update(nmap_dict)
                    listed_services.append(DIC)
            listedServices = dict.fromkeys(['listed_services'], listed_services)
            outDIC = {}
            outDIC.update(listedServices)
            outDIC.update(nmap_products)
            outDIC.update(nmap_services)
            outDIC.update(nmap_protocols)
        
        
            services_nmap_out.append(outDIC)
            ###print('#')
            ###print('services_nmap_out', services_nmap_out)
            ###print('#')

        templates = [ n.get('Templates_record', {})[0] for n in Records_here if bool(n.get('Templates_record', {})) != False]
        info = [ t.get('info', {}) for t in templates]
    
        severity = [s['severity'] for s in info ]
        #severity = info.get('severity')
        occurrence = {item: severity.count(item) for item in severity}
        results = {item: 0 for item in index if item not in occurrence}
        occurrence.update(results)

        ###print(occurrence)
        print(np.cumsum(severity))
        #df = pd.DataFrame.from_dict(severity)
        #dfgraph = df.plot.bar()
        #image = dfi.export(df, 'dataframe.png')
        mydict = {
            "dataframe":  occurrence
        }
    
        #fuzz.partial_ratio(str(lowerCustomerValues),str(lowerVendorValues))
        seen=set()
        seen_add = seen.add
        tuple_list = [ t for t in services_nmap_out if  t.get('map') ]
        ###print('#')
        ###print(tuple_list)
        nmap_tup = [ (x.get('map').get('port')) for x in tuple_list  if x.get('map').get('port') ]
        ###print(nmap_tup)
        ###print('#')
        if nmap_tup:
            ignore = list(mode(nmap_tup))
            ###print(ignore)
        flat_list_ports = [s for s in tuple_list if s.get('map').get('port') != ignore]
        #flat_list_ports = [s for s in set_sorted_ports if s.get('OpenPorts', ) in super]
        flat_list_subdomain_alive = [p for p in Records_here if bool(p.get('alive', "")) == True ]
        flat_list_subdomain_dead = [p for p in Records_here if bool(p.get('alive', "")) == False ]
        counter = len(rjson['customer_records'])
        services_nmap = dict.fromkeys(['services_nmap'], services_nmap_out)
        dic_flat_list_subdomain_alive = dict.fromkeys(['alive_host'], flat_list_subdomain_alive)
        dic_flat_list_subdomain_dead = dict.fromkeys(['dead_host'], flat_list_subdomain_dead)
        dic_flat_list_ports = dict.fromkeys(['flat_list_port_tuple'], flat_list_ports)
        dic_ports = dict.fromkeys(['total_ports'], sorted(ports_out))
        dic_single_ports = dict.fromkeys(['single_ports'], sorted(single_ports_out))
        dic_count = dict.fromkeys(['counter'], counter)
        ###print(counter)
        rjson.update(dic_flat_list_subdomain_dead)
        rjson.update(dic_flat_list_subdomain_alive)
        rjson.update(dic_flat_list_ports)
        rjson.update(dic_count)
        rjson.update(dic_ports)
        rjson.update(dic_single_ports)
        rjson.update(mydict)
        rjson.update(services_nmap)
        print(rjson)
        if rjson:
            return render(request, "TotalVulnApp.html", {'rjson': rjson}, )
        else:
            return HttpResponseRedirect('/Web/')

    
def flatten_dict(d, parent_key='', sep='_'):
    items = []
    for k, v in d.items():
        new_key = f"{parent_key}{sep}{k}" if parent_key else k
        if isinstance(v, dict):
            items.extend(flatten_dict(v, new_key, sep=sep).items())
        else:
            items.append((new_key, v))
    return dict(items)

@method_decorator(csrf_exempt, name='dispatch')
class NistView(View):
    def post(self, request, pk, *args, **kwargs):
        customer = get_object_or_404(Customers, pk=pk)
        customer_records = CustomerRecordSerializer(customer)
        customer_records = customer_records.data
        out = []
        DICnist_rjson_out = []
        seen = []
        for record in customer_records['customerrecords']:
            record_id = record['id']
            record_instance = Record.objects.get(id=record_id)
            for nmap in record['Nmaps_record']:
                cpe = nmap['cpe']
                product = nmap['product'].replace(' ', ':').replace('+', ':')
                if 'httpd' in str(product):
                    product = product.replace('httpd', 'http_server')
                else:
                    product = product
                version = nmap['version'].replace(' ', ':').replace('+', ':')
                service = nmap['service'].replace(' ', ':').replace('+', ':')
                if cpe and cpe != 'a':
                    if version or service:
                        TOTALCPE = f'{cpe[0]}:{product}:{version}:{service}'
                    else:
                        if product:
                            TOTALCPE = f'{cpe[0]}:{product}'
                        else:
                            TOTALCPE = False
                elif product:
                    if version or service:
                        TOTALCPE = f'{product}:{version}:{service}'
                    else:
                        TOTALCPE = False
                else:
                    TOTALCPE = False
                if TOTALCPE and TOTALCPE not in seen: 
                    seen.append(TOTALCPE)
                    out.append(TOTALCPE)
                    existing_vulnerability, created = Vulnerability.objects.get_or_create(configurations__nodes__cpeMatch__criteria=TOTALCPE)
                    if not created:
                        continue  # Skip this iteration if a Vulnerability with the same TOTALCPE already exists
                    time.sleep(1)
                    try:
                        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName=cpe:2.3:{TOTALCPE}"
                        header = {"Authorization": f"Bearer {settings.BEARER_TOKEN}"}
                        nist_rjson_response = requests.get(url=url, headers=header, verify=True, timeout=60)
                        if nist_rjson_response.status_code == 200:
                            nist_rjson = json.loads(nist_rjson_response.text)
                            if nist_rjson:
                                vulns = nist_rjson.get('vulnerabilities')
                                for vuln in vulns:
                                    if len(vuln) > 0:
                                        out.append(vuln)
                                        cve = vuln.get('cve')
                                        cve_id = cve.get('id')
                                        references = cve.get('references', [])
                                        descriptions = cve['descriptions']
                                        metrics = cve.get('metrics', {})
                                        cvs = metrics.get('cvssMetricV2', [])
                                        cvssData = [c.get('cvssData') for c in cvs if c.get('cvssData')[0]]
                                        csv = CvssMetricV2.objects.create(**cvssData)
                                        csv.save()
                                        print('csv')
                                        DICnist_rjson = {
                                            'descriptions': descriptions,
                                            'references': references,
                                            'nist_record_id': record_instance,
                                            'CPEServiceID': cpe[0],
                                            'cvssMetricV2_id': csv,
                                            'cpe': cpe,
                                            'service': service
                                        }
                                        DICnist_rjson_out.append(DICnist_rjson)
                                        nist = Vulnerability.objects.create(**DICnist_rjson)
                                        nist.save()
                                    else:
                                        pass
                            else:
                                pass
                        else:
                            pass
                    except Exception as E:
                        print(E)
                        pass
                else:           
                    for vulnerability in Vulnerability.objects.all():
                        if check_totalcpe_in_vulnerability(TOTALCPE, vulnerability):
                            cve = vulnerability.cve
                            cve_id = cve.get('id')
                            references = cve.get('references', [])
                            descriptions = cve.get('descriptions', [])
                            metrics = cve.get('metrics', {})
                            cvs = metrics.get('cvssMetricV2', {})
                            cvssData = cvs.get('cvssData', {})
                            csv = CvssMetricV2.objects.create(**cvssData)
                            csv.save()
                            DICnist_rjson = {
                                'descriptions': descriptions,
                                'references': references,
                                'nist_record_id': record_instance,
                                'CPEServiceID': cpe[0],
                                'cvssMetricV2_id': csv,
                                'cpe': cpe,
                                'service': service
                            }
                            DICnist_rjson_out.append(DICnist_rjson)
                            nist = Vulnerability.objects.create(**DICnist_rjson)
                            nist.save()
        return JsonResponse({"message": f"Data {len(customer_records['customerrecords'])} proces{DICnist_rjson_out}sed.{out}"})

@login_required
def create_ego_agent(request):
    if request.method == 'POST':
        form = EGOAgentForm(request.POST)
        if form.is_valid():
            form.save()
            return HttpResponseRedirect('/EgoControlBoard/agent')  # Redirect to a page showing all EGOAgents
        else:
            print(form.errors)  # Print form validation errors
    else:
        data = EGOAgent.objects.all()
        form = EGOAgentForm()
        return TemplateResponse(request, 'EgoControl/create_ego_agent.html', {'form': form, "data": data})



@login_required
def delete_ego_agent(request, pk):
    print('here')
    ego_agent = get_object_or_404(EGOAgent, pk=pk)
    if request.method == 'GET':
        ego_agent.delete()
    return HttpResponseRedirect('/EgoControlBoard/agent')

def EgoControlFormViews(request):
    response = EgoControl.objects.all()
    customers = Customers.objects.all()
    return TemplateResponse(request, 'EgoControl/EgoControlBoards.html', {"controls": response, "customers": customers})


class BaseView:
    authentication_classes = [BearerTokenAuthentication]
    permission_classes = [IsAuthenticated]

class GnawControlCreateViewSet(BaseView, generics.ListCreateAPIView):
    serializer_class = GnawControlSerializer
    queryset = GnawControl.objects.all()

class GnawControlViewSet(BaseView, generics.RetrieveUpdateDestroyAPIView):
    serializer_class = GnawControlSerializer
    queryset = GnawControl.objects.all()

class ThreatModelingCreateViewSet(BaseView, generics.CreateAPIView):
    serializer_class = ThreatModelingSerializer
    queryset = ThreatModeling.objects.all()

class ThreatModelingListViewSet(BaseView, generics.ListAPIView):
    serializer_class = ThreatModelingSerializer
    queryset = ThreatModeling.objects.all()

class ThreatModelingViewSet(BaseView, generics.RetrieveUpdateDestroyAPIView):
    serializer_class = ThreatModelingSerializer
    queryset = ThreatModeling.objects.all()

class PythonMantisListViewSet(BaseView, generics.ListAPIView):
    serializer_class = PythonMantisSerializer
    queryset = PythonMantis.objects.all()

class PythonMantisCreateViewSet(BaseView, generics.CreateAPIView):
    serializer_class = PythonMantisSerializer
    queryset = PythonMantis.objects.all()

class PythonMantisViewSet(BaseView, generics.RetrieveUpdateDestroyAPIView):
    serializer_class = PythonMantisSerializer
    queryset = PythonMantis.objects.all()

#class VulnCardListViewSet(BaseView, generics.ListCreateAPIView):
#    serializer_class = VulnCardSerializer
#    queryset = VulnCard.objects.all()

#class VulnCardViewSet(BaseView, generics.RetrieveUpdateDestroyAPIView):
#    serializer_class = VulnCardSerializer
#    queryset = VulnCard.objects.all()

class FoundVulnCreateViewSet(BaseView, generics.CreateAPIView):
    serializer_class = FoundVulnSerializer
    queryset = FoundVuln.objects.all()

class FoundVulnListViewSet(BaseView, generics.ListAPIView):
    serializer_class = FoundVulnSerializer
    queryset = FoundVuln.objects.all()

class FoundVulnViewSet(BaseView, generics.RetrieveUpdateDestroyAPIView):
    serializer_class = FoundVulnSerializer
    queryset = FoundVuln.objects.all()

class FoundVulnDetailCreateViewSet(BaseView, generics.CreateAPIView):
    serializer_class = FoundVulnDetailSerializers
    queryset = FoundVuln.objects.all()

class FoundVulnDetailListViewSet(BaseView, generics.ListAPIView):
    serializer_class = FoundVulnDetailSerializers
    queryset = FoundVuln.objects.all()

class FoundVulnDetailViewSet(BaseView, generics.RetrieveUpdateDestroyAPIView):
    serializer_class = FoundVulnDetailSerializers
    queryset = FoundVuln.objects.all()

class TotalFoundVulnCreateViewSet(BaseView, generics.CreateAPIView):
    serializer_class = TotalFoundVulnSeerializers
    queryset = FoundVuln.objects.all()

class TotalFoundVulnListViewSet(BaseView, generics.ListAPIView):
    serializer_class = TotalFoundVulnSeerializers
    queryset = FoundVuln.objects.all()

class TotalFoundVulnViewSet(BaseView, generics.RetrieveUpdateDestroyAPIView):
    serializer_class = TotalFoundVulnSeerializers
    queryset = FoundVuln.objects.all()

class ThreatModelingListViewSet(BaseView, generics.ListCreateAPIView):
    serializer_class = ThreatModelingSerializer
    queryset = ThreatModeling.objects.all()

class ThreatModelingViewSet(BaseView):
    serializer_class =ThreatModelingSerializer
    queryset = ThreatModeling.objects.all()
    
class TemplatesListViewSet(BaseView, generics.ListAPIView):
    serializer_class = TemplatesSerializer
    queryset = Template.objects.all()

class TemplatesViewSet(BaseView, generics.RetrieveUpdateDestroyAPIView):
    serializer_class = TemplatesSerializer
    queryset = Template.objects.all()
    
class TemplatesCreateViewSet(BaseView, generics.CreateAPIView):
    serializer_class = TemplatesSerializer
    queryset = Template.objects.all()

class WordListGroupListViewSet(BaseView,generics.ListAPIView):
    serializer_class = WordListGroupSerializer
    queryset = WordListGroup.objects.all()
    
class WordListGroupCreateViewSet(BaseView,generics.CreateAPIView):
    serializer_class = WordListGroupSerializer
    queryset = WordListGroup.objects.all()

class WordListGroupUpdateViewSet(BaseView, generics.RetrieveUpdateDestroyAPIView):
    serializer_class = WordListGroupSerializer
    queryset = WordListGroup.objects.all()

class WordListListViewSet(BaseView, generics.ListAPIView):
    serializer_class = WordListSerializer
    queryset = WordList.objects.all()
    
class WordListCreateViewSet(BaseView, generics.CreateAPIView):
    serializer_class = WordListSerializer
    queryset = WordList.objects.all()

class WordListUpdateViewSet(BaseView, generics.RetrieveUpdateDestroyAPIView):
    serializer_class = WordListSerializer
    queryset = WordList.objects.all()

class DirectoryListViewSet(BaseView, generics.ListAPIView):
    serializer_class = DirectoryListingWordListSerializer
    queryset = WordListGroup.objects.all()

class DirectoryViewSet(BaseView, generics.RetrieveUpdateDestroyAPIView):
    serializer_class = DirectoryListingWordListSerializer
    queryset = WordListGroup.objects.all()

class NmapListViewSet(BaseView, generics.ListAPIView):
    serializer_class = NmapSerializer
    queryset = Nmap.objects.all()

class NmapCreateViewSet(BaseView, generics.CreateAPIView):
    serializer_class = NmapSerializer
    queryset = Nmap.objects.all()

class NmapViewSet(BaseView, generics.RetrieveUpdateDestroyAPIView):
    serializer_class = NmapSerializer
    queryset = Nmap.objects.all()

class CredentialsListViewSet(BaseView, generics.ListAPIView):
    serializer_class = CredentialsSerializer
    queryset = Credential.objects.all()

class CredentialsCreateViewSet(BaseView, generics.CreateAPIView):
    serializer_class = CredentialsSerializer
    queryset = Credential.objects.all()

class CredentialsViewSet(BaseView, generics.RetrieveUpdateDestroyAPIView):
    serializer_class = CredentialsSerializer
    queryset = Credential.objects.all()

class RequestMetaDataListViewSet(BaseView, generics.ListAPIView):
    serializer_class = RequestMetaDataSerializer
    queryset = RequestMetaData.objects.all()

class RequestMetaDataCreateViewSet(BaseView, generics.CreateAPIView):
    serializer_class = RequestMetaDataSerializer
    queryset = RequestMetaData.objects.all()

class RequestMetaDataViewSet(BaseView, generics.RetrieveUpdateDestroyAPIView):
    serializer_class = RequestMetaDataSerializer
    queryset = RequestMetaData.objects.all()

class CertificateRecordsListViewSet(BaseView, generics.ListAPIView):
    serializer_class = CertificateSerializer
    queryset = Certificate.objects.all()

class CertificateRecordsCreateViewSet(BaseView, generics.CreateAPIView):
    serializer_class = CertificateSerializer
    queryset = Certificate.objects.all()

class CertificateRecordsViewSet(BaseView, generics.RetrieveUpdateDestroyAPIView):
    serializer_class = CertificateSerializer
    queryset = Certificate.objects.all()

class DNSQueryRecordsListViewSet(BaseView, generics.ListCreateAPIView):
    serializer_class = DNSQuerySerializer
    queryset = DNSQuery.objects.all()

class DNSQueryRecordsViewSet(BaseView, generics.RetrieveUpdateDestroyAPIView):
    serializer_class = DNSQuerySerializer
    queryset = DNSQuery.objects.all()

class DNSAuthRecordsListViewSet(BaseView, generics.ListCreateAPIView):
    serializer_class = DNSAuthoritySerializer
    queryset = DNSAuthority.objects.all()

class DNSAuthRecordsViewSet(BaseView, generics.RetrieveUpdateDestroyAPIView):
    serializer_class = DNSAuthoritySerializer
    queryset = DNSAuthority.objects.all()

class NucleiRecordsListViewSet(BaseView, generics.ListCreateAPIView):
    serializer_class = NucleiSerializer
    queryset = Nuclei.objects.all()

class NucleiRecordsViewSet(BaseView, generics.RetrieveUpdateDestroyAPIView):
    serializer_class = NucleiSerializer
    queryset = Nuclei.objects.all()

class RecordsCreateViewSet(BaseView, generics.CreateAPIView):
    serializer_class = RecordSerializer
    queryset = Record.objects.all()

class RecordsListViewSet(BaseView, generics.ListAPIView):
    serializer_class = RecordSerializer
    queryset = Record.objects.all()

class RecordsViewSet(BaseView, generics.RetrieveUpdateDestroyAPIView):
    serializer_class = RecordSerializer
    queryset = Record.objects.all()

class TotalRecordsViewSet(BaseView, generics.RetrieveUpdateDestroyAPIView):
    serializer_class = TotalRecords
    queryset = Record.objects.all()

class CustomersCreateViewSet(BaseView, generics.CreateAPIView):
    serializer_class = CustomerSerializer
    queryset = Customers.objects.all()

class CustomersRetrieveLimitedViewSet(generics.RetrieveUpdateDestroyAPIView):
    serializer_class = limitedCustomerSerializer
    queryset = Customers.objects.all()

class CustomersListViewSet(BaseView, generics.ListAPIView):
    serializer_class = limitedCustomerSerializer
    queryset = Customers.objects.all()

#class vulncardListCreateViewSet(BaseView, generics.ListCreateAPIView):
#    serializer_class = VulnCardSerializer
#    queryset = VulnCard.objects.all()
    
#class vulncardRetrieveViewSet(BaseView, generics.RetrieveUpdateDestroyAPIView):
#    serializer_class = VulnCardSerializer
#    queryset = VulnCard.objects.all()

class CustomersViewSet(generics.RetrieveUpdateDestroyAPIView):
    serializer_class = CustomerRecordSerializer
    queryset = Customers.objects.all()

class apiCreateViewSet(BaseView, generics.CreateAPIView):
    serializer_class = apiSerialiser
    queryset = api.objects.all()

class apiListViewSet(BaseView, generics.ListAPIView):
    serializer_class = apiSerialiser
    queryset = api.objects.all()

class apiRetrieveViewSet(BaseView, generics.RetrieveUpdateDestroyAPIView):
    serializer_class = apiSerialiser
    queryset = api.objects.all()

class apiproviderCreateViewSet(BaseView, generics.CreateAPIView):
    serializer_class = apiprovidersSerialiser
    queryset = apiproviders.objects.all()

class apiproviderListViewSet(BaseView, generics.ListAPIView):
    serializer_class = apiprovidersSerialiser
    queryset = apiproviders.objects.all()

class apiproviderRetrieveViewSet(BaseView, generics.RetrieveUpdateDestroyAPIView):
    serializer_class = apiprovidersSerialiser
    queryset = apiproviders.objects.all()
    
class apiprovidersRetrieveViewSet(BaseView, generics.RetrieveUpdateDestroyAPIView):
    serializer_class = apiProviderApisSerialiser
    queryset = apiproviders.objects.all()

class apiprovidersCreateViewSet(BaseView, generics.CreateAPIView):
    serializer_class = apiProviderApisSerialiser
    queryset = apiproviders.objects.all()

class apiprovidersListViewSet(BaseView, generics.ListAPIView):
    serializer_class = apiProviderApisSerialiser
    queryset = apiproviders.objects.all()

class FindingMatrixCreateViewSet(BaseView, generics.CreateAPIView):
    serializer_class = FindingMatrixSerializer
    queryset = FindingMatrix.objects.all()

class FindingMatrixListViewSet(BaseView, generics.ListAPIView):
    serializer_class = FindingMatrixSerializer
    queryset = FindingMatrix.objects.all()

class FindingMatrixRetrieveViewSet(BaseView, generics.RetrieveUpdateDestroyAPIView):
    serializer_class = FindingMatrixSerializer
    queryset = FindingMatrix.objects.all()

class GEOCODESCreateViewSet(BaseView, generics.CreateAPIView):
    serializer_class = GEOCODESerializer
    queryset = GEOCODES.objects.all()

class GEOCODESListViewSet(BaseView, generics.ListAPIView):
    serializer_class = GEOCODESerializer
    queryset = GEOCODES.objects.all()

class GEOCODESRetrieveViewSet(BaseView, generics.RetrieveUpdateDestroyAPIView):
    serializer_class = GEOCODESerializer
    queryset = GEOCODES.objects.all()


class whoisCreateViewSet(BaseView, generics.CreateAPIView):
    serializer_class = Whois_serializers
    queryset = whois.objects.all()

class whoisListViewSet(BaseView, generics.ListAPIView):
    serializer_class = Whois_serializers
    queryset = whois.objects.all()

class whoisRetrieveViewSet(BaseView, generics.RetrieveUpdateDestroyAPIView):
    serializer_class = Whois_serializers
    queryset = whois.objects.all()

class EGOAgentListCreateView(BaseView,generics.ListCreateAPIView):
    queryset = EGOAgent.objects.all()
    serializer_class = EGOAgentSerializer

class EGOAgentRetrieveUpdateDestroyView(BaseView,generics.RetrieveUpdateDestroyAPIView):
    queryset = EGOAgent.objects.all()
    serializer_class = EGOAgentSerializer
    
class EgoControlListViewSet(BaseView, generics.ListAPIView):
    serializer_class = EgoControlSerializer
    queryset = EgoControl.objects.all()

class EgoControlCreateViewSet(BaseView, generics.CreateAPIView):
    serializer_class = EgoControlSerializer
    queryset = EgoControl.objects.all()

class EgoControlViewSet(BaseView, generics.RetrieveUpdateDestroyAPIView):
    serializer_class = EgoControlSerializer
    queryset = EgoControl.objects.all()
    
class MantisControlsListViewSet(BaseView, generics.ListAPIView):
    serializer_class = MantisControlSerializer
    queryset = MantisControls.objects.all()

class MantisControlsCreateViewSet(BaseView, generics.CreateAPIView):
    serializer_class = MantisControlSerializer
    queryset = MantisControls.objects.all()

class MantisControlsViewSet(BaseView, generics.RetrieveUpdateDestroyAPIView):
    serializer_class = MantisControlSerializer
    queryset = MantisControls.objects.all()
    
class MantisControlsListViewSet(BaseView, generics.ListAPIView):
    serializer_class = MantisControlSerializer
    queryset = MantisControls.objects.all()

class MantisControlsCreateViewSet(BaseView, generics.CreateAPIView):
    serializer_class = MantisControlSerializer
    queryset = MantisControls.objects.all()

class MantisControlsViewSet(BaseView, generics.RetrieveUpdateDestroyAPIView):
    serializer_class = MantisControlSerializer
    queryset = MantisControls.objects.all()
    


class BucketValidationListViewSet(BaseView, generics.ListAPIView):
    """
    ViewSet for listing all BucketValidation instances.
    """
    serializer_class = BucketValidationSerializer
    queryset = BucketValidation.objects.all()

class BucketValidationCreateViewSet( generics.CreateAPIView):
    """
    ViewSet for creating a new BucketValidation instance.
    """
    serializer_class = BucketValidationSerializer
    queryset = BucketValidation.objects.all()

class BucketValidationViewSet( generics.RetrieveUpdateDestroyAPIView):
    """
    ViewSet for retrieving, updating, or deleting a BucketValidation instance.
    """
    serializer_class = BucketValidationSerializer
    queryset = BucketValidation.objects.all()
