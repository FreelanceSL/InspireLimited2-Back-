from django.core.mail import send_mail
from django.core.mail import EmailMessage
import random
from django.contrib.sites.shortcuts import get_current_site
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from django.contrib.auth.tokens import default_token_generator
from django.conf import settings
from .models import User


def send_otp_via_email(request,user):
    subject =f'Welcome to InspireLimited {user.first_name} !'
    otp=str(random.randint(1000, 9999))
    user.otp=otp
    user.save()
    message=f'Your account verification code is :{otp} '
    email_from= settings.DEFAULT_FROM_EMAIL
    
    send_mail(subject,message,email_from,[user.email])
    user_obj=User.objects.get(email=user.email)

def send_reset_password(request,user):
    subject ='Hello {user.last_name} !'
    id=urlsafe_base64_encode(force_bytes(user.pk))
    domain="localhost:8000"
    token= default_token_generator.make_token(user)
    print(token)
    message=f'Your reset password link : http://{domain}/api/reset/{id}/{token}/'
    email_from= settings.DEFAULT_FROM_EMAIL
    
    send_mail(subject,message,email_from,[user.email])
    user_obj=User.objects.get(email=user.email)

from django.core.mail import EmailMessage
from django.conf import settings

def send_infos(request, user):
    subject = 'Hello InspireLimited team, there is a new user who requested an account!'
    message = f"""
    User Infos:
    First Name: {user.first_name}
    Last Name: {user.last_name}
    Email: {user.email}
    Phone: {user.phone}
    Country: {user.country}
    """
    
    email_from = settings.DEFAULT_FROM_EMAIL
    recipient_list = ["haddarskander50@gmail.com"]

    email = EmailMessage(subject, message, email_from, recipient_list)

    if user.image:
        
        email.attach(user.image.name, user.image.read())

   
    email.send()

   
    user_obj = User.objects.get(email=user.email)
