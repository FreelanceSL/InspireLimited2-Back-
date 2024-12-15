from django.core.mail import send_mail
from django.core.mail import EmailMessage
import random
from django.contrib.sites.shortcuts import get_current_site
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from django.contrib.auth.tokens import default_token_generator
from django.conf import settings
from .models import User
from django.core.mail import EmailMessage
from django.conf import settings

def send_otp_via_email(request, user):
    import random
    from django.core.mail import send_mail
    from django.conf import settings
    
    subject = 'Verify Your Account - Inspire Trade'
    otp = str(random.randint(1000, 9999))
    user.otp = otp
    user.save()
    
    message = f"""
    Dear {user.first_name} {user.last_name},

    Thank you for registering with Inspire Trade!

    To complete your registration, please use the One-Time Password (OTP) below to verify your account: 

    Your account verification code is: {otp}

    This code is valid for the next 15 minutes. If you did not initiate this request, please ignore this email or contact our support team immediately.

    For assistance, feel free to reach us at support@inspiretrade.com.

    Welcome aboard!

    The Inspire Trade Team

    Disclaimer: This is an automated email. Please do not reply directly to this message.
    """
    
    email_from = settings.DEFAULT_FROM_EMAIL
    send_mail(subject, message, email_from, [user.email])


def send_reset_password(request,user):
    subject =f'Hello {user.last_name} {user.first_name}  !'
    id=urlsafe_base64_encode(force_bytes(user.pk))
    domain="www.inspire-trade.com"
    token= default_token_generator.make_token(user)
    message=f'Your reset password link : https://{domain}/api/reset/{id}/{token}/'
    email_from= settings.DEFAULT_FROM_EMAIL
    
    send_mail(subject,message,email_from,[user.email])
    user_obj=User.objects.get(email=user.email)


def send_reset_password_ar(request,user):
    subject =f'Hello {user.last_name} {user.first_name} !'
    id=urlsafe_base64_encode(force_bytes(user.pk))
    domain="www.inspire-trade.com"
    langue="arabic"
    token= default_token_generator.make_token(user)
    message=f'link : https://{domain}/api/reset/{id}/{token}/{langue}/'
    print(message)
    email_from= settings.DEFAULT_FROM_EMAIL
    
    send_mail(subject,message,email_from,[user.email])
    user_obj=User.objects.get(email=user.email)


def send_infos(request, user):
    subject = 'Hello InspireTrade team, there is a new user who requested an account!'
    message = f"""
    User Infos:
    First Name: {user.first_name}
    Last Name: {user.last_name}
    Email: {user.email}
    Phone: {user.phone}
    Country: {user.country}
    """
    
    email_from = settings.DEFAULT_FROM_EMAIL
    recipient_list = ["contact@inspire-limited.com"]

    email = EmailMessage(subject, message, email_from, recipient_list)

    if user.image:
        
        email.attach(user.image.name, user.image.read())

   
    email.send()

   
    user_obj = User.objects.get(email=user.email)


def send_infos_trade(request, user,asset,platform,ammount):
    subject = 'Hello InspireTrade team, there is a new user who will trade with this infos!'
    message = f"""
    User Infos:
    First Name: {user.first_name}
    Last Name: {user.last_name}
    Email: {user.email}
    Trading asset :{asset}
    platform: {platform}
    ammount :{ammount}

    """
    
    email_from = settings.DEFAULT_FROM_EMAIL
    recipient_list = ["contact@inspire-trade.com"]

    email = EmailMessage(subject, message, email_from, recipient_list)
    email.send()
