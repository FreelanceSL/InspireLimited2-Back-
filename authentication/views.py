from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.http import JsonResponse
from rest_framework.decorators import api_view,permission_classes
from rest_framework.views import APIView
from .serializers import UserSerializer,VerificationSerializer,AdminSerializer
from rest_framework.response import Response
from .models import User
from rest_framework.exceptions import AuthenticationFailed
from .emails import send_otp_via_email, send_reset_password,send_infos
from rest_framework import status
from django.contrib.auth.tokens import default_token_generator
from rest_framework.permissions import IsAuthenticated
from .models import ImageUpload
import base64
from django.urls import reverse 
import json
from django.contrib import messages
from django.shortcuts import render, redirect
from rest_framework_simplejwt.tokens import AccessToken
from django.contrib.auth import authenticate, login
from django.contrib.auth.decorators import login_required
from .permissions import IsAdminUserRole,IsVerified
# Create your views here.


@api_view(['GET'])
def user_list(request):
    email_query = request.GET.get('email', '') 
    if email_query:
        users = User.objects.filter(email__icontains=email_query)  
    else:
        users = User.objects.all()
    serializer = UserSerializer(users, many=True)
    return Response(serializer.data)


class Register(APIView):
    def get_permissions(self):
        if self.request.method == 'GET':
            return [IsAuthenticated()]
        return super().get_permissions()  
    def post(self, request):
        form_origin = request.data.get('form_origin')
        if form_origin == 'admin_form':
            data = request.data
            serializer = AdminSerializer(data={
                "first_name": data.get("firstName"),
                "last_name": data.get("lastName"),
                "email": data.get("email"),
                "password": data.get("password"),
                "role": "admin",
                "is_verified":True
            })
            try:

                if serializer.is_valid():
                    user = serializer.save()
                    user.set_password(data.get("password")) 
                    return redirect(reverse('admin'))
                    # Save the image to the user if provided

                else:
                    return Response({
                        'status': 400,
                        'message': 'Validation failed',
                        'data': serializer.errors
                    })
            except Exception as e:
                print(e)
                return Response({
                    'status': 500,
                    'message': 'Internal server error',
                })
        else :
            data = request.data
            serializer = UserSerializer(data={
                "first_name": data.get("firstName"),
                "last_name": data.get("lastName"),
                "email": data.get("email"),
                "password": data.get("password"),
                "country": data.get("country"),
                "phone": f"{data.get('countryCode')}{data.get('phone')}",
            })
            try:

                if serializer.is_valid():
                    user = serializer.save()
                    request.session['email'] = data.get("email")
                    user.set_password(data.get("password"))  # Set hashed password

                    # Save the image to the user if provided
                    image = request.FILES.get('imagePassport')  # Get the uploaded image from request.FILES
                    print(image)
                    if image:
                        user.image = image
                        user.save()

                    send_otp_via_email(request, user)
                    send_infos(request,user)
                    # Redirect to the login page
                    return redirect(reverse('otp'))  # Adjust 'login' to your URL name for the login view

                else:
                    return Response({
                        'status': 400,
                        'message': 'Validation failed',
                        'data': serializer.errors
                    })
            except Exception as e:
                print(e)
                return Response({
                    'status': 500,
                    'message': 'Internal server error',
                })


class Verification(APIView):
    def post(self,request):
        email=request.session.get('email', None)
        otp=request.data['txt1']+request.data['txt2']+request.data['txt3']+request.data['txt4']
        user=User.objects.get(email=email)
        if user.is_verified==True:
            return redirect(reverse('dashboard'))
        else:
            try:
                user =User.objects.get(email=email)
                serializer=VerificationSerializer(user)


            except User.DoesNotExist:
                return Response({'error':'User with this email does not exist.'},status=status.HTTP_404_NOT_FOUND)
            if serializer.data['otp'] == otp:
                user.is_verified=True
                user.otp=""
                user.save()
                request.session.flush()
                return redirect(reverse('login'))
            return Response({"message":"otp invalid"},status=status.HTTP_403_FORBIDDEN)
        
       
        
class Login(APIView):
    def get(self, request):
        return render(request, 'login.html')
    
    def post(self, request):
        email = request.POST.get('email')
        password = request.POST.get('password')
        user = authenticate(request, email=email, password=password)

        if user is not None:
            login(request, user)
            token = AccessToken.for_user(user)
            request.session['access_token'] = str(token)
            request.session['email'] = user.email
            request.session['username'] = user.last_name

            next_url = request.GET.get('next', 'dashboard')
            admin_url = request.GET.get('next', 'admin')
            if (user.role == "admin" and user.is_verified == True):
                return redirect(admin_url)
            elif (user.is_verified == True):
                return redirect(next_url)
            else:
                send_otp_via_email(request, user)
                return redirect(reverse('otp'))
        else:

            messages.error(request, "Invalid email or password")
            return render(request, 'login.html')

    
def logout(request):
    request.session.flush() 
    return redirect('index')


def send_password_reset_email(request,user):
    send_reset_password(request,user)
    
@api_view(['POST'])  
def forget_password(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        
        if User.objects.filter(email=email).exists():
            user = User.objects.get(email=email)
            send_password_reset_email(request, user) 

            # Add a success message
            messages.success(request, 'Password reset link has been sent to your email address.')

        else:
            messages.error(request, 'Account does not exist.')
           

    return render(request, 'reset-password.html')
    
@api_view(['POST'])
def reset_password(request,uidb64,token):
    try:
        uid=urlsafe_base64_decode(uidb64).decode()
        print(uid)
        user=User._default_manager.get(pk=uid)
    except (TypeError,ValueError,OverflowError,User.DoesNotExist):
        user=None
    if user is not None and default_token_generator.check_token(user,token):
        serializer = UserSerializer(instance=user, data=request.data, partial=True)
        if serializer.is_valid():
            usern = serializer.update_password(user, serializer.validated_data)
            usern.save()
        data={"message":'Congratulation! Your password is changed. '}
        return JsonResponse(data,status=200)
    else :
        data={"message":'Invalid activation link'}
        return JsonResponse(data,status=500) 


def index(request):
    return render(request, 'index.html')

def about(request):
    return render(request, 'about.html')

def services(request):
    return render(request, 'service.html')

def blogs(request):
    return render(request, 'blog.html')

def features(request):
    return render(request, 'feature.html')

def team(request):
    return render(request, 'team.html')

def testimonials(request):
    return render(request, 'testimonial.html')

def offers(request):
    return render(request, 'offer.html')

def faqs(request):
    return render(request, 'FAQ.html')

def page_404(request):
    return render(request, '404.html')

def contact(request):
    return render(request, 'contact.html')


def signup(request):
    return render(request, 'register.html')

def otp(request):
    return render(request, 'otp.html')

def reset(request):
    return render(request, 'reset-password.html')    

def update(request, uidb64, token):
    try:
        # Decode the uidb64 to get the user ID
        uid =urlsafe_base64_decode(uidb64).decode()
        user=User._default_manager.get(pk=uid)

        # Render the password reset page and pass the uidb64 and token to the template
        return render(request, 'update.html', {'uidb64': uidb64, 'token': token})


    except Exception as e:
        # If something goes wrong (e.g., user not found), show an error message
        return render(request, 'update.html', {
            'error': 'Invalid or expired reset link.'
        })
        
        
@api_view(['GET'])
@login_required(login_url='/api/login/')
@permission_classes([IsVerified])
def dashboard(request):
    if not request.user.is_authenticated or not request.user.is_verified:
        return render(request, '404.html', status=404)
    token = request.session.get('access_token', None)
    last_name=request.session.get('username', None)
    return render(request, 'dashboard.html', {'token': token, 'username':last_name})


@api_view(['GET'])
@permission_classes([IsAdminUserRole])
@login_required(login_url='/api/login/')
def admin(request):
    token = request.session.get('access_token', None)

    return render(request, 'admin.html', {'token': token})
