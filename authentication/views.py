from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.http import JsonResponse
from rest_framework.decorators import api_view,permission_classes
from rest_framework.views import APIView
from .serializers import UserSerializer,VerificationSerializer
from rest_framework.response import Response
from .models import User
from rest_framework.exceptions import AuthenticationFailed
from .emails import send_otp_via_email, send_reset_password
from rest_framework import status
from django.contrib.auth.tokens import default_token_generator
from rest_framework.permissions import IsAuthenticated
from .models import FileUpload
import base64
import json
from django.shortcuts import render, redirect
from rest_framework_simplejwt.tokens import AccessToken
from django.contrib.auth import authenticate, login
from django.contrib.auth.decorators import login_required
# Create your views here.


class Register(APIView):
    def get_permissions(self):
        if self.request.method == 'GET':
            return [IsAuthenticated()]
        return super().get_permissions()  
    def post(self, request):
        try:
            data = request.data
            serializer = UserSerializer(data=data)
            if serializer.is_valid():
                serializer.save()
                user=User.objects.get(email=serializer.data['email'])
                send_otp_via_email(request,user)
                return Response({
                    'status': 200,
                    'message': 'Registration successful, check email for OTP',
                    'data': serializer.data
                })
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
    def get(self, request):
        try:
            users = User.objects.all()
            serializer = UserSerializer(users, many=True)  # Use many=True for multiple objects
            return Response({
                "users": serializer.data  # Use serializer.data to get serialized output
            })
        except Exception as e:
            print(e)
            return Response({
                'status': 500,
                'message': 'Internal server error'
            })

class Verification(APIView):
    def post(self,request):
        email=request.data['email']
        otp=request.data['otp']
        try:
            user =User.objects.get(email=email)
            serializer=VerificationSerializer(user)


        except User.DoesNotExist:
            return Response({'error':'User with this email does not exist.'},status=status.HTTP_404_NOT_FOUND)
        if serializer.data['otp'] == otp:
            user.is_verified=True
            user.otp=""
            user.save()

            return Response(serializer.data,status=status.HTTP_201_CREATED)
        return Response({"message":"otp invalid"},status=status.HTTP_403_FORBIDDEN)
        
       
        
class Login(APIView):
    def get(self,request):
        return render(request, 'login.html')
    
    def post(self, request):
        email = request.POST.get('email')
        password = request.POST.get('password')
        user = authenticate(request, email=email, password=password)

        if user is not None:
            login(request, user)
            token = AccessToken.for_user(user)
            request.session['access_token'] = str(token)

            # Redirect to `next` if it exists; otherwise, go to dashboard
            next_url = request.GET.get('next', 'dashboard')
            return redirect(next_url)
        else:
            return render(request, 'login.html', {'error': 'Invalid credentials'})

    
def logout(request):
    request.session.flush() 
    return redirect('index')

class FileUploadView(APIView):
    permission_classes = [IsAuthenticated] 

    def post(self, request):
    
        file_data = request.FILES.get('file_data')  
        file_name = request.data.get('file_name')  
        
        if file_data is None or file_name is None:
            return Response({"error": "File data and file name are required."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            file_data_read = file_data.read()  
            

            file_instance = FileUpload(
                user=request.user,  
                file_name=file_name,
                file_data=file_data_read
            )
            file_instance.save()  
            
            return Response({"message": "File uploaded successfully."}, status=status.HTTP_201_CREATED)
        
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

def send_password_reset_email(request,user):
    send_reset_password(request,user)
    
@api_view(['POST'])  
def forget_password(request):
    if request.method == 'POST':
        email= request.data['email']
        if User.objects.filter(email=email).exists():
            user=User.objects.get(email__exact=email)
            print("haha")
            send_password_reset_email(request,user)
            data={"message":'Password reset link has been sent to you email adress.'}
            return JsonResponse(data,status=200)
        else :
            data={"message":'Account does not exist'}
            return JsonResponse(data,status=404)
    
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


    

@api_view(['GET'])
@login_required(login_url='/api/login/')
def dashboard(request):
    token = request.session.get('access_token', None)
    return render(request, 'dashboard.html', {'token': token})
