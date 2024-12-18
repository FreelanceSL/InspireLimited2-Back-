from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.http import JsonResponse
from rest_framework.decorators import api_view,permission_classes
from rest_framework.views import APIView
from .serializers import UserSerializer,VerificationSerializer,AdminSerializer
from rest_framework.response import Response
from .models import User
from rest_framework.exceptions import AuthenticationFailed
from .emails import send_otp_via_email, send_reset_password,send_infos,send_infos_trade,send_reset_password_ar
from rest_framework import status
from django.contrib.auth.tokens import default_token_generator
from rest_framework.permissions import IsAuthenticated
from .models import ImageUpload
import base64
from django.urls import reverse 
import json
import requests
from django.contrib import messages
from django.shortcuts import render, redirect
from rest_framework_simplejwt.tokens import AccessToken
from django.contrib.auth import authenticate, login
from django.contrib.auth.decorators import login_required
from .permissions import IsAdminUserRole,IsVerified
from rest_framework import pagination
from django.core.paginator import Paginator
# Create your views here.


class CustomPagination(pagination.PageNumberPagination):
    page_size = 10
    page_size_query_param = 'per_page'
    max_page_size = 100

    def get_paginated_response(self, data):
        return Response({
            'count': self.page.paginator.count,
            'total_pages': self.page.paginator.num_pages,
            'current_page': self.page.number,
            'results': data
        })

@api_view(['GET'])
def user_list(request):
    email_query = request.GET.get('email', '')
    per_page = int(request.GET.get('per_page', 10))
    
    if email_query:
        users = User.objects.filter(email__icontains=email_query)
    else:
        users = User.objects.all()
        
    paginator = CustomPagination()
    paginator.page_size = per_page
    result_page = paginator.paginate_queryset(users, request)
    serializer = UserSerializer(result_page, many=True)
    
    return paginator.get_paginated_response(serializer.data)


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
                    user.set_password(data.get("password"))  

                    image = request.FILES.get('imagePassport') 
                    print(image)
                    if image:
                        user.image = image
                        user.save()

                    send_otp_via_email(request, user)
                    send_infos(request,user)
                    if(form_origin=="register_arabe"):
                        return redirect(reverse('otp_ar'))
                    return redirect(reverse('otp'))  

                else:
                    
                    messages.error(request, 'An account with this email already exists.')
                    if(form_origin=="register_arabe"):
                        return render(request,'register_ar.html')
                    return render(request,'register.html')
                    
                    
            except Exception as e:
                print(e)
                return Response({
                    'status': 500,
                    'message': 'Internal server error',
                })

@api_view(['POST'])  
def resend_otp(request):
    email=request.session.get('email', None)
    user=User.objects.get(email=email)
    send_otp_via_email(request, user)
    return render(request,'otp.html')


@api_view(['POST'])  
def resend_otp_ar(request):
    email=request.session.get('email', None)
    user=User.objects.get(email=email)
    send_otp_via_email(request, user)
    return render(request,'otp_ar.html')


class Verification(APIView):
    def post(self,request):
        form_origin = request.data.get('form_origin')
        email=request.session.get('email', None)
        otp=request.data['txt1']+request.data['txt2']+request.data['txt3']+request.data['txt4']
        user=User.objects.get(email=email)
        if user.is_verified==True:
            if form_origin=="otp_arabe" :
                return redirect(reverse('dashboard_ar'))
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
                if form_origin=="otp_arabe" :
                    return redirect(reverse('login_ar'))
                return redirect(reverse('login'))
            else :
                messages.error(request, "Incorrect otp code !")
                return render(request, 'otp.html')
        
       
        
class Login(APIView):
    def get(self, request):
        return render(request, 'login.html')
    
    def post(self, request):
        email = request.POST.get('email')
        password = request.POST.get('password')
        user = authenticate(request, email=email, password=password)
        form_origin = request.data.get('form_origin')
        if user is not None:
            login(request, user)
            token = AccessToken.for_user(user)
            request.session['access_token'] = str(token)
            request.session['email'] = user.email
            request.session['first_name'] = user.first_name
            request.session['last_name'] = user.last_name

            next_url = request.GET.get('next', 'dashboard')
            next_url_ar = request.GET.get('next', 'dashboard_ar')
            admin_url = request.GET.get('next', 'admin')
            if (user.role == "admin" and user.is_verified == True):
                return redirect(admin_url)
            elif (user.is_verified == True):
                if form_origin=="arabic_login" :
                    return redirect(next_url_ar)
                return redirect(next_url)
            else:
                send_otp_via_email(request, user)
                if form_origin=="arabic_login" :
                    return redirect(reverse('otp_ar'))
                return redirect(reverse('otp'))
        else:

            messages.error(request, "Invalid email or password")
            if(form_origin=="arabic_login"):
                return render(request,'login_ar.html')
            return render(request, 'login.html')

    
def logout(request):
    request.session.flush() 
    return redirect('index')

def logout_ar(request):
    request.session.flush() 
    return redirect('index_ar')


def send_password_reset_email(request,user):
    send_reset_password(request,user)
    
@api_view(['POST'])  
def forget_password(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        form_origin = request.data.get('form_origin')
        if User.objects.filter(email=email).exists():
            user = User.objects.get(email=email)
            if form_origin=="reset_arabe":
                print("yeeeeeeeeees")
                send_reset_password_ar(request, user)
            send_password_reset_email(request, user) 

            # Add a success message
            if form_origin=="reset_arabe":
                messages.success(request, 'تم إرسال رابط إلى عنوان بريدك الإلكتروني.')
            else :
                messages.success(request, 'Password reset link has been sent to your email address.')

        else:
            if form_origin=="reset_arabe":
                messages.error(request, 'الحساب غير موجود.')
            else :
                messages.error(request, 'Account does not exist.')
           
    if form_origin=="reset_arabe":
        return render(request, 'reset-password_ar.html')
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
    
    
@api_view(['POST'])
def reset_password_ar(request,uidb64,token,langue):
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
        data={"message":'تهانينا! تم تغيير كلمة المرور '}
        return JsonResponse(data,status=200)
    else :
        data={"message":'رابط التفعيل غير صالح'}
        return JsonResponse(data,status=500) 


def index(request):
    return render(request, 'index.html' ,{'langue':'AR','url_lang': reverse('index_ar')})

def about(request):
    return render(request, 'about.html',{'langue':'AR','url_lang': reverse('about_ar')})

def services(request):
    return render(request, 'service.html',{'langue':'AR','url_lang': reverse('services_ar')})

def blogs(request):
    return render(request, 'blog.html',{'langue':'AR','url_lang': reverse('blogs_ar')})


def page_404(request):
    return render(request, '404.html')

def contact(request):
    return render(request, 'contact.html',{'langue':'AR','url_lang': reverse('contact_ar')})

def qstart(request):
    return render(request, 'qstart.html',{'langue':'AR','url_lang': reverse('qstart_ar')})

def signup(request):
    return render(request, 'register.html')

def otp(request):
    return render(request, 'otp.html')

def reset(request):
    return render(request, 'reset-password.html')  

def index_ar(request):
    return render(request, 'index_ar.html',{'langue':'ENG','url_lang': reverse('index')})

def about_ar(request):
    return render(request, 'about_ar.html',{'langue':'ENG','url_lang': reverse('about')})

def services_ar(request):
    return render(request, 'service_ar.html',{'langue':'ENG','url_lang': reverse('services')})

def contact_ar(request):
    return render(request, 'contact_ar.html',{'langue':'ENG','url_lang': reverse('contact')})

def blogs_ar(request):
    return render(request, 'blog_ar.html',{'langue':'ENG','url_lang': reverse('blogs')})
def login_ar(request):
    return render(request, 'login_ar.html')
def signup_ar(request):
    return render(request, 'register_ar.html')
def qstart_ar(request):
    return render(request, 'qstart_ar.html')

def otp_ar(request):
    return render(request, 'otp_ar.html')

def reset_ar(request):
    return render(request, 'reset-password_ar.html')  

def forex(request):
    return render (request,'forex.html',{'langue':'AR','url_lang': reverse('forex_ar')})


def forex_ar(request):
    return render (request,'forex_ar.html',{'langue':'ENG','url_lang': reverse('forex')})


def crypto(request):
    return render (request,'crypto.html',{'langue':'AR','url_lang': reverse('crypto_ar')})


def crypto_ar(request):
    return render (request,'crypto_ar.html',{'langue':'ENG','url_lang': reverse('crypto')})

def metals(request):
    return render (request,'metals.html',{'langue':'AR','url_lang': reverse('metals_ar')})


def metals_ar(request):
    return render (request,'metals_ar.html',{'langue':'ENG','url_lang': reverse('metals')})

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
        
def update_ar(request, uidb64, token, langue):
    try:
        # Decode the uidb64 to get the user ID
        uid =urlsafe_base64_decode(uidb64).decode()
        user=User._default_manager.get(pk=uid)

        # Render the password reset page and pass the uidb64 and token to the template
        return render(request, 'update_ar.html', {'uidb64': uidb64, 'token': token , 'langue':langue})


    except Exception as e:
        # If something goes wrong (e.g., user not found), show an error message
        return render(request, 'update_ar.html', {
            'error': 'Invalid or expired reset link.'
        })
                

def get_crypto_data():
    try:
        # CoinGecko API endpoint for top 5 cryptocurrencies
        url = "https://api.coingecko.com/api/v3/coins/markets"
        params = {
            "vs_currency": "usd",
            "order": "market_cap_desc",
            "per_page": "5",
            "page": "1",
            "sparkline": "true",
            "price_change_percentage": "1h,24h,7d"
        }
        
        response = requests.get(url, params=params)
        data = response.json()
        
        formatted_data = []
        for coin in data:
            formatted_data.append({
                'rank': coin['market_cap_rank'],
                'name': coin['name'],
                'symbol': coin['symbol'].upper(),
                'price': coin['current_price'],
                'image': coin['image'],
                'price_1h': coin['price_change_percentage_1h_in_currency'],
                'price_24h': coin['price_change_percentage_24h_in_currency'],
                'price_7d': coin['price_change_percentage_7d_in_currency'],
                'volume_24h': coin['total_volume'],
                'market_cap': coin['market_cap'],
                'sparkline': coin['sparkline_in_7d']['price']
            })
        return formatted_data
    except Exception as e:
        print(f"Error fetching data: {e}")
        return []
   
   
   
import requests

def get_precious_metals_data():
    try:
        # Metals API endpoint from World Gold Council
        url = "https://data.gold.org/api/v1/prices"
        params = {
            "metal": "gold,silver",
            "period": "1w"
        }

        response = requests.get(url, params=params)
        data = response.json()

        formatted_data = []
        for metal in data['data']:
            formatted_data.append({
                'name': metal['name'],
                'symbol': metal['symbol'],
                'price': metal['latest']['price'],
                'price_change_1h': metal['latest']['priceChange']['hour'],
                'price_change_24h': metal['latest']['priceChange']['day'],
                'price_change_7d': metal['latest']['priceChange']['week']
            })
        return formatted_data
    except Exception as e:
        print(f"Error fetching data: {e}")
        return []     
    
    
    
        
@api_view(['GET'])
@login_required(login_url='/api/login/')
@permission_classes([IsVerified])
def dashboard(request):
    if not request.user.is_authenticated or not request.user.is_verified:
        return render(request, '404.html', status=404)
    token = request.session.get('access_token', None)
    first_name=request.session.get('first_name', None)
    last_name=request.session.get('last_name', None)
    crypto_data = get_crypto_data()
    # metal_data= get_precious_metals_data()

    return render(request, 'dashboard.html', {'token': token, 'first_name':first_name, 'last_name':last_name,'crypto_data': crypto_data , 'langue':'AR','url_lang': reverse('dashboard_ar')})

@api_view(['GET'])
@login_required(login_url='/api/login/')
@permission_classes([IsVerified])
def dashboard_ar(request):
    if not request.user.is_authenticated or not request.user.is_verified:
        return render(request, '404.html', status=404)
    token = request.session.get('access_token', None)
    first_name=request.session.get('first_name', None)
    last_name=request.session.get('last_name', None)
    crypto_data = get_crypto_data()
    # metal_data= get_precious_metals_data()

    return render(request, 'dashboard_ar.html', {'token': token, 'first_name':first_name, 'last_name':last_name,'crypto_data': crypto_data ,'langue':'ENG','url_lang': reverse('dashboard')}  )


@api_view(['GET'])
@permission_classes([IsAdminUserRole])
@login_required(login_url='/api/login/')
def admin(request):
    token = request.session.get('access_token', None)

    return render(request, 'admin.html', {'token': token})



@api_view(['POST'])
@login_required(login_url='/api/login/')
def profiling(request):
    asset=request.POST.get("selectedAssets")
    platform=request.data.get("platformSelect")
    ammount=request.data.get("amount")
    email=request.session.get('email', None)
    user = User.objects.get(email=email)
    user.trading_ammount=float(ammount)
    user.sum_trading_ammount=user.sum_trading_ammount+float(ammount)
    user.save()
    send_infos_trade(request,user,asset,platform,ammount)
    return redirect(reverse('dashboard'))


# def get_bitcoin_price():
#     # Fetching Bitcoin price from CoinGecko
#     url = "https://api.coingecko.com/api/v3/simple/price?ids=bitcoin&vs_currencies=usd"
#     response = requests.get(url)
#     data = response.json()
#     print(data)
#     return data.get('bitcoin', {}).get('usd', 'N/A')


# def real_time_prices(request):
#     bitcoin_price = get_bitcoin_price()

    
#     return JsonResponse({
#         'bitcoin_price': bitcoin_price,
       
#     })




