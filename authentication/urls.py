from django.urls import path,include
from django.conf.urls.static import static
from django.conf import settings
from . import views
from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView
)
urlpatterns = [
    path("register/",views.Register.as_view(),name='register'),
    path('login/',views.Login.as_view(),name='login'),
    path('logout/',views.logout,name='logout'),
    path('token/',TokenObtainPairView.as_view(),name='token_obtain_pair'),
    path('token/refresh/',TokenRefreshView.as_view(),name='token_refresh'),
    path('verify/',views.Verification.as_view(),name='verify'),
    path("modify/<uidb64>/<token>/",views.reset_password, name='modify'),
    path("modify/<uidb64>/<token>/<langue>/",views.reset_password_ar, name='modify_ar'),
    path("forget_password/",views.forget_password, name='forget_password'),
    path("resend_otp/",views.resend_otp, name='resend_otp'),
    path("resend_otp_ar/",views.resend_otp_ar, name='resend_otp_ar'),
    path('reset_email/',views.send_password_reset_email),
    path('logout_ar/',views.logout_ar,name='logout_ar'),

    # path('upload/', views.FileUploadView.as_view(), name='upload_file'),
    
    
    path('',views.index, name='index'),
    path('about/', views.about, name='about'),
    path('services/', views.services, name='services'),
    path('blogs/', views.blogs, name='blogs'),
    path('404/', views.page_404, name='page_404'),
    path('contact/', views.contact, name='contact'),
    path('dashboard/',views.dashboard,name="dashboard"),
    path('signup/',views.signup,name="signup"),
    path('admin_dashboard/',views.admin,name="admin"),
    path('otp/',views.otp,name="otp"),
    path('admin_dashboard/users/', views.user_list, name='user_list'),
    path('reset/',views.reset,name='reset'),
    path('reset_ar/',views.reset_ar,name='reset_ar'),
    path('qstart/',views.qstart,name='qstart'),
    path('reset/<uidb64>/<token>/',views.update,name='update'),
    path('reset/<uidb64>/<token>/<langue>/',views.update_ar,name='update_ar'),
    path('home_ar/',views.index_ar, name='index_ar'),
    path('about_ar/', views.about_ar, name='about_ar'),
    path('services_ar/', views.services_ar, name='services_ar'),
    path('blogs_ar/', views.blogs_ar, name='blogs_ar'),
    path('contact_ar/', views.contact_ar, name='contact_ar'),
    path('login_ar/', views.login_ar, name='login_ar'),
    path('signup_ar/', views.signup_ar, name='signup_ar'),
    path('qstart_ar/', views.qstart_ar, name='qstart_ar'),
    path('dashboard_ar/', views.dashboard_ar, name='dashboard_ar'),
    path('otp_ar/', views.otp_ar, name='otp_ar'),
    path('profiling/', views.profiling, name='profiling'),
    path('forex/',views.forex, name='forex'),
    path('forex_ar/',views.forex_ar, name='forex_ar'),
    path('crypto/',views.crypto, name='crypto'),
    path('crypto_ar/',views.crypto_ar, name='crypto_ar'),
    path('metals/',views.metals, name='metals'),
    path('metals_ar/',views.metals_ar, name='metals_ar'),
    path('dashboard/withdraw/',views.withdraw, name='withdraw'),
    path('dashboard_ar/withdraw_ar/',views.withdraw_ar, name='withdraw_ar'),
    path('trading_history/', views.trading_history, name='trading_history'),
    path('trading_history_ar/', views.trading_history_ar, name='trading_history_ar'),
    path('admin_trading_history/',views.admin_trading_history, name='admin_trading_history'),
    
    
    
    
    
    
]+ static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
