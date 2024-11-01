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
    path('verify/',views.Verification.as_view()),
    path("reset/<uidb64>/<token>/",views.reset_password),
    path("forget_password/",views.forget_password),
    path('reset_email/',views.send_password_reset_email),
    # path('upload/', views.FileUploadView.as_view(), name='upload_file'),
    
    
    path('home/',views.index, name='index'),
    path('about/', views.about, name='about'),
    path('services/', views.services, name='services'),
    path('blogs/', views.blogs, name='blogs'),
    path('features/', views.features, name='features'),
    path('team/', views.team, name='team'),
    path('testimonials/', views.testimonials, name='testimonials'),
    path('offers/', views.offers, name='offers'),
    path('faqs/', views.faqs, name='faqs'),
    path('404/', views.page_404, name='page_404'),
    path('contact/', views.contact, name='contact'),
    path('dashboard/',views.dashboard,name="dashboard"),
    path('signup/',views.signup,name="signup"),
    path('admin/',views.admin,name="admin"),
    path('users/', views.user_list, name='user_list'),
    
]+ static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
