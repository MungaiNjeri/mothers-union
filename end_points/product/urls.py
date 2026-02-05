# urls.py
from django.urls import path
from django.contrib.auth import views as auth_views
from . import auth

urlpatterns = [
    path('signup/', auth.signup_view, name='signup'),
    path('login/', auth.login_view, name='login'),
    path('logout/', auth.logout_view, name='logout'),
    
  '''  path('dashboard/', views.dashboard_view, name='dashboard'),
    
    path('forgot-password/', views.forgot_password_view, name='forgot_password'),
    path('reset-password/<uidb64>/<token>/', 
         views.password_reset_confirm_view, 
         name='password_reset_confirm'),
    
    path('profile/', views.profile_view, name='profile'),
    path('change-password/', views.change_password_view, name='change_password'),
    
    path('api/validate-email/', views.validate_email_api, name='validate_email_api'),
    path('api/validate-phone/', views.validate_phone_api, name='validate_phone_api'),


'''
]