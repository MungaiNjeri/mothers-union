from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.views.decorators.csrf import csrf_protect
from django.http import JsonResponse
from django.core.validators import validate_email
from django.core.exceptions import ValidationError
from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
from django.contrib.sites.shortcuts import get_current_site
from django.core.mail import send_mail
from django.template.loader import render_to_string
from django.conf import settings
from .models import User
import json
import re

def validate_kenyan_phone(phone):
    """Validate Kenyan phone number format"""
    pattern = r'^\+?254[17]\d{8}$|^0[17]\d{8}$'
    return bool(re.match(pattern, phone))

def validate_password(password):
    """Validate password requirements"""
    if len(password) < 6:
        return False, "Password must be at least 6 characters"
    return True, ""

@csrf_protect
def signup_view(request):
    if request.user.is_authenticated:
        return redirect('dashboard')
    
    if request.method == 'POST':
        full_name = request.POST.get('fullName', '').strip()
        role = request.POST.get('role', '').strip()
        phone = request.POST.get('phone', '').strip()
        email = request.POST.get('email', '').strip().lower()
        password = request.POST.get('password', '')
        confirm_password = request.POST.get('confirmPassword', '')
        
        errors = {}
        
        # Validation
        if not full_name:
            errors['fullName'] = ['Please enter your full name']
        
        if not role or role not in ['treasurer', 'chairlady', 'secretary']:
            errors['role'] = ['Please select a valid role']
        
        if not phone:
            errors['phone'] = ['Please enter your phone number']
        elif not validate_kenyan_phone(phone):
            errors['phone'] = ['Please enter a valid Kenyan phone number']
        elif User.objects.filter(phone_number=phone).exists():
            errors['phone'] = ['This phone number is already registered']
        
        if not email:
            errors['email'] = ['Please enter your email address']
        else:
            try:
                validate_email(email)
                if User.objects.filter(email=email).exists():
                    errors['email'] = ['This email is already registered']
            except ValidationError:
                errors['email'] = ['Please enter a valid email address']
        
        if not password:
            errors['password'] = ['Please enter a password']
        else:
            is_valid, msg = validate_password(password)
            if not is_valid:
                errors['password'] = [msg]
        
        if password != confirm_password:
            errors['confirmPassword'] = ['Passwords do not match']
        
        # Check for AJAX request
        if request.headers.get('x-requested-with') == 'XMLHttpRequest':
            if errors:
                return JsonResponse({
                    'success': False,
                    'errors': errors
                }, status=400)
            
            # Create user
            try:
                user = User.objects.create_user(
                    email=email,
                    full_name=full_name,
                    phone_number=phone,
                    role=role,
                    password=password
                )
                
                # Auto login
                login(request, user)
                
                return JsonResponse({
                    'success': True,
                    'message': 'Account created successfully!',
                    'redirect_url': '/dashboard/'
                })
                
            except Exception as e:
                return JsonResponse({
                    'success': False,
                    'errors': {'__all__': [str(e)]}
                }, status=500)
        
        else:
            # Regular form submission
            if not errors:
                try:
                    user = User.objects.create_user(
                        email=email,
                        full_name=full_name,
                        phone_number=phone,
                        role=role,
                        password=password
                    )
                    
                    login(request, user)
                    messages.success(request, 'Account created successfully!')
                    return redirect('dashboard')
                    
                except Exception as e:
                    messages.error(request, f'Error creating account: {str(e)}')
            else:
                for field, error_list in errors.items():
                    for error in error_list:
                        messages.error(request, f'{field}: {error}')
    
    # GET request - show signup page
    roles = User.Role.choices
    return render(request, 'product/signup.html', {
        'roles': roles,
        'page_title': 'Sign Up'
    })

# Login View
@csrf_protect
def login_view(request):
    if request.user.is_authenticated:
        return redirect('dashboard')
    
    if request.method == 'POST':
        email = request.POST.get('username', '').strip().lower()
        password = request.POST.get('password', '')
        remember_me = request.POST.get('rememberMe') == 'on'
        
        errors = {}
        
        if not email:
            errors['username'] = ['Please enter your email address']
        
        if not password:
            errors['password'] = ['Please enter your password']
        
        # Check for AJAX request
        if request.headers.get('x-requested-with') == 'XMLHttpRequest':
            if errors:
                return JsonResponse({
                    'success': False,
                    'errors': errors
                }, status=400)
            
            # Authenticate user
            user = authenticate(request, username=email, password=password)
            
            if user is not None:
                if user.is_active:
                    login(request, user)
                    
                    # Handle remember me
                    if remember_me:
                        request.session.set_expiry(2592000)  # 30 days
                    else:
                        request.session.set_expiry(0)
                    
                    # Update last login IP
                    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
                    if x_forwarded_for:
                        ip = x_forwarded_for.split(',')[0]
                    else:
                        ip = request.META.get('REMOTE_ADDR')
                    user.last_login_ip = ip
                    user.save(update_fields=['last_login_ip'])
                    
                    return JsonResponse({
                        'success': True,
                        'message': 'Login successful!',
                        'redirect_url': '/dashboard/'
                    })
                else:
                    return JsonResponse({
                        'success': False,
                        'errors': {'__all__': ['Account is inactive. Please contact support.']}
                    }, status=400)
            else:
                return JsonResponse({
                    'success': False,
                    'errors': {'__all__': ['Invalid email or password.']}
                }, status=400)
        
        else:
            # Regular form submission
            user = authenticate(request, username=email, password=password)
            
            if user is not None:
                if user.is_active:
                    login(request, user)
                    
                    if remember_me:
                        request.session.set_expiry(2592000)
                    else:
                        request.session.set_expiry(0)
                    
                    messages.success(request, 'Login successful!')
                    return redirect('dashboard')
                else:
                    messages.error(request, 'Account is inactive. Please contact support.')
            else:
                messages.error(request, 'Invalid email or password.')
    
    # GET request - show login page
    return render(request, 'auth/login.html', {
        'page_title': 'Login'
    })

# Logout View
@login_required
def logout_view(request):
    logout(request)
    messages.success(request, 'You have been logged out successfully.')
    return redirect('login')

# Dashboard View
@login_required
def dashboard_view(request):
    user = request.user
    return render(request, 'dashboard.html', {
        'user': user,
        'page_title': 'Dashboard'
    })

# Forgot Password View
def forgot_password_view(request):
    if request.method == 'POST':
        email = request.POST.get('email', '').strip().lower()
        
        if not email:
            messages.error(request, 'Please enter your email address.')
            return render(request, 'auth/forgot_password.html')
        
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            messages.error(request, 'No account found with this email address.')
            return render(request, 'auth/forgot_password.html')
        
        # Generate password reset token
        token = default_token_generator.make_token(user)
        uid = urlsafe_base64_encode(force_bytes(user.pk))
        
        current_site = get_current_site(request)
        
        # Send email
        subject = 'Password Reset Request'
        message = render_to_string('auth/password_reset_email.html', {
            'user': user,
            'domain': current_site.domain,
            'uid': uid,
            'token': token,
            'protocol': 'https' if request.is_secure() else 'http',
        })
        
        try:
            send_mail(
                subject,
                message,
                settings.DEFAULT_FROM_EMAIL,
                [user.email],
                fail_silently=False,
            )
            
            messages.success(request, 'Password reset link has been sent to your email.')
            return redirect('login')
            
        except Exception as e:
            messages.error(request, f'Error sending email: {str(e)}')
            return render(request, 'auth/forgot_password.html')
    
    return render(request, 'auth/forgot_password.html', {
        'page_title': 'Forgot Password'
    })

# Password Reset Confirm View
def password_reset_confirm_view(request, uidb64, token):
    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None
    
    if user is not None and default_token_generator.check_token(user, token):
        if request.method == 'POST':
            password = request.POST.get('password', '')
            confirm_password = request.POST.get('confirmPassword', '')
            
            if not password:
                messages.error(request, 'Please enter a new password.')
                return render(request, 'auth/password_reset_confirm.html')
            
            is_valid, msg = validate_password(password)
            if not is_valid:
                messages.error(request, msg)
                return render(request, 'auth/password_reset_confirm.html')
            
            if password != confirm_password:
                messages.error(request, 'Passwords do not match.')
                return render(request, 'auth/password_reset_confirm.html')
            
            # Set new password
            user.set_password(password)
            user.save()
            
            messages.success(request, 'Password has been reset successfully. You can now login.')
            return redirect('login')
        
        return render(request, 'auth/password_reset_confirm.html', {
            'validlink': True,
            'page_title': 'Reset Password'
        })
    else:
        messages.error(request, 'The password reset link is invalid or has expired.')
        return redirect('forgot_password')

# Profile View
@login_required
def profile_view(request):
    if request.method == 'POST':
        user = request.user
        
        full_name = request.POST.get('fullName', '').strip()
        phone = request.POST.get('phone', '').strip()
        
        errors = {}
        
        if not full_name:
            errors['fullName'] = ['Please enter your full name']
        
        if not phone:
            errors['phone'] = ['Please enter your phone number']
        elif not validate_kenyan_phone(phone):
            errors['phone'] = ['Please enter a valid Kenyan phone number']
        elif phone != user.phone_number and User.objects.filter(phone_number=phone).exists():
            errors['phone'] = ['This phone number is already registered']
        
        if not errors:
            user.full_name = full_name
            user.phone_number = phone
            
            # Handle profile picture if needed
            if 'profile_picture' in request.FILES:
                # Add profile_picture field to your User model if needed
                # user.profile_picture = request.FILES['profile_picture']
                pass
            
            user.save()
            messages.success(request, 'Profile updated successfully!')
            return redirect('profile')
        else:
            for field, error_list in errors.items():
                for error in error_list:
                    messages.error(request, f'{field}: {error}')
    
    return render(request, 'auth/profile.html', {
        'user': request.user,
        'page_title': 'My Profile'
    })

# Change Password View
@login_required
def change_password_view(request):
    if request.method == 'POST':
        user = request.user
        
        current_password = request.POST.get('currentPassword', '')
        new_password = request.POST.get('newPassword', '')
        confirm_password = request.POST.get('confirmPassword', '')
        
        errors = {}
        
        if not current_password:
            errors['currentPassword'] = ['Please enter your current password']
        elif not user.check_password(current_password):
            errors['currentPassword'] = ['Current password is incorrect']
        
        if not new_password:
            errors['newPassword'] = ['Please enter a new password']
        else:
            is_valid, msg = validate_password(new_password)
            if not is_valid:
                errors['newPassword'] = [msg]
        
        if new_password != confirm_password:
            errors['confirmPassword'] = ['New passwords do not match']
        
        if current_password == new_password:
            errors['newPassword'] = ['New password must be different from current password']
        
        if not errors:
            user.set_password(new_password)
            user.save()
            
            updated_user = authenticate(username=user.email, password=new_password)
            if updated_user:
                login(request, updated_user)
            
            messages.success(request, 'Password changed successfully!')
            return redirect('profile')
        else:
            for field, error_list in errors.items():
                for error in error_list:
                    messages.error(request, f'{field}: {error}')
    
    return render(request, 'auth/change_password.html', {
        'page_title': 'Change Password'
    })