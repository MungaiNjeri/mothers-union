from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.core.validators import RegexValidator
import re

class CustomUserManager(BaseUserManager):
    def create_user(self, email, full_name, phone_number, role, password=None, **extra_fields):
        if not email:
            raise ValueError('The Email field must be set')
        if not full_name:
            raise ValueError('The Full Name field must be set')
        if not phone_number:
            raise ValueError('The Phone Number field must be set')
        
        email = self.normalize_email(email)
        user = self.model(
            email=email,
            full_name=full_name,
            phone_number=phone_number,
            role=role,
            **extra_fields
        )
        user.set_password(password)
        user.save(using=self._db)
        return user
    
    def create_superuser(self, email, full_name, phone_number, role, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('is_active', True)
        
        return self.create_user(email, full_name, phone_number, role, password, **extra_fields)

class User(AbstractBaseUser, PermissionsMixin):
    # Role choices
    class Role(models.TextChoices):
        TREASURER = 'treasurer', 'Treasurer'
        CHAIRLADY = 'chairlady', 'Chairlady'
        SECRETARY = 'secretary', 'Secretary'
    
    # Custom fields
    full_name = models.CharField(max_length=100)
    
    # Phone validation for Kenyan format
    phone_regex = RegexValidator(
        regex=r'^\+?1?\d{9,15}$',
        message="Phone number must be entered in the format: '+999999999'. Up to 15 digits allowed."
    )
    phone_number = models.CharField(
        max_length=17, 
        validators=[phone_regex], 
        unique=True
    )
    
    role = models.CharField(
        max_length=20,
        choices=Role.choices,
        default=Role.TREASURER
    )
    
    email = models.EmailField(unique=True)
    
    # Django auth fields
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    is_superuser = models.BooleanField(default=False)
    
    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    is_verified = models.BooleanField(default=False)
    last_login_ip = models.GenericIPAddressField(null=True, blank=True)
    
    objects = CustomUserManager()
    
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['full_name', 'phone_number', 'role']
    
    def __str__(self):
        return f"{self.full_name} ({self.email})"
    
    def has_perm(self, perm, obj=None):
        return self.is_superuser
    
    def has_module_perms(self, app_label):
        return self.is_superuser
    
    class Meta:
        verbose_name = 'User'
        verbose_name_plural = 'Users'