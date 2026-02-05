# models.py
from django.db import models
from django.contrib.auth.models import AbstractUser
from django.core.validators import RegexValidator

class User(AbstractUser):
    class Role(models.TextChoices):
        TREASURER = 'treasurer', 'Treasurer'
        CHAIRLADY = 'chairlady', 'Chairlady'
        SECRETARY = 'secretary', 'Secretary'
    
    phone_regex = RegexValidator(
        regex=r'^\+?1?\d{9,15}$',
        message="Phone number must be entered in the format: '+999999999'. Up to 15 digits allowed."
    )
    
    full_name = models.CharField(max_length=100)
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
    
    username = None
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['full_name', 'phone_number', 'role']
    
    is_verified = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        return f"{self.full_name} - {self.role}"