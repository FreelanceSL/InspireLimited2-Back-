from django.db import models
from django.contrib.auth.models import AbstractUser,BaseUserManager
from django.conf import settings
# Create your models here.

class UserManager(BaseUserManager):
    use_in_migrations= True
    
    def _create_user(self,email,password, **extra_fields):
        if not email:
            raise ValueError('The given email must be set')
        email=self.normalize_email(email)
        user=self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user
    
    
    def create_user(self,email,password=None, **extra_fields):
        if not email:
            raise ValueError(('The email must be set'))
        email =self.normalize_email(email)
        user=self.model(email=email,**extra_fields)
        user.set_password(password)
        user.save()
        return user
    
    def create_superuser(self,email,password,**extra_fields):
        extra_fields.setdefault('is_staff',True)
        extra_fields.setdefault('is_superuser',True)
        extra_fields.setdefault('is_active',True)
        
        
        if extra_fields.get('is_staff') is not True:
            raise ValueError(('Superuser must have is_staff=True'))
        if extra_fields.get('is_superuser') is not True:
            raise ValueError(('Superuser must have is_superuser=True'))
        return self.create_user(email,password, **extra_fields)




class User(AbstractUser):
    username=None
    first_name=models.CharField(max_length=20)
    last_name=models.CharField(max_length=30)
    email=models.EmailField(unique=True)
    password=models.CharField(max_length=100)
    role = models.CharField(max_length=20, blank=True, default='user') 
    otp=models.CharField(max_length=4)
    is_verified=models.BooleanField(default=False)
    
    USERNAME_FIELD= 'email'
    REQUIRED_FIELDS=[]
    objects = UserManager()
        
        
    def name(self):
        return self.first_name+ ' ' + self.last_name
    
    def __str__(self):
        return self.email


class FileUpload(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)  # Relate to the User model
    file_name = models.CharField(max_length=255)
    file_data = models.BinaryField()

    def __str__(self):
        return self.file_name
        