from django.db import models
from django.db.models.functions import Cast
from django.db.models import DecimalField
from django.db.models import Sum

class Fish(models.Model):
    

    name = models.CharField(max_length=100)
    malayalam_name = models.CharField(max_length=100)
    price_per_kg = models.DecimalField(max_digits=6, decimal_places=2)
    total_kg = models.DecimalField(max_digits=10, decimal_places=2)
    description = models.TextField(blank=True, null=True)
    image = models.ImageField(upload_to='fish_images/', blank=True, null=True)
    delivery_available = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.name

from django.contrib.auth.models import User
from django.conf import settings
from django.contrib.auth.hashers import make_password
class Customer(models.Model):
    full_name = models.CharField(max_length=255)
    phone = models.CharField(max_length=15, unique=True)  # Made unique and required
    address = models.TextField(blank=True, null=True)
    email = models.EmailField(null=True, blank=True) 
    password = models.CharField(max_length=128) 
    reset_code = models.CharField(max_length=6, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.full_name} - {self.phone}"

    def save(self, *args, **kwargs):
        if self._state.adding or 'password' in kwargs:
            self.password = make_password(self.password)
        super().save(*args, **kwargs)
    

from django.db import models

class Order(models.Model):
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('processing', 'Processing'),
        ('delivered', 'Delivered'),
        ('cancelled', 'Cancelled'),
    ]
    user = models.ForeignKey(Customer, on_delete=models.CASCADE, related_name='orders')
    fish = models.ForeignKey(Fish, on_delete=models.CASCADE, related_name='orders')  # Links to Fish model
    customer_name = models.CharField(max_length=100)
    address=models.JSONField()
    quantity = models.DecimalField(max_digits=6, decimal_places=2, help_text="Quantity in kg")
    total_price = models.DecimalField(max_digits=10, decimal_places=2, blank=True, null=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')  # New field for status
    label = models.CharField(max_length=20, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def save(self, *args, **kwargs):
        # Calculate total price before saving
        if self.fish and self.quantity:
            self.total_price = self.fish.price_per_kg * self.quantity
        if self._state.adding:  # New order
            self.fish.available = False
            self.fish.save()
        elif self.status == 'cancelled':
            self.fish.available = True
            self.fish.save()
        elif self.status == 'delivered':
            self.fish.available = True
            self.fish.save()
        super(Order, self).save(*args, **kwargs)

    def __str__(self):
        return f"Order {self.id} - {self.customer_name} - {self.status}"




    

from django.contrib.auth.models import AbstractUser


class customUser(AbstractUser):
    
    is_business = models.BooleanField(default=False)
    
    
    groups = models.ManyToManyField(
        'auth.Group',
        related_name='customuser_set',  # This avoids conflict with default User model
        blank=True
    )
    user_permissions = models.ManyToManyField(
        'auth.Permission',
        related_name='customuser_permissions',  # This avoids conflict with default User model
        blank=True
    )
    
    
    
    
class Address(models.Model):
    customer = models.ForeignKey(Customer, on_delete=models.CASCADE, related_name='addresses')
    street_address = models.CharField(max_length=255)
    city = models.CharField(max_length=100)
    state = models.CharField(max_length=100)
    postal_code = models.CharField(max_length=20)
    country = models.CharField(max_length=100)
    is_default = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-is_default', '-created_at']

    def save(self, *args, **kwargs):
        # If this is marked as default, remove default status from other addresses
        if self.is_default:
            Address.objects.filter(customer=self.customer, is_default=True).update(is_default=False)
        super().save(*args, **kwargs)
        
    def __str__(self):
        return f"{self.customer} "