from django.contrib import admin
from .models import Fish, Order, Customer, customUser,Address

@admin.register(Fish)
class FishAdmin(admin.ModelAdmin):
    list_display = ('name', 'price_per_kg', 'total_kg', 'created_at', 'updated_at')
    search_fields = ('name',)
    list_filter = ('created_at', 'updated_at')

@admin.register(Order)
class OrderAdmin(admin.ModelAdmin):
    list_display = ('id', 'customer_name', 'fish', 'quantity', 'total_price', 'status', 'created_at')
    list_filter = ('status', 'created_at')
    search_fields = ('customer_name',)

@admin.register(Customer)
class CustomerAdmin(admin.ModelAdmin):
    list_display = ('full_name', 'phone', 'created_at')

@admin.register(customUser)
class CustomUserAdmin(admin.ModelAdmin):
    list_display = ('username', 'email', 'is_business', 'is_staff')
    list_filter = ('is_business', 'is_staff', 'is_active')
    search_fields = ('username', 'email')
    filter_horizontal = ('groups', 'user_permissions')
    
    
admin.site.register(Address)