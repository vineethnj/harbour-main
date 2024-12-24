# fish/serializers.py
from rest_framework import serializers
from .models import Fish

class FishSerializer(serializers.ModelSerializer):
    class Meta:
        model = Fish
        fields = ['id','name', 'price_per_kg', "total_kg",'description', 'image', 'created_at', 'updated_at','delivery_available']
        
        
from rest_framework import serializers
from .models import Order

class OrderSerializer(serializers.ModelSerializer):
    class Meta:
        model = Order
        fields = ['id', 'user','fish', 'customer_name', 'quantity', 'total_price', 'status', 'created_at','address']
        read_only_fields = ['total_price', 'created_at']  # Total price is auto-calculated


from rest_framework import serializers
from django.contrib.auth.hashers import check_password
from .models import Customer

class CustomerRegistrationSerializer(serializers.ModelSerializer):
    confirm_password = serializers.CharField(write_only=True)

    class Meta:
        model = Customer
        fields = ['full_name', 'phone', 'password', 'confirm_password', 'address','email']
        extra_kwargs = {
            'password': {'write_only': True}
        }

    def validate(self, data):
        if data.get('password') != data.get('confirm_password'):
            raise serializers.ValidationError("Passwords do not match")
        return data

    def create(self, validated_data):
        validated_data.pop('confirm_password')
        return Customer.objects.create(**validated_data)

class CustomerLoginSerializer(serializers.Serializer):
    phone = serializers.CharField()
    password = serializers.CharField()

    def validate(self, data):
        try:
            customer = Customer.objects.get(phone=data['phone'])
            if not check_password(data['password'], customer.password):
                raise serializers.ValidationError("Invalid credentials")
            return data
        except Customer.DoesNotExist:
            raise serializers.ValidationError("Invalid credentials")
        
        
from .models import Address
class AddressSerializer(serializers.ModelSerializer):
    class Meta:
        model = Address
        fields = ['id', 'street_address', 'city', 'state', 'postal_code', 'country', 'is_default']

class CustomerSerializer(serializers.ModelSerializer):
    addresses = AddressSerializer(many=True, read_only=True)
    
    class Meta:
        model = Customer
        fields = ['id', 'full_name', 'phone', 'addresses', 'created_at','email']
        
        


class CancelOrderSerializer(serializers.Serializer):
    user_id = serializers.IntegerField()
    
    
    
    
# serializers.py
from rest_framework import serializers

# For sending reset email
class EmailSerializer(serializers.Serializer):
    email = serializers.EmailField()

# For setting new password
class ResetPasswordSerializer(serializers.Serializer):
    password = serializers.CharField()
    confirm_password = serializers.CharField()
    
    
    


from .models import Notification

class NotificationSerializer(serializers.ModelSerializer):
    class Meta:
        model = Notification
        fields = ['id', 'title', 'message','is_active', 'created_at']