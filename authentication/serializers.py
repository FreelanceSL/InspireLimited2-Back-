from rest_framework import serializers
from .models import User
class UserSerializer(serializers.ModelSerializer):
    image = serializers.ImageField(required=False, allow_null=True)
    class Meta:
        model = User
        fields = ['first_name', 'last_name', 'id', 'email', 'password', 'country', 'phone', 'image','is_verified']
        extra_kwargs = {
            'password': {'write_only': True},
            'first_name': {'required': True},
            'last_name': {'required': True},
            'email': {'required': True},
            'country': {'required': True},
        }
        
    def create(self, validated_data):
        password = validated_data.pop('password', None)
        instance = self.Meta.model(**validated_data)
        if password is not None:
            instance.set_password(password)
        instance.save()
        return instance

    def update_password(self, instance, validated_data):
        password = validated_data.get('password')
        if password:
            instance.set_password(password)
        return instance

class VerificationSerializer(serializers.ModelSerializer):
    class Meta:
        model=User
        fields=['first_name','last_name','id','email','otp']