from django.contrib.auth.models import User
from app.models import *
from rest_framework import serializers

class UserSerializer(serializers.HyperlinkedModelSerializer):
    class Meta:
        model = User
        fields = [
            'url',
            'username',
        ]

class PrivateKeySerializer(serializers.HyperlinkedModelSerializer):
    class Meta:
        model = PrivateKey
        fields = '__all__'

class PublicKeySerializer(serializers.HyperlinkedModelSerializer):
    class Meta:
        model = PublicKey
        fields = '__all__'