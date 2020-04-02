from Crypto.PublicKey import RSA
from django.contrib.auth.models import User
from rest_framework import serializers

from app.models import *


class UserSerializer(serializers.HyperlinkedModelSerializer):
    class Meta:
        model = User
        fields = [
            'url',
            'username',
        ]

class HashSerializer(serializers.HyperlinkedModelSerializer):
    class Meta:
        model = Hash
        fields = '__all__'

class MessageSerializer(serializers.HyperlinkedModelSerializer):
    owner = serializers.PrimaryKeyRelatedField(read_only=True)
    recipient_private_key = serializers.PrimaryKeyRelatedField(
        queryset=PrivateKey.objects.all()
    )

    class Meta:
        model = Message
        fields = '__all__'

class PrivateKeySerializer(serializers.HyperlinkedModelSerializer):
    owner = serializers.PrimaryKeyRelatedField(read_only=True)
    key_from_bytes = serializers.SerializerMethodField()

    # attribute method
    def get_key_from_bytes(self, obj):
        return obj.content.decode("utf-8")

    # generate a private key with RSA module
    def private_gen(self):
        key = RSA.generate(2048) # 2048 is secure enough for modern standards
        return key.export_key('PEM')

    # called on post to endpoint
    def create(self, validated_data):
        gen = self.private_gen()
        priv_key = PrivateKey(
            content=gen,
            owner=validated_data['owner'],
        )
        priv_key.save()
        return priv_key

    class Meta:
        model = PrivateKey
        fields = '__all__'

