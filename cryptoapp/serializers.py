from Crypto.PublicKey import RSA
from django.contrib.auth.models import User
from rest_framework import serializers

from app.models import *


class StringBytesSerializer(serializers.HyperlinkedModelSerializer):
    key_from_bytes = serializers.SerializerMethodField()

    def get_key_from_bytes(self, obj):
        return obj.content.decode("utf-8")


class UserSerializer(serializers.HyperlinkedModelSerializer):
    class Meta:
        model = User
        fields = [
            'url',
            'username',
        ]

class PrivateKeySerializer(StringBytesSerializer):

    def private_gen(self):
        key = RSA.generate(2048) # 2048 is secure enough for modern standards
        return key.export_key('PEM')

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

class PublicKeySerializer(StringBytesSerializer):

    def public_gen(self, private_key):
        rsa_key = RSA.import_key(private_key)
        public_key = rsa_key.publickey()
        return public_key.export_key('PEM')

    def create(self, validated_data):
        gen = self.public_gen(validated_data['private_key'].content)
        pub_key = PublicKey(
            content=gen,
            owner=validated_data['owner'],
            private_key=validated_data['private_key'],
        )
        pub_key.save()
        return pub_key

    class Meta:
        model = PublicKey
        fields = '__all__'
