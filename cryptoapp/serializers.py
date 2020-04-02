from Crypto.PublicKey import RSA
from django.contrib.auth.models import User
from rest_framework import serializers

from app.models import *


class UserFilteredPrimaryKeyRelatedField(serializers.PrimaryKeyRelatedField):
    def get_queryset(self):
        request = self.context.get('request', None)
        queryset = super(UserFilteredPrimaryKeyRelatedField, self).get_queryset()
        if not request or not queryset:
            return None
        return queryset.filter(owner=request.user)

class UserSerializer(serializers.HyperlinkedModelSerializer):
    class Meta:
        model = User
        fields = [
            'url',
            'username',
        ]

class HashSerializer(serializers.HyperlinkedModelSerializer):
    owner = serializers.PrimaryKeyRelatedField(read_only=True)
    class Meta:
        model = Hash
        fields = '__all__'

class MessageSerializer(serializers.HyperlinkedModelSerializer):
    owner = serializers.PrimaryKeyRelatedField(read_only=True)
    recipient_private_key = serializers.PrimaryKeyRelatedField(
        queryset=PrivateKey.objects.all()
    )
    signing_key = serializers.PrimaryKeyRelatedField(
        queryset=PrivateKey.objects.all()
    )

    class Meta:
        model = Message
        fields = '__all__'

class MessageFilteredSerializer(serializers.HyperlinkedModelSerializer):
    owner = serializers.PrimaryKeyRelatedField(read_only=True)
    recipient_private_key = UserFilteredPrimaryKeyRelatedField(
        queryset=PrivateKey.objects
    )
    signing_key = serializers.PrimaryKeyRelatedField(
        queryset=PrivateKey.objects.all()
    )

    class Meta:
        model = Message
        fields = '__all__'

class PrivateKeySerializer(serializers.HyperlinkedModelSerializer):
    id = serializers.ReadOnlyField()
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

