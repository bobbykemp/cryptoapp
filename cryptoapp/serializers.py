from Crypto.PublicKey import RSA
from django.contrib.auth.models import User
from rest_framework import serializers

from app.models import *
import uuid

class UserRelationField(serializers.RelatedField):
    def to_representation(self, value):
        return '{}'.format(value.user.username)

class AllOthersRelationField(UserRelationField):
    def get_queryset(self):
        request = self.context.get('request', None)
        queryset = super(AllOthersRelationField, self).get_queryset()
        if not request or not queryset:
            return None
        return queryset.all().exclude(user=request.user)

class MyRelationField(UserRelationField):
    def get_queryset(self):
        request = self.context.get('request', None)
        queryset = super(MyRelationField, self).get_queryset()
        if not request or not queryset:
            return None
        return queryset.filter(user=request.user)

class UserFilteredPrimaryKeyRelatedField(serializers.PrimaryKeyRelatedField):
    def get_queryset(self):
        request = self.context.get('request', None)
        queryset = super(UserFilteredPrimaryKeyRelatedField, self).get_queryset()
        if not request or not queryset:
            return None
        return queryset.filter(owner=request.user)

class UserFilteredSlugRelatedField(serializers.SlugRelatedField):
    def get_queryset(self):
        request = self.context.get('request', None)
        queryset = super(UserFilteredSlugRelatedField, self).get_queryset()
        if not request or not queryset:
            return None
        return queryset.filter(owner=request.user)

class UserSerializer(serializers.HyperlinkedModelSerializer):
    class Meta:
        model = User
        fields = [
            'url',
            'username',
            'email',
        ]

class SearchSerializer(serializers.ModelSerializer):
    class Meta:
        model = Search
        fields = '__all__'

class UserKeysSerializer(serializers.ModelSerializer):
    user = UserSerializer(read_only=True)

    signing_key = UserFilteredSlugRelatedField(
        many=False,
        read_only=False,
        queryset=PrivateKey.objects,
        slug_field='secure_id',
        required=False
    )
    messaging_key = UserFilteredSlugRelatedField(
        many=False,
        read_only=False,
        queryset=PrivateKey.objects,
        slug_field='secure_id',
        required=False
    )

    class Meta:
        model = UserKeys
        fields = '__all__'

class HashSerializer(serializers.ModelSerializer):
    owner = serializers.PrimaryKeyRelatedField(read_only=True)
    class Meta:
        model = Hash
        fields = '__all__'

class SignatureSerializer(serializers.ModelSerializer):
    class Meta:
        model = Signature
        fields = '__all__'
        lookup_field = 'user'

class MessageSerializer(serializers.ModelSerializer):
    owner = serializers.PrimaryKeyRelatedField(read_only=True)
    file_to_decrypt = serializers.HiddenField(default='')
    recipient_public_key = AllOthersRelationField(
        queryset=UserKeys.objects
    )
    signing_key = MyRelationField(
        queryset=UserKeys.objects
    )

    class Meta:
        model = Message
        fields = '__all__'

class DecryptionSerializer(serializers.ModelSerializer):
    owner = serializers.PrimaryKeyRelatedField(read_only=True)
    recipient_public_key = MyRelationField(
        queryset=UserKeys.objects
    )
    signing_key = AllOthersRelationField(
        queryset=UserKeys.objects
    )
    content = serializers.HiddenField(default='')

    class Meta:
        model = Message
        fields = '__all__'

class PrivateKeySerializer(serializers.ModelSerializer):
    id = serializers.ReadOnlyField()
    secure_id = serializers.ReadOnlyField()
    key_from_bytes = serializers.SerializerMethodField()
    owner = UserSerializer(read_only=True)

    # attribute method
    def get_key_from_bytes(self, obj):
        return obj.content

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
            secure_id=uuid.uuid4()
        )
        priv_key.save()
        return priv_key

    class Meta:
        model = PrivateKey
        fields = '__all__'
        depth = 1

