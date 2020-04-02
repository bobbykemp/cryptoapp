import json

from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.models import User
from django.core import serializers
from django.http import HttpResponse, JsonResponse
from django.shortcuts import get_object_or_404, render
from django.views.generic import TemplateView
from django.views.generic.edit import FormView
from rest_framework import viewsets
from rest_framework.decorators import action

from app.models import *
from cryptoapp.serializers import *


class UserViewSet(viewsets.ModelViewSet):
    queryset = User.objects.all()
    serializer_class = UserSerializer

class CreateUserView(FormView):
    template_name = 'registration/signup.html' 
    form_class = UserCreationForm
    success_url = '/'

    def form_valid(self, form):
        form.save()
        return super().form_valid(form)

class PrivateKeyViewset(viewsets.ModelViewSet):
    serializer_class = PrivateKeySerializer

    def perform_create(self, serializer):
        serializer.save(owner=self.request.user)

    def get_queryset(self):
        return PrivateKey.objects.filter(owner=self.request.user)

    @action(detail=True, methods=['get'])
    def get_public_key(self, request, pk=None):
        private_key = get_object_or_404(PrivateKey, pk=pk)
        return JsonResponse({'key': private_key.get_public_key().decode('utf-8')})


class MessageViewSet(viewsets.ReadOnlyModelViewSet):
    serializer_class = MessageSerializer

    def perform_create(self, serializer):
        serializer.save(owner=self.request.user)

    def get_queryset(self):
        return Message.objects.filter(owner=self.request.user)

    @action(detail=False, methods=['post'])
    def encrypt(self, request):
        data = request.data['content'].encode('utf-8')
        recipient_public_key = PrivateKey.objects.get(pk=request.data['recipient_private_key']).get_public_key()
        public_key = RSA.import_key(recipient_public_key)
        session_key = get_random_bytes(16)

        ciper_rrsa = PKCS1_OAEP.new(public_key)
        enc_session_key = ciper_rrsa.encrypt(session_key)

        cipher_aes = AES.new(session_key, AES.MODE_EAX)
        ciphertext, tag = cipher_aes.encrypt_and_digest(data)

        return JsonResponse({
            'enc_session_key': enc_session_key.decode('ISO-8859-1'),
            'ciper_aes.nonce': cipher_aes.nonce.decode('ISO-8859-1'),
            'tag': tag.decode('ISO-8859-1'),
            'ciphertext': ciphertext.decode('ISO-8859-1')
        })

    @action(detail=False, methods=['post'])
    def decrypt(self, request):
        data = request.data['content'].encode('ISO-8859-1')



