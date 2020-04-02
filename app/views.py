import json
from tempfile import TemporaryFile

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.models import User
from django.core import serializers
from django.http import HttpResponse, JsonResponse, FileResponse
from django.shortcuts import get_object_or_404, render
from django.views.generic import TemplateView
from django.views.generic.edit import FormView
from rest_framework import viewsets
from rest_framework.decorators import action
from rest_framework.parsers import FileUploadParser

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

class HashViewSet(viewsets.GenericViewSet):
    serializer_class = HashSerializer

    def perform_create(self, serializer):
        serializer.save(owner=self.request.user)

    def create(self, request):
        content = request.data['content']
        return JsonResponse({
            'Hashed_message': SHA256.new(bytes(content, 'utf-8')).hexdigest()
        })


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
        parser_classes = [FileUploadParser]
        data = request.data['content'].encode('utf-8')
        recipient_public_key = PrivateKey.objects.get(pk=request.data['recipient_private_key']).get_public_key()
        public_key = RSA.import_key(recipient_public_key)
        session_key = get_random_bytes(16)

        ciper_rrsa = PKCS1_OAEP.new(public_key)
        enc_session_key = ciper_rrsa.encrypt(session_key)

        cipher_aes = AES.new(session_key, AES.MODE_EAX)
        ciphertext, tag = cipher_aes.encrypt_and_digest(data)

        # 'w+b' mode by default
        file_out = TemporaryFile()

        [ file_out.write(x) for x in (enc_session_key, cipher_aes.nonce, tag, ciphertext) ]

        file_out.seek(0)

        return FileResponse(file_out, as_attachment=True)


    @action(detail=False, methods=['post'])
    def decrypt(self, request):
        file_in = request.data['file_to_decrypt']
        recipient_private_key = PrivateKey.objects.get(pk=request.data['recipient_private_key']).content
        private_key = RSA.import_key(recipient_private_key)

        enc_session_key, nonce, tag, ciphertext = \
            [ file_in.read(x) for x in (private_key.size_in_bytes(), 16, 16, -1) ]

        # Decrypt the session key with the private RSA key
        cipher_rsa = PKCS1_OAEP.new(private_key)
        session_key = cipher_rsa.decrypt(enc_session_key)

        # Decrypt the data with the AES session key
        cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
        data = cipher_aes.decrypt_and_verify(ciphertext, tag)
        return JsonResponse({
            'Decrypted_message': data.decode("utf-8")
        })

