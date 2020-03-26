import json

from Crypto.Hash import MD5
from Crypto.PublicKey import RSA
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.models import User
from django.core import serializers
from django.http import HttpResponse, JsonResponse
from django.shortcuts import get_object_or_404, render
from django.views.generic import TemplateView
from django.views.generic.edit import FormView
from rest_framework import viewsets

from app.models import *
from cryptoapp.forms import *
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

class HashForm(FormView):
    template_name = 'app/hash.html'
    form_class = HashForm

    def get_hash(self, hash):
        h = MD5.new()
        h.update(bytes(hash, encoding='utf-8'))
        return h.hexdigest()

    # called on posting of valid data
    def form_valid(self, form):
        hash_in = form.cleaned_data['value_to_hash']
        hash_out = self.get_hash(hash_in)
        return HttpResponse(hash_out)

class PrivateKeyViewset(viewsets.ModelViewSet):
    serializer_class = PrivateKeySerializer

    def get_queryset(self):
        return PrivateKey.objects.filter(owner=self.request.user)

    def private_gen(self, request):
        key = RSA.generate(2048) # 2048 is secure enough for modern standards
        return key.export_key('PEM')

    def create(self, request):
        key = self.private_gen(request)
        private_key_serializer = self.get_serializer_class()
        serialized = private_key_serializer(
            data={
                'content': key,
                'owner': request.user,
            }
        )
        serialized.save()
        return JsonResponse(serialized.data, status=201)

class PublicKeyViewset(viewsets.ModelViewSet):
    serializer_class = PublicKeySerializer

    def get_queryset(self):
        return PublicKey.objects.filter(owner=self.request.user)

    def public_gen(self, private_key):
        rsa_key = RSA.import_key(private_key)
        return rsa_key.publickey()

    def create(self, request, pk=None):
        # get private key to create this public key for
        # by its pk in the database
        private_key = get_object_or_404(
            PrivateKey.objects.get(owner=request.user),
            pk=pk
        )
        public_key = self.public_gen(private_key.content)
        public_key_serializer = self.get_serializer_class()
        serialized = public_key_serializer(
            data={
                'content': public_key,
                'owner': request.user,
                'private_key': private_key,
            }
        )
        serialized.save()
        return JsonResponse(serialized.data, status=201)
