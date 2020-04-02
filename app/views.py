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
from rest_framework.decorators import action

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

<<<<<<< HEAD
=======
    def private_gen(self, request):
        key = RSA.generate(2048) # 2048 is secure enough for modern standards
        return key.export_key('PEM')

    @action(detail=True, methods=['get'])
    def get_public_keys(self, request, pk=None):
        private_key = get_object_or_404(PrivateKey, pk=pk)
        queryset = PublicKey.objects.filter(private_key=private_key.pk)
        serializer = PublicKeySerializer(queryset, many=True)
        return JsonResponse(serializer.data, status=200)

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

>>>>>>> 9e8f3c23b275d1dcfcb30a18f70ed1fcd639cd80
class PublicKeyViewset(viewsets.ModelViewSet):
    serializer_class = PublicKeySerializer

    def get_queryset(self):
        return PublicKey.objects.filter(owner=self.request.user)
