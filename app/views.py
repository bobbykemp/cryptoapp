import json

from Crypto.Hash import SHA256
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


class MessageViewSet(viewsets.ModelViewSet):
    serializer_class = MessageSerializer

    def perform_create(self, serializer):
        serializer.save(owner=self.request.user)

    def get_queryset(self):
        return Message.objects.filter(owner=self.request.user)

    def create(self, request):
        data = request.data['contents'].encode('utf-8')
        private_key = request.data['recipient_private_key']

