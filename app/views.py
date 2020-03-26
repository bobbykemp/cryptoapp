from django.shortcuts import render
from django.http import HttpResponse, JsonResponse
from django.core import serializers
from cryptoapp.forms import *
from app.models import *
from django.views.generic.edit import FormView
from django.views.generic import TemplateView
from django.contrib.auth.forms import UserCreationForm
import json
from Crypto.Hash import MD5
from Crypto.PublicKey import RSA

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

# keygen stuff
class RSAKeyGen(TemplateView):

    # pass single RSAKey object for json serialization
    def serializeObj(self, keys):
        if not hasattr(keys, '__len__'):
            serialized = serializers.serialize("json", [keys])
            data = dict({'keys': serialized})
            return data
        if len(keys) == 0:
            data = dict({'keys': 'no keys yet'})
            return data
        else:
            data = {}
            for key in keys:
                serialized = serializers.serialize("json", [key])
                data[key.pk] = key.content
            return data

    def private_gen(self, request):
        key = RSA.generate(2048) # 2048 is secure enough for modern standards
        key_out = PrivateKey.objects.create(
            content=key.export_key('PEM'),
            owner=self.request.user,
        )
        return key_out

    def public_gen(self, request, private_key_obj):
        rsa_key = RSA.import_key(private_key_obj.content)
        public_key = rsa_key.publickey()
        key_out = PublicKey.objects.create(
            private_key = private_key_obj,
            owner=request.user,
            content=public_key,
        )
        return key_out

    def post(self, request, type=None, pk=None):
        if type == 'private':
            key = self.private_gen(request)
            return JsonResponse(self.serializeObj(key), status=201)

        # need to specify which public key to gen for
        elif type == 'public':
            private_key = PrivateKey.objects.get(pk=pk)
            key = self.public_gen(request, private_key)
            return JsonResponse(self.serializeObj(key), status=201)

    def get_pks(self, request):
        q = PrivateKey.objects.filter(owner=request.user)
        pks = []
        for o in q:
            pks.append(o.pk)
        return JsonResponse({
            'pks': pks
        })

    def get(self, request, type=None, pk=None):
        if type ==  'private':
            q = PrivateKey.objects.filter(owner=request.user)
            if pk:
                q = PrivateKey.objects.get(pk=pk)
            serialized = self.serializeObj(q)
            return JsonResponse(serialized)

        elif type == 'public':
            q = PublicKey.objects.filter(owner=request.user)
            if pk:
                private_key = PrivateKey.objects.get(pk=pk)
                q = PublicKey.objects.filter(private_key=private_key)
            serialized = self.serializeObj(q)
            return JsonResponse(serialized)

class RSAForm(FormView):
    template_name = 'app/rsa.html'
    form_class = RSAForm

    # called on posting of valid data
    def form_valid(self, form):
        pass

