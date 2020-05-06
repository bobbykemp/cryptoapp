import json
import os
import uuid
from tempfile import TemporaryFile

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Signature import pkcs1_15
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.models import User
from django.core import serializers
from django.db.models.signals import post_save
from django.dispatch import receiver
from django.http import FileResponse, HttpResponse, JsonResponse, Http404
from django.shortcuts import get_object_or_404, render
from django.views.generic import TemplateView
from django.views.generic.edit import FormView
from rest_framework import viewsets
from rest_framework.decorators import action
from rest_framework.mixins import UpdateModelMixin
from rest_framework.parsers import FileUploadParser
from rest_framework.renderers import HTMLFormRenderer, TemplateHTMLRenderer
from rest_framework.response import Response

from app.models import *
from cryptoapp.serializers import *


@receiver(post_save, sender=User)
def createUserKeys(sender, **kwargs):
    UserKeys.objects.get_or_create(
        user=kwargs['instance']
    )

class CreateUserView(FormView):
    template_name = 'app/signup.html'
    form_class = UserCreationForm
    success_url = '/'

    def form_invalid(self, form):
        response = super().form_invalid(form)
        print(form)
        return JsonResponse(form.errors, status=400)

    def form_valid(self, form):
        print('test')
        form.save()
        return super().form_valid(form)

def sign(request, data):
    # private key of the _sender_ to sign this message with
    # signing with the sender's private key means that
    # the reciever can verify the signature with the signer's public key
    signing_key = UserKeys.objects.get(user=request.user) \
                                                .signing_key \
                                                .content
    private_key = RSA.import_key(signing_key)

    # hash of plaintext for signature
    hash_ = SHA256.new(data)
    signature = pkcs1_15.new(private_key).sign(hash_)

    return signature

def verify_signature(request, data, signature):
    signing_public_key = UserKeys.objects.get(signing_key__secure_id=request.data['signing_key']) \
                                                .signing_key \
                                                .get_public_key()
    # RSA public key of sender to verify signature agains
    public_key = RSA.import_key(signing_public_key)

    # take hash of message and seek back to file start
    hash_ = SHA256.new(data)

    is_sig_valid = None

    try:
        pkcs1_15.new(public_key).verify(hash_, signature)
        is_sig_valid = True
    except(ValueError, TypeError):
        is_sig_valid = False

    return is_sig_valid

# def index(request):
#     return render(request, 'index.html')

class UserViewSet(viewsets.ModelViewSet):
    queryset = User.objects.all()
    serializer_class = UserSerializer

    def perform_create(self, serializer):
        serializer.save(
            owner=self.request.user,
        )
    

class UserKeysViewSet(viewsets.ReadOnlyModelViewSet, UpdateModelMixin):
    queryset = UserKeys.objects.all()
    serializer_class = UserKeysSerializer
    lookup_field = 'user'

    @action(detail=False, methods=['get'])
    def search_usernames(self, request):
        vals = []
        for key in UserKeys.objects.exclude(user=request.user) \
                                .filter(user__username__icontains=request.query_params['term']):
            kwargs = {}
            try:
                kwargs['label'] = key.user.username
                kwargs['value'] = key.user.username
            except AttributeError:
                kwargs['label'] = None
                kwargs['value'] = None

            try:
                kwargs['messaging_key_id'] = key.messaging_key.secure_id
            except AttributeError:
                kwargs['messaging_key_id'] = None
            try:
                kwargs['signing_key_id'] = key.signing_key.secure_id
            except AttributeError:
                kwargs['signing_key_id'] = None

            vals.append(kwargs)

        serializer = SearchSerializer(vals, many=True)
        return JsonResponse(serializer.data, safe=False)


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

class SignatureViewSet(viewsets.ModelViewSet):
    '''
    Signs a file using the pkcs1_15 algorithm.

    Returns the file and it's signature (signature is 256 bytes in length)
    '''
    serializer_class = SignatureSerializer

    def perform_create(self, serializer):
        serializer.save(owner=self.request.user)

    def get_queryset(self):
        return Signature.objects.filter(owner=self.request.user)


    def create(self, request):
        parser_classes = [FileUploadParser]

        file = request.data['file_to_sign']
        file_name, file_ext = os.path.splitext(file.name)
        data = file.read()

        signature = sign(request, data)

        # 'w+b' mode by default
        file_out = TemporaryFile()

        [file_out.write(x) for x in (signature, data)]

        file_out.seek(0)

        return FileResponse(file_out, as_attachment=True, filename=f'{file_name}{file_ext}.signed')

    @action(detail=False, methods=['post'])
    def verify(self, request):
        parser_classes = [FileUploadParser]

        file = request.data['file_to_sign']
        file_name, file_ext = os.path.splitext(file.name)

        signature, data = \
            [file.read(x) for x in (256, -1)]

        is_sig_valid = verify_signature(request, data, signature)

        if not is_sig_valid:
            return JsonResponse({
                'Signature status': is_sig_valid
            })

        # 'w+b' mode by default
        file_out = TemporaryFile()

        file_out.write(data)

        file_out.seek(0)

        return FileResponse(file_out, as_attachment=True, filename=f'{file_name}')


class PrivateKeyViewset(viewsets.ModelViewSet):
    serializer_class = PrivateKeySerializer
    lookup_field = 'secure_id'

    def perform_create(self, serializer):
        serializer.save(
            owner=self.request.user,
            secure_id=uuid.uuid4()
        )

    def get_queryset(self):
        return PrivateKey.objects.filter(owner=self.request.user)

    @action(detail=True, methods=['get'])
    def get_public_key(self, request, secure_id=None):
        private_key = get_object_or_404(PrivateKey, secure_id=secure_id)
        return JsonResponse({'key': private_key.get_public_key().decode('utf-8')})

    @action(detail=True, methods=['get'])
    def get_public_key_as_file(self, request, secure_id=None):
        key = get_object_or_404(PrivateKey, secure_id=secure_id)
        public_key = key.get_public_key()

        # 'w+b' mode by default
        file_out = TemporaryFile()

        file_out.write(public_key)
        file_out.seek(0)

        return FileResponse(file_out, as_attachment=True, filename=f'{key.owner.username}_public_key.txt')

    @action(detail=True, methods=['get'])
    def get_private_key_as_file(self, request, secure_id=None):
        private_key = PrivateKey.objects \
                                        .filter(owner=request.user) \
                                        .get(secure_id=secure_id) \
                                        .content

        # 'w+b' mode by default
        file_out = TemporaryFile()

        file_out.write(private_key)
        file_out.seek(0)

        return FileResponse(file_out, as_attachment=True, filename=f'{request.user}_private_key.txt')


class MessageViewSet(viewsets.ReadOnlyModelViewSet):
    serializer_class = MessageSerializer
    renderer_classes = [TemplateHTMLRenderer]
    template_name = 'app/base.html'

    # dynamically determine how many references to show in
    # drf frontend form based on routing action
    serializer_action_classes = {
        'encrypt': MessageSerializer,
        'decrypt': DecryptionSerializer
    }

    def get_serializer_class(self):
        try:
            return self.serializer_action_classes[self.action]
        except (KeyError, AttributeError):
            return super().get_serializer_class()

    def perform_create(self, serializer):
        serializer.save(owner=self.request.user)

    def get_queryset(self):
        return Message.objects.filter(owner=self.request.user)

    @action(detail=False, methods=['post'])
    def encrypt(self, request):
        parser_classes = [FileUploadParser]

        # plaintext from user
        data = request.data['content'].encode('utf-8')
        # did user request a signature
        try:
            signed = request.data['signed']
        except:
            signed = None

        # public key of the recipient to encrypt this message with
        # can access anyone's public key via a reference to their private key
        # this protect's the private key while also simplifying the database schema by
        # one model
        recipient_public_key = UserKeys.objects.get(messaging_key__secure_id=request.data['recipient_public_key']) \
                                                    .messaging_key \
                                                    .get_public_key()

        recip_uname = UserKeys.objects.get(messaging_key__secure_id=request.data['recipient_public_key']) \
                                                    .user \
                                                    .username

        public_key = RSA.import_key(recipient_public_key)

        # randomly-generate session key for encryption
        session_key = get_random_bytes(16)

        signature = sign(request, data)

        ciper_rrsa = PKCS1_OAEP.new(public_key)
        enc_session_key = ciper_rrsa.encrypt(session_key)

        cipher_aes = AES.new(session_key, AES.MODE_EAX)
        ciphertext, tag = cipher_aes.encrypt_and_digest(data)

        # 'w+b' mode by default
        file_out = TemporaryFile()

        if signed:
            [ file_out.write(x) for x in (enc_session_key, cipher_aes.nonce, tag, signature, ciphertext) ]
        else:
            [ file_out.write(x) for x in (enc_session_key, cipher_aes.nonce, tag, ciphertext) ]

        file_out.seek(0)

        return FileResponse(file_out, as_attachment=True, filename=f'encrypted_message_to_{recip_uname}')


    @action(detail=False, methods=['post'])
    def decrypt(self, request):
        serializer = DecryptionSerializer

        # encrypted file to decrypt, may or may not
        # be signed
        file_in = request.data['file_to_decrypt']
        # whether or not the file is signed
        try:
            signed = request.data['signed']
        except:
            signed = None

        # private key of recipient to decrypt message with
        # have to be this key's owner to decrypt
        # on decryption, first filter by key owner then get the 
        # private key's value; this ensure's only someone
        # who own's the private key can decrypt a message intended
        # for them
        recipient_private_key = UserKeys.objects.get(user=request.user) \
                                                    .messaging_key \
                                                    .content
        private_key = RSA.import_key(recipient_private_key)

        if signed:
            enc_session_key, nonce, tag, signature, ciphertext = \
                [ file_in.read(x) for x in (private_key.size_in_bytes(), 16, 16, 256, -1) ]
        else:
            enc_session_key, nonce, tag, ciphertext = \
                [ file_in.read(x) for x in (private_key.size_in_bytes(), 16, 16, -1) ]

        # Decrypt the session key with the private RSA key
        cipher_rsa = PKCS1_OAEP.new(private_key)
        session_key = cipher_rsa.decrypt(enc_session_key)

        # Decrypt the data with the AES session key
        cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
        data = cipher_aes.decrypt_and_verify(ciphertext, tag)

        if signed:
            is_sig_valid = verify_signature(request, data, signature)
        else:
            is_sig_valid = 'No signature'

        return JsonResponse({
            'Decrypted_message': data.decode("utf-8"),
            'Signature status': is_sig_valid
        })
