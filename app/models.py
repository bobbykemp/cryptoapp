from django.db import models
from django.forms import ModelForm
from django.contrib.auth.models import User
from Crypto.PublicKey import RSA
import uuid


class PrivateKey(models.Model):
    content  = models.BinaryField()
    owner = models.ForeignKey(User, on_delete=models.CASCADE)
    secure_id = models.CharField(max_length=100, unique=True)

    def get_public_key(self):
        return RSA.import_key(self.content).publickey().export_key('PEM')

# accessed by user.userkeys
class UserKeys(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, primary_key=True, unique=True)
    # the private key of a keypair that any messages will be signed with
    signing_key = models.ForeignKey(PrivateKey, default=None, on_delete=models.SET_DEFAULT, related_name='signing_key', blank=True, null=True)
    # the private key of a keypair that will be used for message encryption
    messaging_key = models.ForeignKey(PrivateKey, default=None, on_delete=models.SET_DEFAULT, related_name='messaging_key', blank=True, null=True)

class Hash(models.Model):
    content = models.TextField()
    owner = models.ForeignKey(User, on_delete=models.CASCADE)

class Message(models.Model):
    content = models.TextField()
    owner = models.ForeignKey(User, on_delete=models.CASCADE, related_name='message_owner')
    recipient_public_key = models.ForeignKey(UserKeys, on_delete=models.CASCADE, blank=True, null=True, related_name='message_key')
    file_to_decrypt = models.FileField()
    signed = models.BooleanField(default=False)
    signing_key = models.ForeignKey(UserKeys, on_delete=models.CASCADE, blank=True, null=True, related_name='sign_key')

