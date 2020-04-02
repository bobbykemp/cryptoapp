from django.db import models
from django.contrib.auth.models import User
from Crypto.PublicKey import RSA

class PrivateKey(models.Model):
    content  = models.BinaryField()
    owner = models.ForeignKey(User, on_delete=models.CASCADE)

    def get_public_key(self):
        return RSA.import_key(self.content).publickey().export_key('PEM')

class Hash(models.Model):
    content = models.TextField()
    owner = models.ForeignKey(User, on_delete=models.CASCADE)

class Message(models.Model):
    content = models.TextField()
    owner = models.ForeignKey(User, on_delete=models.CASCADE, related_name='message_owner')
    recipient_private_key = models.ForeignKey(PrivateKey, on_delete=models.CASCADE, related_name='message_recipient')
    file_to_decrypt = models.FileField(blank=True)