from django.db import models
from django.contrib.auth.models import User
from Crypto.PublicKey import RSA

class RSAKey(models.Model):
    content  = models.BinaryField()
    owner = models.ForeignKey(User, on_delete=models.CASCADE)

    class Meta:
        abstract = True

class PrivateKey(RSAKey):
    pass

class PublicKey(RSAKey):
    content  = models.BinaryField()
    private_key = models.ForeignKey(PrivateKey, on_delete=models.CASCADE)

    def generate_pub_key(self):
        rsa_key = RSA.import_key(self.private_key)
        return rsa_key.publickey()
