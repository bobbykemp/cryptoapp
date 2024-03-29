# Generated by Django 3.0.4 on 2020-04-02 03:41

from django.db import migrations
from django.apps import apps
from django.contrib.auth.models import User
import datetime

def create_test_user(apps, schema_editor):
    user = User.objects.create_user('me', password='test', email="test@test.com", last_login=datetime.datetime.now())
    User.objects.create_user('bob', password='test', email="bob@test.com", last_login=datetime.datetime.now())
    User.objects.create_user('alice', password='test', email="alice@test.com", last_login=datetime.datetime.now())
    User.objects.create_user('jay', password='test', email="jay@test.com", last_login=datetime.datetime.now())

class Migration(migrations.Migration):

    dependencies = [
        ('app', '0001_initial'),
    ]

    operations = [
        migrations.RunPython(create_test_user),
    ]
