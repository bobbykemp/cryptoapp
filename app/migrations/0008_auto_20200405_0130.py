# Generated by Django 3.0.4 on 2020-04-05 01:30

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('app', '0007_message_secure_id'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='message',
            name='secure_id',
        ),
        migrations.AddField(
            model_name='privatekey',
            name='secure_id',
            field=models.CharField(default='ey', max_length=100),
            preserve_default=False,
        ),
    ]