# Generated by Django 3.0.4 on 2020-03-31 00:12

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('app', '0003_auto_20200330_2339'),
    ]

    operations = [
        migrations.AlterField(
            model_name='publickey',
            name='content',
            field=models.BinaryField(),
        ),
    ]