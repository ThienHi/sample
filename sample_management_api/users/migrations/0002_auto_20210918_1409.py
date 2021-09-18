# Generated by Django 3.1.13 on 2021-09-18 14:09

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('users', '0001_initial'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='user',
            name='name',
        ),
        migrations.AddField(
            model_name='user',
            name='first_name',
            field=models.CharField(blank=True, max_length=255, null=True),
        ),
        migrations.AddField(
            model_name='user',
            name='last_name',
            field=models.CharField(blank=True, max_length=250),
        ),
        migrations.AddField(
            model_name='user',
            name='role',
            field=models.CharField(blank=True, choices=[('Chemist', 'Chemist'), ('Manager', 'Manager')], max_length=10, null=True),
        ),
        migrations.AddField(
            model_name='user',
            name='status',
            field=models.CharField(blank=True, choices=[('Active', 'Active'), ('Suspended', 'Suspended')], max_length=10, null=True),
        ),
        migrations.AlterField(
            model_name='user',
            name='email',
            field=models.CharField(blank=True, max_length=255, null=True),
        ),
        migrations.AlterField(
            model_name='user',
            name='last_login',
            field=models.DateTimeField(null=True),
        ),
    ]