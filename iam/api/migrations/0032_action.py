# -*- coding: utf-8 -*-
# Generated by Django 1.9 on 2018-01-21 20:16
from __future__ import unicode_literals

from django.conf import settings
import django.contrib.postgres.fields.jsonb
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ('api', '0031_remove_authevent_real'),
    ]

    operations = [
        migrations.CreateModel(
            name='Action',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('created', models.DateTimeField(auto_now_add=True, db_index=True)),
                ('action_name', models.CharField(choices=[('election:created', 'election:created')], db_index=True, max_length=255)),
                ('metadata', django.contrib.postgres.fields.jsonb.JSONField(db_index=True, default=dict)),
                ('event', models.ForeignKey(null=True, on_delete=django.db.models.deletion.CASCADE, related_name='related_actions', to='api.AuthEvent')),
                ('executer', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='executed_actions', to=settings.AUTH_USER_MODEL)),
                ('receiver', models.ForeignKey(null=True, on_delete=django.db.models.deletion.CASCADE, related_name='received_actions', to=settings.AUTH_USER_MODEL)),
            ],
        ),
    ]