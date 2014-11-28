# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations
from django.conf import settings


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0001_initial'),
    ]

    operations = [
        migrations.AlterField(
            model_name='userdata',
            name='event',
            field=models.ForeignKey(to='api.AuthEvent', related_name='userdata', null=True),
        ),
        migrations.AlterField(
            model_name='userdata',
            name='user',
            field=models.OneToOneField(to=settings.AUTH_USER_MODEL, related_name='userdata'),
        ),
    ]
