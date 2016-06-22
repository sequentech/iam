# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0023_authevent_registration_authentication_action'),
    ]

    operations = [
        migrations.AddField(
            model_name='authevent',
            name='based_in',
            field=models.IntegerField(null=True),
        ),
        migrations.AddField(
            model_name='authevent',
            name='real',
            field=models.BooleanField(default=False),
        ),
    ]
