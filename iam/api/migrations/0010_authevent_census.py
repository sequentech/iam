# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0009_auto_20150114_2141'),
    ]

    operations = [
        migrations.AddField(
            model_name='authevent',
            name='census',
            field=models.CharField(max_length=5, choices=[('close', 'Close census'), ('open', 'Open census')], default='close'),
            preserve_default=True,
        ),
    ]
