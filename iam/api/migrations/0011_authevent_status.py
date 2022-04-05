# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0010_authevent_census'),
    ]

    operations = [
        migrations.AddField(
            model_name='authevent',
            name='status',
            field=models.CharField(default='stop', max_length=5, choices=[('start', 'start'), ('stop', 'stop')]),
            preserve_default=True,
        ),
    ]
