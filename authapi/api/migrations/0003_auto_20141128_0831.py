# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations
import jsonfield.fields


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0002_auto_20141128_0827'),
    ]

    operations = [
        migrations.AlterField(
            model_name='userdata',
            name='metadata',
            field=jsonfield.fields.JSONField(default='{}'),
        ),
        migrations.AlterField(
            model_name='userdata',
            name='status',
            field=models.CharField(choices=[('act', 'Active'), ('pen', 'Pending'), ('dis', 'Disabled')], max_length=255, default='act'),
        ),
    ]
