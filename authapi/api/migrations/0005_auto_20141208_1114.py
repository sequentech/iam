# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0004_auto_20141128_0914'),
    ]

    operations = [
        migrations.AddField(
            model_name='acl',
            name='obj_type',
            field=models.CharField(max_length=255, null=True),
            preserve_default=True,
        ),
        migrations.AddField(
            model_name='acl',
            name='objectid',
            field=models.CharField(max_length=255, null=True),
            preserve_default=True,
        ),
    ]
