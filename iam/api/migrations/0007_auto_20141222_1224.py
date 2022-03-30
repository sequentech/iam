# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0006_auto_20141221_1132'),
    ]

    operations = [
        migrations.AlterField(
            model_name='acl',
            name='object_id',
            field=models.CharField(null=True, max_length=255, blank=True),
        ),
    ]
