# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0014_auto_20150124_0901'),
    ]

    operations = [
        migrations.AlterField(
            model_name='acl',
            name='object_id',
            field=models.CharField(max_length=255, default=0),
        ),
    ]
