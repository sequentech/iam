# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations
import jsonfield.fields


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0018_auto_20150208_1536'),
    ]

    operations = [
        migrations.AlterField(
            model_name='acl',
            name='object_type',
            field=models.CharField(max_length=255, null=True, blank=True),
        ),
        migrations.AlterField(
            model_name='userdata',
            name='metadata',
            field=jsonfield.fields.JSONField(default=dict, null=True, blank=True),
        ),
        migrations.AlterField(
            model_name='userdata',
            name='tlf',
            field=models.CharField(max_length=20, null=True, blank=True),
        ),
    ]
