# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations
import jsonfield.fields


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0017_auto_20150204_1206'),
    ]

    operations = [
        migrations.AlterField(
            model_name='authevent',
            name='extra_fields',
            field=jsonfield.fields.JSONField(blank=True, null=True),
        ),
    ]
