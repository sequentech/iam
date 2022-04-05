# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations
import jsonfield.fields


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0016_userdata_tlf'),
    ]

    operations = [
        migrations.AlterField(
            model_name='authevent',
            name='extra_fields',
            field=jsonfield.fields.JSONField(null=True),
        ),
    ]
