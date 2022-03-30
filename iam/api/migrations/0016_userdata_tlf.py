# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0015_auto_20150124_0936'),
    ]

    operations = [
        migrations.AddField(
            model_name='userdata',
            name='tlf',
            field=models.CharField(null=True, max_length=20),
            preserve_default=True,
        ),
    ]
