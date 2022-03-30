# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations
import datetime


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0020_auto_20150219_1022'),
    ]

    operations = [
        migrations.AddField(
            model_name='acl',
            name='created',
            field=models.DateTimeField(default=datetime.date(2015, 2, 23), auto_now_add=True),
            preserve_default=False,
        ),
    ]
