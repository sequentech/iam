# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations
import datetime


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0021_acl_created'),
    ]

    operations = [
        migrations.AddField(
            model_name='authevent',
            name='created',
            field=models.DateTimeField(auto_now_add=True, default=datetime.date(2015, 3, 10)),
            preserve_default=False,
        ),
    ]
