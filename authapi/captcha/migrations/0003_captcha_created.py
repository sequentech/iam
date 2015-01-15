# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations
import datetime


class Migration(migrations.Migration):

    dependencies = [
        ('captcha', '0002_captcha_challenge'),
    ]

    operations = [
        migrations.AddField(
            model_name='captcha',
            name='created',
            field=models.DateTimeField(default=datetime.datetime(2015, 1, 15, 11, 27, 22, 222946), auto_now=True),
            preserve_default=False,
        ),
    ]
