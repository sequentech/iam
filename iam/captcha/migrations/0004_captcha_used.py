# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations


class Migration(migrations.Migration):

    dependencies = [
        ('captcha', '0003_captcha_created'),
    ]

    operations = [
        migrations.AddField(
            model_name='captcha',
            name='used',
            field=models.BooleanField(default=False),
            preserve_default=True,
        ),
    ]
