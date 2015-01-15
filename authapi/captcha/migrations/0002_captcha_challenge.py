# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations


class Migration(migrations.Migration):

    dependencies = [
        ('captcha', '0001_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='captcha',
            name='challenge',
            field=models.CharField(default='XXX', max_length=4),
            preserve_default=False,
        ),
    ]
