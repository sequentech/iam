# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations


class Migration(migrations.Migration):

    dependencies = [
        ('authmethods', '0002_code_connection'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='code',
            name='dni',
        ),
        migrations.RemoveField(
            model_name='code',
            name='tlf',
        ),
    ]
