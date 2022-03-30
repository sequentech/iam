# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0012_auto_20150122_1853'),
    ]

    operations = [
        migrations.RenameField(
            model_name='authevent',
            old_name='metadata',
            new_name='extra_fields',
        ),
        migrations.RemoveField(
            model_name='authevent',
            name='name',
        ),
    ]
