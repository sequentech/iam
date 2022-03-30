# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations


class Migration(migrations.Migration):

    dependencies = [
        ('authmethods', '0007_msg'),
    ]

    operations = [
        migrations.RenameModel(
            old_name='Msg',
            new_name='MsgLog',
        ),
    ]
