# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0005_auto_20141208_1114'),
    ]

    operations = [
        migrations.RenameField(
            model_name='acl',
            old_name='obj_type',
            new_name='object_id',
        ),
        migrations.RenameField(
            model_name='acl',
            old_name='objectid',
            new_name='object_type',
        ),
    ]
