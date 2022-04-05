# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0013_auto_20150122_2252'),
    ]

    operations = [
        migrations.AlterField(
            model_name='authevent',
            name='status',
            field=models.CharField(default='notstarted', choices=[('notstarted', 'not-started'), ('started', 'started'), ('stopped', 'stopped')], max_length=15),
        ),
    ]
