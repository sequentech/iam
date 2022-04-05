# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0011_authevent_status'),
    ]

    operations = [
        migrations.AlterField(
            model_name='authevent',
            name='name',
            field=models.CharField(null=True, max_length=255),
        ),
    ]
