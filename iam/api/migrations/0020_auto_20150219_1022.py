# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0019_auto_20150210_1821'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='creditsaction',
            name='authevent',
        ),
        migrations.RemoveField(
            model_name='creditsaction',
            name='user',
        ),
        migrations.DeleteModel(
            name='CreditsAction',
        ),
        migrations.RemoveField(
            model_name='userdata',
            name='credits',
        ),
    ]
