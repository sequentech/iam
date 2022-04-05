# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations


class Migration(migrations.Migration):

    dependencies = [
        ('authmethods', '0005_auto_20150124_1907'),
    ]

    operations = [
        migrations.AddField(
            model_name='code',
            name='auth_event_id',
            field=models.IntegerField(default=0),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name='colorlist',
            name='auth_event_id',
            field=models.IntegerField(default=0),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name='connection',
            name='auth_event_id',
            field=models.IntegerField(default=0),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name='message',
            name='auth_event_id',
            field=models.IntegerField(default=0),
            preserve_default=False,
        ),
    ]
