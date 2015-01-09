# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0007_auto_20141222_1224'),
    ]

    operations = [
        migrations.CreateModel(
            name='Pack',
            fields=[
                ('id', models.AutoField(primary_key=True, serialize=False, verbose_name='ID', auto_created=True)),
                ('name', models.CharField(default='b', choices=[('f', 'Free'), ('b', 'Basic'), ('p', 'Premium')], max_length=3)),
                ('status', models.CharField(default='pen', choices=[('pen', 'Pending'), ('pai', 'Paid'), ('act', 'Active'), ('dis', 'Disabled')], max_length=3)),
                ('created', models.DateTimeField(auto_now_add=True)),
                ('user', models.ForeignKey(to='api.UserData', related_name='packs')),
            ],
            options={
            },
            bases=(models.Model,),
        ),
    ]
