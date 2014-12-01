# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations


class Migration(migrations.Migration):

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='ColorList',
            fields=[
                ('id', models.AutoField(serialize=False, auto_created=True, verbose_name='ID', primary_key=True)),
                ('key', models.CharField(default='ip', max_length=3)),
                ('value', models.CharField(max_length=255)),
                ('action', models.CharField(choices=[('black', 'blacklist'), ('white', 'whitelist')], default='black', max_length=255)),
                ('created', models.CharField(max_length=255)),
                ('modified', models.CharField(max_length=255)),
            ],
            options={
            },
            bases=(models.Model,),
        ),
    ]
