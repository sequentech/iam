# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations


class Migration(migrations.Migration):

    dependencies = [
        ('authmethods', '0001_initial'),
    ]

    operations = [
        migrations.CreateModel(
            name='Message',
            fields=[
                ('id', models.AutoField(auto_created=True, verbose_name='ID', serialize=False, primary_key=True)),
                ('ip', models.CharField(max_length=15)),
                ('tlf', models.CharField(max_length=20)),
                ('created', models.DateField(auto_now_add=True)),
            ],
            options={
            },
            bases=(models.Model,),
        ),
        migrations.RemoveField(
            model_name='colorlist',
            name='modified',
        ),
        migrations.AlterField(
            model_name='colorlist',
            name='created',
            field=models.DateField(auto_now_add=True),
        ),
    ]
