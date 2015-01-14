# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations
import jsonfield.fields


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0008_pack'),
    ]

    operations = [
        migrations.CreateModel(
            name='CreditsAction',
            fields=[
                ('id', models.AutoField(serialize=False, primary_key=True, verbose_name='ID', auto_created=True)),
                ('action', models.CharField(default='add', max_length=5, choices=[('add', 'add_credits'), ('spend', 'spend_credits')])),
                ('status', models.CharField(default='created', max_length=10, choices=[('created', 'created'), ('done', 'done'), ('cancelled', 'cancelled')])),
                ('quantity', models.FloatField()),
                ('payment_metadata', jsonfield.fields.JSONField(default='{}')),
                ('created', models.DateTimeField(auto_now_add=True)),
                ('updated', models.DateTimeField(auto_now_add=True)),
                ('authevent', models.ForeignKey(null=True, to='api.AuthEvent', related_name='creditsactions')),
                ('user', models.ForeignKey(related_name='creditsactions', to='api.UserData')),
            ],
            options={
            },
            bases=(models.Model,),
        ),
        migrations.RemoveField(
            model_name='pack',
            name='user',
        ),
        migrations.DeleteModel(
            name='Pack',
        ),
        migrations.AddField(
            model_name='userdata',
            name='credits',
            field=models.FloatField(default=0),
            preserve_default=True,
        ),
    ]
