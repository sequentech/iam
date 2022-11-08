# Generated by Edulix on 2022-10-19 10:00

import uuid
from django.db import migrations, models
import django

class Migration(migrations.Migration):

    dependencies = [
        ('authmethods', '0009_code_is_enabled'),
    ]

    operations = [
        migrations.CreateModel(
            name='OneTimeLink',
            fields=[
                (
                    'id',
                    models.AutoField(
                        serialize=False,
                        verbose_name='ID',
                        auto_created=True,
                        primary_key=True
                    )
                ),
                (
                    'user',
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="one_time_links",
                        to="api.UserData"
                    )
                ),
                ('auth_event_id', models.IntegerField()),
                (
                    'secret',
                    models.UUIDField(
                        default=uuid.uuid4,
                        editable=False,
                        db_index=True
                    )
                ),
                ('created', models.DateTimeField(auto_now_add=True)),
                ('used', models.DateTimeField(
                    auto_now=False,
                    auto_now_add=False,
                    null=True,
                    blank=True
                )),
                ('is_enabled', models.BooleanField(default=True)),
            ],
            options={},
            bases=(models.Model,),
        )
    ]
