# Generated by Edulix on 2023-05-24 10:40

from django.db import migrations, models
from django.contrib.postgres.fields import JSONField

class Migration(migrations.Migration):
    dependencies = [
        ('api', '0050_authevent_tally_mode'),
    ]

    operations = [
        migrations.AddField(
            model_name='authevent',
            name='alternative_auth_methods',
            field=JSONField(blank=True, db_index=False, null=True),
            preserve_default=False
        )
    ]
