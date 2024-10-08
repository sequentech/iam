# Generated by Felix Robles on 2024-06-27 06:36

from django.db import migrations, models
from django.contrib.postgres.fields import JSONField
import django.core.validators

class Migration(migrations.Migration):
    dependencies = [
        ('api', '0053_authapi_oidc_providers'),
    ]

    operations = [
        migrations.AddField(
            model_name='authevent',
            name='refresh_token_duration_secs',
            field=models.IntegerField(default=600, validators=[django.core.validators.MinValueValidator(0)]),
        ),
        migrations.AddField(
            model_name='authevent',
            name='access_token_duration_secs',
            field=models.IntegerField(default=120, validators=[django.core.validators.MinValueValidator(0)]),
        ),
    ]
