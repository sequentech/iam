# Generated by Felix Robles on 2024-07-19 15:14

from django.db import migrations, models

class Migration(migrations.Migration):
    dependencies = [
        ('api', '0054_token_duration'),
    ]

    operations = [
        migrations.AddField(
            model_name='authevent',
            name='force_census_query',
            field=models.BooleanField(default=False),
        ),
    ]