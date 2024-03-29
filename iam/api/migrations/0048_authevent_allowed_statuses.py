# Generated by Edulix on 2021-12-30 11:00

from django.db import migrations, models

class Migration(migrations.Migration):
    dependencies = [
        ('api', '0047_userdata_use_generated_auth_code'),
    ]

    operations = [
        migrations.AlterField(
            model_name='authevent',
            name='status',
            field=models.CharField(
                default='notstarted',
                max_length=15,
                choices=[
                    ('notstarted', 'not-started'),
                    ('started', 'started'),
                    ('stopped', 'stopped'),
                    ('resumed', 'resumed'),
                    ('suspended', 'suspended')
                ]
            ),
            preserve_default=True
        )
    ]
