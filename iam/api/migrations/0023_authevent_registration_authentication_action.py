# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations

def add_default_registration_authentication_actions(apps, schema_editor):
    '''
    Convert all authevents to add to the default registration-action and
    authentication-action mode: "vote", if it's not set.
    '''

    # We can't import the model directly as it may be a newer
    # version than this migration expects. We use the historical version.
    AuthEvent = apps.get_model("api", "AuthEvent")

    default_mode = {
      "mode": "vote",
      "mode-config": None
    }

    for ae in AuthEvent.objects.all():
        if 'config' not in ae.auth_method_config:
            ae.auth_method_config = {
                'config': {},
                'pipelines': []
            }

        config = ae.auth_method_config['config']
        if "authentication-action" not in config:
            config['authentication-action'] = default_mode
        if "registration-action" not in config:
            config['registration-action'] = default_mode
        ae.save()

class Migration(migrations.Migration):

    dependencies = [
        ('api', '0022_authevent_created'),
    ]

    operations = [
      migrations.RunPython(add_default_registration_authentication_actions)
    ]

