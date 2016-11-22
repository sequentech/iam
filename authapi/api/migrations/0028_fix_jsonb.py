# This file is part of authapi.
# Copyright (C) 2014-2016  Agora Voting SL <agora@agoravoting.com>

# authapi is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License.

# authapi  is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.

# You should have received a copy of the GNU Affero General Public License
# along with authapi.  If not, see <http://www.gnu.org/licenses/>.

from __future__ import unicode_literals

import django.core.validators
from django.db import migrations, models
import django.db.models.deletion
import jsonfield.fields
import json


def fix_metadata(apps, schema_editor):
    # We can't import the Person model directly as it may be a newer
    # version than this migration expects. We use the historical version.
    UserData = apps.get_model("api", "UserData")
    for user_data in UserData.objects.all():
        if type(user_data) == str:
          user_data.metadata = json.loads(user_data.metadata)
          user_data.save()


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0027_successful_login'),
    ]

    operations = [
        migrations.RunPython(fix_metadata),
        migrations.AlterField(
            model_name='userdata',
            name='metadata',
            field=jsonfield.fields.JSONField(blank=True, db_index=True, default=dict(), null=True),
        ),
    ]
