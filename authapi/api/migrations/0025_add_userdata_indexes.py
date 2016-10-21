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

from django.db import migrations, models
import jsonfield.fields


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0024_auto_20151125_0916'),
    ]

    operations = [
        migrations.AlterField(
            model_name='userdata',
            name='metadata',
            field=jsonfield.fields.JSONField(blank=True, db_index=True, default='{}', max_length=4096, null=True),
        ),
        migrations.AlterField(
            model_name='userdata',
            name='status',
            field=models.CharField(choices=[('act', 'Active'), ('pen', 'Pending'), ('dis', 'Disabled')], db_index=True, default='act', max_length=255),
        ),
    ]
