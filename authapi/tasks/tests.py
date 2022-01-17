# This file is part of authapi.
# Copyright (C) 2022 Sequent Tech Inc <legal@sequentech.io>

# authapi is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License.

# authapi  is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.

# You should have received a copy of the GNU Affero General Public License
# along with authapi.  If not, see <http://www.gnu.org/licenses/>.

from django.conf import settings
from django.contrib.auth.models import User
from django.test import TestCase

from api import test_data
from api.models import AuthEvent
from api.tests import JClient, flush_db_load_fixture, parse_json_response
from tasks.models import Task

class TestListTasks(TestCase):
    '''
    Unit tests for tasks.views.task view
    '''
    def setUpTestData():
        flush_db_load_fixture()

    def setUp(self):
        admin_user = User(
            username='test_admin',
            email=test_data.auth_email_default['email']
        )
        admin_user.save()
        admin_user.userdata.event_id=settings.ADMIN_AUTH_ID
        admin_user.userdata.save()
        self.admin_user = admin_user

    def test_list_requires_auth(self):
        client = JClient()
        response = client.get('/api/task/', {})
        self.assertEqual(response.status_code, 403)

    def test_list_requires_admin_auth(self):
        '''
        Check that listing tasks works when user event_id is
        settings.ADMIN_AUTH_ID but not otherwise
        '''
        client = JClient()
        client.authenticate(
            settings.ADMIN_AUTH_ID,
            test_data.auth_email_default
        )
        response = client.get('/api/task/', {})
        self.assertEqual(response.status_code, 200)

        self.admin_user.userdata.event_id = None
        self.admin_user.userdata.save()

        response = client.get('/api/task/', {})
        self.assertEqual(response.status_code, 403)
