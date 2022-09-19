# This file is part of iam.
# Copyright (C) 2022  Sequent Tech Inc <legal@sequentech.io>

# iam is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License.

# iam  is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.

# You should have received a copy of the GNU Affero General Public License
# along with iam.  If not, see <http://www.gnu.org/licenses/>.

from io import StringIO

from django.core.management import call_command
from django.test import TestCase
from api.tests import flush_db_load_fixture
from api import test_data
from api.models import AuthEvent, UserData
from authmethods.models import Code

class BaseBulkInsertVoters(TestCase):
    def setUpTestData():
        flush_db_load_fixture()

    def call_command(self, *args, **kwargs):
        out = StringIO()
        call_command(
            "bulk_insert_voters",
            *args,
            stdout=out,
            stderr=StringIO(),
            **kwargs,
        )
        return out.getvalue()

    def setUp(self):
        ae = AuthEvent(
            auth_method="email",
            auth_method_config=test_data.authmethod_config_email_default,
            extra_fields=test_data.ae_email_default['extra_fields'],
            status='started',
            census="open"
        )
        ae.save()
        self.ae = ae
        self.aeid = ae.pk

class SimpleBulkInsertVoters(BaseBulkInsertVoters):
    def test_insert_users_base(self):
        self.assertEqual(UserData.objects.filter(event_id=self.ae.id).count(), 0)
        self.call_command(self.ae.id, "api/fixtures/bulk_users_base.csv")
        self.assertEqual(UserData.objects.filter(event_id=self.ae.id).count(), 2)

class FixedCaseBulkInsertVoters(BaseBulkInsertVoters):
    def test_insert_users_fixed_code(self):
        # set fixed code for election
        self.ae.auth_method_config['config']['fixed-code'] = True
        self.ae.save()

        self.assertEqual(UserData.objects.filter(event_id=self.ae.id).count(), 0)
        self.call_command(self.ae.id, "api/fixtures/bulk_users_fixed_code.csv")
        usersdata = UserData.objects.filter(event_id=self.ae.id)
        self.assertEqual(UserData.objects.filter(event_id=self.ae.id).count(), 2)
        self.assertEqual(Code.objects.filter(auth_event_id=self.ae.id, is_enabled=True).count(), 2)
        self.assertEqual(usersdata[0].user.email, "john@example.com")
        user_code1 = Code.objects.get(auth_event_id=self.ae.id, user=usersdata[0], is_enabled=True)
        self.assertEqual(user_code1.code, "22224444")
        self.assertEqual(usersdata[1].user.email, "adam@test.com")
        user_code2 = Code.objects.get(auth_event_id=self.ae.id, user=usersdata[1], is_enabled=True)
        self.assertEqual(user_code2.code, "77775555")

        del self.ae.auth_method_config['config']['fixed-code']
        self.ae.save()

class ExtraFieldsBulkInsertVoters(BaseBulkInsertVoters):
    def setUp(self):
        ae = AuthEvent(
            auth_method="email",
            auth_method_config=test_data.authmethod_config_email_default,
            extra_fields=test_data.auth_event1['extra_fields'],
            status='started',
            census="open"
        )
        ae.save()
        self.ae = ae
        self.aeid = ae.pk

    def test_insert_users_extra_fields(self):
        self.assertEqual(UserData.objects.filter(event_id=self.ae.id).count(), 0)
        self.call_command(self.ae.id, "api/fixtures/bulk_users_extra_fields.csv")
        usersdata = UserData.objects.filter(event_id=self.ae.id)
        self.assertEqual(UserData.objects.filter(event_id=self.ae.id).count(), 2)
        self.assertEqual(usersdata[0].user.email, "john@example.com")
        self.assertEqual(usersdata[0].metadata["name"], "John Fuentes")
        self.assertEqual(usersdata[0].metadata["dni"], "44044873A")
        self.assertEqual(usersdata[0].tlf, "+34654342312")