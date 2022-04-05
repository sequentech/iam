# This file is part of iam.
# Copyright (C) 2014-2020  Sequent Tech Inc <legal@sequentech.io>

# iam is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License.

# iam  is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.

# You should have received a copy of the GNU Affero General Public License
# along with iam.  If not, see <http://www.gnu.org/licenses/>.

import json
from django.test import TestCase
from django.contrib.auth.models import User
from django.test.utils import override_settings

from api.models import ACL, AuthEvent, UserData
from api.tests import JClient, flush_db_load_fixture
from authmethods.models import Code
from captcha.models import Captcha
from captcha.views import newcaptcha


class TestFixtureSaas(TestCase):
    def setUpTestData():
        flush_db_load_fixture("saas.json")

    def setUp(self):
        self.ae = AuthEvent.objects.get(pk=1)

    @override_settings(CELERY_ALWAYS_EAGER=True)
    def test_register_user(self):

        captcha = newcaptcha()
        user = {
                'Email': 'test@sequentech.io',
                'tlf': '+34666666667',
                'captcha_code': captcha.code,
                'Captcha': captcha.challenge,
                'Acepto las <a href="https://sequentech.io/#tos">condiciones de servicio</a>': True,
        }
        c = JClient()
        init_users = UserData.objects.count()
        response = c.register(self.ae.pk, user)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(init_users + 1, UserData.objects.count())

        userdata = UserData.objects.get(tlf=user['tlf'], event=self.ae)
        self.assertTrue(ACL.objects.filter(user=userdata,
                object_type='UserData', perm='edit', object_id=userdata.pk))
        self.assertTrue(ACL.objects.filter(user=userdata,
                object_type='AuthEvent', perm='create'))


    def _test_authenticate_user(self):
        u = User.objects.create_user('test', 'test@sequentech.io', 'test')
        u.userdata.event = self.ae
        u.userdata.tlf = '+34666666667'
        u.userdata.save()

        acl = ACL(user=u.userdata, object_type='UserData', perm='edit', object_id=u.pk)
        acl.save()
        acl = ACL(user=u.userdata, object_type='AuthEvent', perm='create', object_id=0)
        acl.save()

        code = Code(user=u.userdata, code='ABCDEF', auth_event_id=self.ae.pk)
        code.save()

        auth = {
                'Email': 'test@sequentech.io',
                'tlf': '+34666666667',
                'code': code.code,
        }

        c = JClient()
        response = c.authenticate(1, auth)
        self.assertEqual(response.status_code, 200)
