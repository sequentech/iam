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

import json
import os
from django.conf import settings
from django.contrib.auth.models import User
from django.test import TestCase
from django.test.utils import override_settings

from api import test_data
from api.models import ACL, AuthEvent
from api.tests import JClient
from authmethods.models import Code
from captcha.models import Captcha

# Create your tests here.

class TestProcessCaptcha(TestCase):
    fixtures = ['initial.json']
    def setUp(self):
        ae = AuthEvent(auth_method="email",
                auth_method_config=test_data.authmethod_config_email_default,
                extra_fields=test_data.ae_email_fields_captcha['extra_fields'],
                status='started',
                census="open")
        ae.save()
        self.ae = ae
        self.aeid = ae.pk

        u = User(username='test', email=test_data.auth_email_default['email'])
        u.save()
        u.userdata.event = ae
        u.userdata.save()

        acl = ACL(user=u.userdata, object_type='AuthEvent', perm='edit',
            object_id=self.aeid)
        acl.save()

        c = Code(user=u.userdata, code=test_data.auth_email_default['code'], auth_event_id=self.aeid)
        c.save()
        self.code = c

    def tearDown(self):
        # Removed generated captchas
        captcha_dir = settings.STATIC_ROOT + '/captcha/'
        captchas = [f for f in os.listdir(captcha_dir) if f.endswith('.png') ]
        for c in captchas:
            os.remove(captcha_dir + c)


    def test_create_new_captcha(self):
        c = JClient()
        self.assertEqual(0, Captcha.objects.count())
        response = c.get('/api/captcha/new/', {})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(1, Captcha.objects.count())

    @override_settings(CELERY_EAGER_PROPAGATES_EXCEPTIONS=True,
                       CELERY_ALWAYS_EAGER=True,
                       BROKER_BACKEND='memory')
    def _test_pregenerate_captchas(self):
        self.assertEqual(0, Captcha.objects.count())

        c = JClient()
        c.authenticate(0, test_data.admin)
        response = c.post('/api/auth-event/', test_data.ae_email_fields_captcha)
        self.assertEqual(response.status_code, 200)

        self.assertEqual(settings.PREGENERATION_CAPTCHA, Captcha.objects.filter(used=False).count())

    @override_settings(CELERY_ALWAYS_EAGER=True)
    def test_create_authevent_email_with_captcha(self):
        c = JClient()

        # add census without problem with captcha
        c.authenticate(self.aeid, test_data.auth_email_default)
        response = c.census(self.aeid, test_data.census_email_default)
        self.assertEqual(response.status_code, 200)
        response = c.get('/api/auth-event/%d/census/' % self.aeid, {})
        self.assertEqual(response.status_code, 200)
        r = json.loads(response.content.decode('utf-8'))
        self.assertEqual(len(r['object_list']), 4)

        # add register: without captcha
        response = c.register(self.aeid, test_data.register_email_fields)
        self.assertEqual(response.status_code, 400)
        r = json.loads(response.content.decode('utf-8'))
        self.assertEqual(r['error_codename'], 'invalid_credentials')

        # create captcha
        response = c.get('/api/captcha/new/', {})
        self.assertEqual(response.status_code, 200)
        captcha = Captcha.objects.all()[0]
        data = test_data.register_email_fields

        # add register: bad code
        data.update({'captcha_code': '', 'captcha': captcha.challenge})
        response = c.register(self.aeid, data)
        self.assertEqual(response.status_code, 400)
        r = json.loads(response.content.decode('utf-8'))
        self.assertEqual(r['error_codename'], 'invalid_credentials')

        # add register # TODO fix
        data.update({'captcha_code': captcha.code, 'captcha': captcha.challenge})
        response = c.register(self.aeid, data)
        self.assertEqual(response.status_code, 200)

        # add register: repeat captcha invalid
        response = c.register(self.aeid, data)
        self.assertEqual(response.status_code, 400)
        r = json.loads(response.content.decode('utf-8'))
        self.assertEqual(r['error_codename'], 'invalid_credentials')

        # create captcha
        response = c.get('/api/captcha/new/', {})
        self.assertEqual(response.status_code, 200)
        captcha = Captcha.objects.all()[0]
        data = test_data.register_email_fields

        # add register: bad challenge
        data.update({'captcha_code': captcha.code, 'captcha': ''})
        response = c.register(self.aeid, data)
        self.assertEqual(response.status_code, 400)
        r = json.loads(response.content.decode('utf-8'))
        self.assertEqual(r['error_codename'], 'invalid_credentials')

    @override_settings(CELERY_ALWAYS_EAGER=True)
    def _test_create_authevent_sms_with_captcha(self):
        self.ae.auth_method = 'sms'
        self.ae.auth_method_config = test_data.authmethod_config_sms_default
        self.ae.save()
        c = JClient()


        # add census without problem with captcha
        c.authenticate(0, test_data.admin)
        response = c.census(self.aeid, test_data.census_sms_default)
        self.assertEqual(response.status_code, 200)
        response = c.get('/api/auth-event/%d/census/' % self.aeid, {})
        self.assertEqual(response.status_code, 200)
        r = json.loads(response.content.decode('utf-8'))
        self.assertEqual(len(r['object_list']), 4)

        # add register: without captcha
        response = c.register(self.aeid, test_data.register_email_fields)
        self.assertEqual(response.status_code, 400)
        r = json.loads(response.content.decode('utf-8'))
        self.assertEqual(r['error_codename'], 'invalid_credentials')

        # create captcha
        response = c.get('/api/captcha/new/', {})
        self.assertEqual(response.status_code, 200)
        captcha = Captcha.objects.all()[0]
        data = test_data.register_sms_default
        data.update({'tlf': '999999999'})

        # add register: bad code
        data.update({'captcha_code': '', 'captcha': captcha.challenge})
        response = c.register(self.aeid, data)
        self.assertEqual(response.status_code, 400)
        r = json.loads(response.content.decode('utf-8'))
        self.assertEqual(r['error_codename'], 'invalid_credentials')

        # add register # TODO fix
        data.update({'captcha_code': captcha.code, 'captcha': captcha.challenge})
        response = c.register(self.aeid, data)
        self.assertEqual(response.status_code, 200)

        # add register: repeat captcha invalid
        response = c.register(self.aeid, data)
        self.assertEqual(response.status_code, 400)
        r = json.loads(response.content.decode('utf-8'))
        self.assertEqual(r['error_codename'], 'invalid_credentials')

        # create captcha
        response = c.get('/api/captcha/new/', {})
        self.assertEqual(response.status_code, 200)
        captcha = Captcha.objects.all()[0]
        data = test_data.register_sms_fields
        data.update({'tlf': '888888888'})

        # add register: bad challenge
        data.update({'captcha_code': captcha.code, 'captcha': ''})
        response = c.register(self.aeid, data)
        self.assertEqual(response.status_code, 400)
        r = json.loads(response.content.decode('utf-8'))
        self.assertEqual(r['error_codename'], 'invalid_credentials')

    def test_get_new_captcha_generate_other_captcha(self):
        self.assertEqual(Captcha.objects.count(), 0)
        self.assertEqual(Captcha.objects.filter(used=True).count(), 0)

        c = JClient()
        response = c.get('/api/captcha/new/', {})
        self.assertEqual(response.status_code, 200)
        r = json.loads(response.content.decode('utf-8'))
        self.assertTrue(r['image_url'] and r['captcha_code'])
        response = c.get('/api/captcha/new/', {})
        self.assertEqual(response.status_code, 200)
        r = json.loads(response.content.decode('utf-8'))
        self.assertTrue(r['image_url'] and r['captcha_code'])

        self.assertEqual(Captcha.objects.count(), 2)
        self.assertEqual(Captcha.objects.filter(used=True).count(), 2)
