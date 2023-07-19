# This file is part of iam.
# Copyright (C) 2014-2023  Sequent Tech Inc <legal@sequentech.io>

# iam is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License.

# iam  is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.

# You should have received a copy of the GNU Affero General Public License
# along with iam.  If not, see <http://www.gnu.org/licenses/>.

from django.conf import settings
from django.contrib.auth.models import User
from django.core import mail
from django.test import TestCase
from django.test.utils import override_settings

import json
import time
from datetime import datetime
from api import test_data
from api.tests import JClient, flush_db_load_fixture
from api.models import AuthEvent, ACL, UserData, SuccessfulLogin
from .m_email import Email
from .m_sms import Sms
from .models import Message, Code
from utils import genhmac, ErrorCodes


class AuthMethodTestCase(TestCase):
    def setUpTestData():
        flush_db_load_fixture()

    def setUp(self):
        ae = AuthEvent(
            auth_method=test_data.auth_event4['auth_method'],
            extra_fields=test_data.auth_event4['extra_fields'],
            status='started',
            census=test_data.auth_event4['census'],
            auth_method_config=test_data.authmethod_config_email_default
        )
        ae.save()
        self.aeid = ae.pk

        u = User(
            username=test_data.admin['username'],
            email=test_data.admin['email']
        )
        u.set_password(test_data.pwd_auth['password'])
        u.save()
        u.userdata.event = ae
        u.userdata.save()
        self.userid = u.pk


    def test_method_custom_view(self):
        c = JClient()
        response = c.authenticate(self.aeid, test_data.pwd_auth)
        self.assertEqual(response.status_code, 200)
        r = json.loads(response.content.decode('utf-8'))
        self.assertEqual(r['status'], 'ok')

        data = { 'email': 'test@sequentech.io', 'password': 'cxzvcx' }
        response = c.authenticate(self.aeid, data)
        self.assertEqual(response.status_code, 400)

    def test_ping(self):
        c = JClient()
        response = c.authenticate(self.aeid, test_data.pwd_auth)
        self.assertEqual(response.status_code, 200)
        response = c.get('/api/auth-event/%s/ping/' % self.aeid, {})
        self.assertEqual(response.status_code, 200)
        r = json.loads(response.content.decode('utf-8'))
        self.assertTrue(r['auth-token'].startswith('khmac:///sha-256'))


class AuthMethodEmailTestCase(TestCase):
    def setUpTestData():
        flush_db_load_fixture()

    def setUp(self):
        auth_method_config = test_data.authmethod_config_email_default
        ae = AuthEvent(
            auth_method=test_data.auth_event3['auth_method'],
            extra_fields=test_data.auth_event3['extra_fields'],
            auth_method_config=auth_method_config,
            status='started',
            census=test_data.auth_event3['census']
        )
        ae.save()
        self.aeid = ae.pk

        u = User(username='test1', email='test1@sequentech.io')
        u.save()
        u.userdata.event = ae
        u.userdata.metadata = {
                'email': 'test@test.com',
                'code': 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
                'email_verified': True
        }
        u.userdata.save()
        self.userid = u.pk

        acl = ACL(
            user=u.userdata,
            object_type='AuthEvent',
            perm='edit',
            object_id=ae.pk
        )
        acl.save()

        u2 = User(email='test2@sequentech.io')
        u2.is_active = False
        u2.save()
        u2.userdata.event = ae
        u2.userdata.metadata = {
                'email': 'test2@test.com',
                'code': 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
                'email_verified': False
        }
        u2.userdata.save()

        code = Code(
            user=u.userdata,
            code='AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
            auth_event_id=ae.pk
        )
        code.save()
        code = Code(
            user=u2.userdata,
            code='AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
            auth_event_id=ae.pk
        )
        code.save()


    @override_settings(CELERY_EAGER_PROPAGATES_EXCEPTIONS=True,
                       CELERY_ALWAYS_EAGER=True,
                       BROKER_BACKEND='memory')
    def test_method_email_register(self):
        c = JClient()
        data = {'email': 'test@test.com', 'user': 'test', 'code': 'AAAAAA'}
        response = c.register(self.aeid, data)
        self.assertEqual(response.status_code, 200)
        r = json.loads(response.content.decode('utf-8'))
        self.assertEqual(r['status'], 'ok')

    def test_method_email_invalid_code(self):
        code = 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'

        c = JClient()
        data = { 'userid': self.userid, 'code': code }
        response = c.authenticate(self.aeid, data)
        self.assertEqual(response.status_code, 400)

    def test_method_email_authenticate_valid_code(self):
        c = JClient()
        data = {
                'email': 'test1@sequentech.io',
                'code': 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
        }
        response = c.authenticate(self.aeid, data)
        self.assertEqual(response.status_code, 200)
        r = json.loads(response.content.decode('utf-8'))
        self.assertTrue(isinstance(r['username'], str))
        self.assertTrue(len(r['username']) > 0)
        self.assertTrue(r['auth-token'].startswith('khmac:///sha-256'))

    def test_method_email_authenticate_invalid_code(self):
        c = JClient()
        data = {
                'email': 'test2@sequentech.io',
                'code': 'AAAAAA'
        }
        response = c.authenticate(self.aeid, data)
        self.assertEqual(response.status_code, 400)

    def test_method_email_authenticate_tilde(self):
        email = "brüggemann@mail.com"

        # Register
        c = JClient()
        data = { "email": email, "user": "tilde" }
        response = c.register(self.aeid, data)
        self.assertEqual(response.status_code, 200)
        r = json.loads(response.content.decode("utf-8"))
        self.assertEqual(r["status"], "ok")

        code = Code.objects.get(user__user__email=email).code

        data = { "email": email, "code": code }
        response = c.authenticate(self.aeid, data)
        self.assertEqual(response.status_code, 200)
        r = json.loads(response.content.decode("utf-8"))
        self.assertTrue(isinstance(r["username"], str))
        self.assertTrue(len(r["username"]) > 0)
        self.assertTrue(r["auth-token"].startswith("khmac:///sha-256"))


class AuthMethodSmartLinkTestCase(TestCase):
    def setUpTestData():
        flush_db_load_fixture()

    def setUp(self):
        auth_method_config = test_data.authmethod_config_smart_link_default
        auth_event = AuthEvent(
          auth_method='smart-link',
          auth_method_config=auth_method_config,
          status='started',
          census='open',
          extra_fields=[
            dict(
              name="user_id",
              type="text",
              required=True,
              min=1,
              max=255,
              unique=True,
              required_on_authentication=True
            )
          ]
        )
        auth_event.save()
        self.auth_event = auth_event

        user = User(username='test1')
        user.save()
        user.userdata.event = auth_event
        user.userdata.metadata = {
          'user_id': 'test@example.com'
        }
        user.userdata.save()
        self.user = user

        acl = ACL(
          user=user.userdata,
          object_type='AuthEvent',
          perm='edit',
          object_id=auth_event.pk
        )
        acl.save()

        user2 = User(username='test2')
        user2.save()
        user2.userdata.event = auth_event
        user2.userdata.metadata = {
          'user_id': 'brüggemann@example.com'
        }
        user2.userdata.save()
        self.user2 = user2

    def test_authenticate_valid_auth_token(self):
        c = JClient()
        message = ':'.join([
          self.user.userdata.metadata['user_id'], 
          'AuthEvent', 
          str(self.auth_event.id), 
          'vote'
        ])
        data = {
          'auth-token': genhmac(
            key=settings.SHARED_SECRET,
            msg=message
          )
        }
        response = c.authenticate(self.auth_event.id, data)
        self.assertEqual(response.status_code, 200)
        r = json.loads(response.content.decode('utf-8'))
        self.assertEqual(r['username'], self.user.username)
        self.assertTrue(r['auth-token'].startswith('khmac:///sha-256'))

    def test_authenticate_invalid_khmac(self):
        c = JClient()
        data = {
          'auth-token': 'this is an invalid khmac'
        }
        response = c.authenticate(self.auth_event.id, data)
        self.assertEqual(response.status_code, 400)

    def test_authenticate_valid_auth_token_tilde(self):
        c = JClient()
        message = ':'.join([
          self.user2.userdata.metadata['user_id'], 
          'AuthEvent', 
          str(self.auth_event.id), 
          'vote'
        ])
        data = {
          'auth-token': genhmac(
            key=settings.SHARED_SECRET,
            msg=message
          )
        }
        response = c.authenticate(self.auth_event.id, data)
        self.assertEqual(response.status_code, 200)
        r = json.loads(response.content.decode('utf-8'))
        self.assertEqual(r['username'], self.user2.username)
        self.assertTrue(r['auth-token'].startswith('khmac:///sha-256'))


class AuthMethodSmsTestCase(TestCase):
    def setUpTestData():
        flush_db_load_fixture()

    def setUp(self):
        auth_method_config = test_data.authmethod_config_sms_default
        ae = AuthEvent(auth_method=test_data.auth_event2['auth_method'],
                auth_method_config=auth_method_config,
                extra_fields=test_data.auth_event2['extra_fields'],
                status='started',
                census=test_data.auth_event2['census'])
        ae.save()
        self.aeid = ae.pk

        u = User(username='test1', email='test@test.com')
        u.save()
        u.userdata.event = ae
        u.userdata.tlf = '+34666666666'
        u.userdata.metadata = { 'dni': 'DNI11111111H' }
        u.userdata.save()
        self.u = u.userdata
        code = Code(user=u.userdata, code='AAAAAAAA', auth_event_id=ae.pk)
        code.save()
        m = Message(tlf=u.userdata.tlf, auth_event_id=ae.pk)
        m.save()

        acl = ACL(
            user=u.userdata, 
            object_type='AuthEvent', 
            perm='edit', 
            object_id=ae.pk)
        acl.save()

        u2 = User(email='test2@sequentech.io')
        u2.is_active = False
        u2.save()
        u2.userdata.tlf = '+34766666666'
        u2.userdata.event = ae
        u2.userdata.metadata = { 'dni': 'DNI11111111H' }
        u2.userdata.save()
        code = Code(user=u2.userdata, code='AAAAAAAA', auth_event_id=ae.pk)
        code.save()
        self.c = JClient()

    @override_settings(CELERY_EAGER_PROPAGATES_EXCEPTIONS=True,
                       CELERY_ALWAYS_EAGER=True,
                       BROKER_BACKEND='memory')
    def test_method_sms_register(self):
        data = {'tlf': '+34666666667', 'code': 'AAAAAAAA',
                    'email': 'test1@test.com', 'dni': '11111111H'}
        response = self.c.register(self.aeid, data)
        self.assertEqual(response.status_code, 200)
        r = json.loads(response.content.decode('utf-8'))
        self.assertEqual(r['status'], 'ok')

    @override_settings(CELERY_EAGER_PROPAGATES_EXCEPTIONS=True,
                       CELERY_ALWAYS_EAGER=True,
                       BROKER_BACKEND='memory')
    def test_method_sms_register_valid_dni(self):
        data = {'tlf': '+34666666666', 'code': 'AAAAAAAA', 'dni': '11111111H'}
        response = self.c.register(self.aeid, data)
        self.assertEqual(response.status_code, 400)
        r = json.loads(response.content.decode('utf-8'))
        self.assertEqual(r['message'].find('Invalid dni'), -1)

    def test_method_sms_register_invalid_dni(self):
        data = {'tlf': '+34666666667', 'code': 'AAAAAAAA', 'dni': '999', 'email': 'test2@test.com'}
        response = self.c.register(self.aeid, data)
        self.assertEqual(response.status_code, 400)
        r = json.loads(response.content.decode('utf-8'))
        self.assertEqual(r['error_codename'], 'invalid_credentials')

    def test_method_sms_register_valid_email(self):
        data = {'tlf': '+34666666666', 'code': 'AAAAAAAA',
                'email': 'test@test.com'}
        response = self.c.register(self.aeid, data)
        self.assertEqual(response.status_code, 400)
        r = json.loads(response.content.decode('utf-8'))
        self.assertEqual(r['message'].find('Invalid email'), -1)

    def test_method_sms_register_invalid_email(self):
        data = {'tlf': '+34666666667', 'code': 'AAAAAAAA', 'email': 'test@@', 'dni': '11111111H'}
        response = self.c.register(self.aeid, data)
        self.assertEqual(response.status_code, 400)
        r = json.loads(response.content.decode('utf-8'))
        self.assertEqual(r['error_codename'], 'invalid_credentials')

    def test_method_sms_valid_code(self):
        data = {'tlf': '+34666666666', 'code': 'AAAAAAAA', 'dni': '11111111H', 'email': 'test@test.com'}
        response = self.c.authenticate(self.aeid, data)
        self.assertEqual(response.status_code, 200)
        r = json.loads(response.content.decode('utf-8'))
        self.assertEqual(r['status'], 'ok')
        self.assertTrue(isinstance(r['username'], str))
        self.assertTrue(len(r['username']) > 0)
        #self.assertGreaterEqual(Connection.objects.filter(tlf='+34666666666').count(), 1)
        self.assertTrue(r['auth-token'].startswith('khmac:///sha-256'))

    def _test_method_sms_valid_code_timeout(self):
        # TODO: check created in code for give code_timeout
        time.sleep(test_data.pipe_timestamp)
        data = {'tlf': '+34666666666', 'code': 'AAAAAAAA', 'dni': '11111111H', 'email': 'test@test.com'}
        response = self.c.authenticate(self.aeid, data)
        self.assertEqual(response.status_code, 400)
        r = json.loads(response.content.decode('utf-8'))
        self.assertEqual(r['message'], 'Incorrect data')

    def test_method_sms_invalid_code(self):
        data = {'tlf': '+34666666666', 'code': 'BBBBBBBB', 'dni': '11111111H', 'email': 'test@test.com'}
        response = self.c.authenticate(self.aeid, data)
        self.assertEqual(response.status_code, 400)
        r = json.loads(response.content.decode('utf-8'))
        self.assertEqual(r['error_codename'], ErrorCodes.INVALID_CODE)

    def test_method_sms_get_perm(self): # Fix
        auth = { 'tlf': '+34666666666', 'code': 'AAAAAAAA',
                'email': 'test@test.com', 'dni': '11111111H'}
        data1 = { "object_type": "Vote", "permission": "create", "object_id":
                self.aeid}
        data2 = { "object_type": "Vote", "permission": "remove", "object_id":
                self.aeid}

        response = self.c.post('/api/get-perms', data1)
        self.assertEqual(response.status_code, 301)
        response = self.c.post('/api/get-perms', data2)
        self.assertEqual(response.status_code, 301)

        acl = ACL(user=self.u, object_type='Vote', perm='create',
                object_id=self.aeid)
        acl.save()
        response = self.c.authenticate(self.aeid, auth)
        r = json.loads(response.content.decode('utf-8'))
        self.assertEqual(response.status_code, 200)
        self.assertTrue(isinstance(r['username'], str))
        self.assertTrue(len(r['username']) > 0)
        response = self.c.post('/api/get-perms/', data1)
        self.assertEqual(response.status_code, 200)
        response = self.c.post('/api/get-perms/', data2)
        self.assertEqual(response.status_code, 400)

    def test_method_sms_authenticate_valid_code(self):
        data = { 'tlf': '+34666666666', 'code': 'AAAAAAAA',
                'email': 'test@test.com', 'dni': '11111111H'}
        response = self.c.authenticate(self.aeid, data)
        r = json.loads(response.content.decode('utf-8'))
        self.assertTrue(isinstance(r['username'], str))
        self.assertTrue(len(r['username']) > 0)
        self.assertEqual(response.status_code, 200)
        r = json.loads(response.content.decode('utf-8'))
        self.assertTrue(r['auth-token'].startswith('khmac:///sha-256'))

    def test_method_sms_authenticate_invalid_code(self):
        data = {
                'email': 'test2@sequentech.io',
                'code': 'AAAAAA'
        }
        response = self.c.authenticate(self.aeid, data)
        self.assertEqual(response.status_code, 400)

    @override_settings(CELERY_EAGER_PROPAGATES_EXCEPTIONS=True,
                       CELERY_ALWAYS_EAGER=True,
                       BROKER_BACKEND='memory')        
    def test_send_sms_with_url2_msg(self):
        data = {'tlf': '+34666666667', 'code': 'AAAAAAAA',
                    'email': 'test1@test.com', 'dni': '11111111H'}
        response = self.c.register(self.aeid, data)
        self.assertEqual(response.status_code, 200)
        r = json.loads(response.content.decode('utf-8'))
        self.assertEqual(r['status'], 'ok')
        user_id = User.objects.filter(email=data['email'])[0].id
        import utils
        from authmethods.sms_provider import TestSMSProvider
        sms_count0 = TestSMSProvider.sms_count
        utils.send_codes(users=[user_id], ip='127.0.0.1',
                         config={'msg':'url[__URL2__], code[__CODE__]',
                                 'subject':'subject'})
        self.assertEqual(1+sms_count0, TestSMSProvider.sms_count)
        import re
        o = re.match('url\[(.+)\], code\[([-2-9]+)\]', TestSMSProvider.last_sms.get('content'))
        self.assertEqual(2, len(o.groups()))
        test_url = 'public/login/\\' + data.get('tlf') + '/' + o.groups()[1].replace("-","")
        e = re.search(test_url, o.groups()[0])
        self.assertTrue(e.group(0) == test_url.replace('\\',''))


class ExtraFieldPipelineTestCase(TestCase):
    def setUpTestData():
        flush_db_load_fixture()

    def setUp(self):
        auth_method_config = {
                "config": Email.CONFIG,
                "pipeline": Email.PIPELINES
        }
        ae = AuthEvent(auth_method=test_data.auth_event6['auth_method'],
                auth_method_config=auth_method_config,
                extra_fields=test_data.auth_event6['extra_fields'],
                status='started', census=test_data.auth_event6['census'])
        ae.save()
        self.aeid = ae.pk

        # Create admin user for authevent6
        u = User(email='admin6@sequentech.io')
        u.save()
        u.userdata.event = ae
        u.userdata.save()
        acl = ACL(user=u.userdata, object_type='AuthEvent', perm='edit', object_id=ae.pk)
        acl.save()

    @override_settings(CELERY_ALWAYS_EAGER=True)
    def test_method_extra_field_pipeline(self):
        c = JClient()
        data = {'email': 'test@test.com', 'user': 'test',
                'dni': '39873625C'}
        response = c.register(self.aeid, data)
        self.assertEqual(response.status_code, 200)
        user = UserData.objects.get(user__email=data['email'])
        self.assertEqual(user.metadata.get('dni'), 'DNI39873625C')

        data = {'email': 'test1@test.com', 'user': 'test',
                'dni': '39873625c'}
        response = c.register(self.aeid, data)
        self.assertEqual(response.status_code, 200)
        user = UserData.objects.get(user__email=data['email'])
        self.assertEqual(user.metadata.get('dni'), 'DNI39873625C')

        data = {'email': 'test2@test.com', 'user': 'test',
                'dni': '39873625X'}
        response = c.register(self.aeid, data)
        self.assertEqual(response.status_code, 400)

class PreRegisterTestCaseEmail(TestCase):
    def setUpTestData():
        flush_db_load_fixture()

    def setUp(self):
        auth_method_config = {
                "config": Email.CONFIG,
                "pipeline": Email.PIPELINES
        }
        ae = AuthEvent(
            auth_method=test_data.auth_event8['auth_method'],
            auth_method_config=auth_method_config,
            extra_fields=test_data.auth_event8['extra_fields'],
            status='started', census=test_data.auth_event8['census']
        )
        ae.save()
        self.aeid = ae.pk

        # Create user for authevent8
        u = User(username='test1', email='test@sequentech.io', is_active=True)
        u.save()
        u.userdata.event = ae
        u.userdata.metadata = {
                'email': 'test@sequentech.io',
                'email_verified': True,
                'match_field': 'match_code_555',
                'fill_field': ''
        }
        u.userdata.save()
        self.userid = u.pk
        acl = ACL(
            user=u.userdata,
            object_type='AuthEvent',
            perm='edit',
            object_id=ae.pk
        )
        acl.save()
        code = Code(
            user=u.userdata,
            code='AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
            auth_event_id=ae.pk
        )
        code.save()

    @override_settings(CELERY_EAGER_PROPAGATES_EXCEPTIONS=True,
                       CELERY_ALWAYS_EAGER=True,
                       BROKER_BACKEND='memory')
    def test_ok_match(self):
        c = JClient()
        data = {
             'email': 'test@sequentech.io', 
             'user': 'test1',
             'code': 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
             'match_field': 'wrong-code',
             'fill_field': 'filled'
        }
        response = c.register(self.aeid, data)
        # no pre-registered user matches to the 'match_field' field
        self.assertEqual(response.status_code, 400)
        data = {
             'email': 'test@sequentech.io', 
             'user': 'test1',
             'code': 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
             'match_field': 'match_code_555',
             'fill_field': ''
        }
        # the fill_field is not filled
        response = c.register(self.aeid, data)
        self.assertEqual(response.status_code, 400)
        data = {
             'email': 'test@sequentvotin.com', 
             'user': 'test1',
             'code': 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
             'match_field': 'match_code_555',
             'fill_field': 'filled'
        }
        response = c.register(self.aeid, data)
        # the email field doesn't match with any of the pre-registered users
        self.assertEqual(response.status_code, 400)
        data = {
             'email': 'test@sequentech.io', 
             'user': 'test1',
             'code': 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
             'match_field': 'match_code_555',
             'fill_field': 'filled'
        }
        response = c.register(self.aeid, data)
        self.assertEqual(response.status_code, 200)

class PreRegisterTestCaseFillEmail(TestCase):
    def setUpTestData():
        flush_db_load_fixture()

    def setUp(self):
        auth_method_config = {
                "config": Email.CONFIG,
                "pipeline": Email.PIPELINES
        }
        ae = AuthEvent(auth_method=test_data.auth_event9['auth_method'],
                auth_method_config=auth_method_config,
                extra_fields=test_data.auth_event9['extra_fields'],
                status='started', census=test_data.auth_event9['census'])
        ae.save()
        self.aeid = ae.pk

        # Create user for authevent9
        u = User(username='test1', email='', is_active=True)
        u.save()
        u.userdata.event = ae
        u.userdata.metadata = {
                'email': '',
                'email_verified': True,
                'match_field': 'match_code_555'
        }
        u.userdata.save()
        self.userid = u.pk
        acl = ACL(user=u.userdata, object_type='AuthEvent', perm='edit', object_id=ae.pk)
        acl.save()
        code = Code(user=u.userdata, code='AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA', auth_event_id=ae.pk)
        code.save()

    @override_settings(CELERY_EAGER_PROPAGATES_EXCEPTIONS=True,
                       CELERY_ALWAYS_EAGER=True,
                       BROKER_BACKEND='memory')
    def test_ok_match(self):
        c = JClient()
        data = {
             'email': 'test@sequentech.io', 
             'user': 'test1',
             'code': 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
             'match_field': 'wrong-code'
        }
        response = c.register(self.aeid, data)
        # no pre-registered user matches with the 'match_field' field
        self.assertEqual(response.status_code, 400)
        data = {
             'email': '', 
             'user': 'test1',
             'code': 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
             'match_field': 'match_code_555'
        }
        # the email is not filled but it's required, even when not listed as a match field
        response = c.register(self.aeid, data)
        self.assertEqual(response.status_code, 400)
        data = {
             'email': 'test@sequentech.io', 
             'user': 'test1',
             'code': 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
             'match_field': 'match_code_555'
        }
        response = c.register(self.aeid, data)
        self.assertEqual(response.status_code, 200)

class PreRegisterTestCaseTlf(TestCase):
    def setUpTestData():
        flush_db_load_fixture()

    def setUp(self):
        auth_method_config = test_data.authmethod_config_sms_default
        ae = AuthEvent(auth_method=test_data.auth_event10['auth_method'],
                auth_method_config=auth_method_config,
                extra_fields=test_data.auth_event10['extra_fields'],
                status='started', census=test_data.auth_event10['census'])
        ae.save()
        self.aeid = ae.pk

        # Create user for authevent10
        u = User(username='test1', email='test@sequentech.io', is_active=True)
        u.save()
        u.userdata.event = ae
        u.userdata.tlf = '+34666666666'
        u.userdata.metadata = {
                'match_field': 'match_code_555',
                'fill_field': ''
        }
        u.userdata.save()
        self.userid = u.pk
        acl = ACL(user=u.userdata, object_type='AuthEvent', perm='edit', object_id=ae.pk)
        acl.save()
        code = Code(user=u.userdata, code='AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA', auth_event_id=ae.pk)
        code.save()

    @override_settings(CELERY_EAGER_PROPAGATES_EXCEPTIONS=True,
                       CELERY_ALWAYS_EAGER=True,
                       BROKER_BACKEND='memory')
    def test_ok_match(self):
        c = JClient()
        data = {
             'tlf': '+34666666666',
             'user': 'test1',
             'code': 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
             'match_field': 'wrong-code',
             'fill_field': 'filled'
        }
        response = c.register(self.aeid, data)
        # no pre-registered user matches to the 'match_field' field
        self.assertEqual(response.status_code, 400)
        data = {
             'tlf': '+34666666666',
             'user': 'test1',
             'code': 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
             'match_field': 'match_code_555',
             'fill_field': ''
        }
        # the fill_field is not filled
        response = c.register(self.aeid, data)
        self.assertEqual(response.status_code, 400)
        data = {
             'tlf': '+34666666667',
             'user': 'test1',
             'code': 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
             'match_field': 'match_code_555',
             'fill_field': 'filled'
        }
        response = c.register(self.aeid, data)
        # the tlf field doesn't match with any of the pre-registered users
        self.assertEqual(response.status_code, 400)
        data = {
             'tlf': '+34666666666',
             'user': 'test1',
             'code': 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
             'match_field': 'match_code_555',
             'fill_field': 'filled'
        }
        response = c.register(self.aeid, data)
        self.assertEqual(response.status_code, 200)


class PreRegisterTestCaseFillTlf(TestCase):
    def setUpTestData():
        flush_db_load_fixture()

    def setUp(self):
        auth_method_config = test_data.authmethod_config_sms_default
        ae = AuthEvent(auth_method=test_data.auth_event11['auth_method'],
                auth_method_config=auth_method_config,
                extra_fields=test_data.auth_event11['extra_fields'],
                status='started', census=test_data.auth_event11['census'])
        ae.save()
        self.aeid = ae.pk

        # Create user for authevent11
        u = User(username='test1', email='test@sequentech.io', is_active=True)
        u.save()
        u.userdata.event = ae
        u.userdata.tlf = None
        u.userdata.metadata = {
                'match_field': 'match_code_555'
        }
        u.userdata.save()
        self.userid = u.pk
        acl = ACL(user=u.userdata, object_type='AuthEvent', perm='edit', object_id=ae.pk)
        acl.save()
        code = Code(user=u.userdata, code='AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA', auth_event_id=ae.pk)
        code.save()

    @override_settings(CELERY_EAGER_PROPAGATES_EXCEPTIONS=True,
                       CELERY_ALWAYS_EAGER=True,
                       BROKER_BACKEND='memory')
    def test_ok_match(self):
        c = JClient()
        data = {
             'tlf': '+34666666666',
             'user': 'test1',
             'code': 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
             'match_field': 'wrong-code'
        }
        response = c.register(self.aeid, data)
        # no pre-registered user matches with the 'match_field' field
        self.assertEqual(response.status_code, 400)
        data = {
             'tlf': '',
             'user': 'test1',
             'code': 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
             'match_field': 'match_code_555'
        }
        # the tlf is not filled but it's required, even when it's not listed as a match field
        response = c.register(self.aeid, data)
        self.assertEqual(response.status_code, 400)
        data = {
             'tlf': '+34666666666',
             'user': 'test1',
             'code': 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
             'match_field': 'match_code_555'
        }
        response = c.register(self.aeid, data)
        self.assertEqual(response.status_code, 200)


class ExternalCheckPipelineTestCase(TestCase):
    def setUpTestData():
        flush_db_load_fixture()

    def setUp(self):
        auth_method_config = {
                "config": Email.CONFIG,
                "pipeline": Email.PIPELINES
        }
        ae = AuthEvent(auth_method=test_data.auth_event7['auth_method'],
                auth_method_config=auth_method_config,
                extra_fields=test_data.auth_event7['extra_fields'],
                status='started', census=test_data.auth_event7['census'])
        ae.save()
        self.aeid = ae.pk

    @override_settings(CELERY_EAGER_PROPAGATES_EXCEPTIONS=True,
                       CELERY_ALWAYS_EAGER=True,
                       BROKER_BACKEND='memory')
    def _test_method_external_pipeline(self):
        # TODO: Fixed external api for validate dni, else is_active will be False
        c = JClient()
        data = {'email': 'test@test.com', 'user': 'test',
                'dni': '39873625C'}
        response = c.register(self.aeid, data)
        self.assertEqual(response.status_code, 200)

        u = User.objects.get(email='test@test.com')
        self.assertEqual(u.is_active, True)
        mdata = u.userdata.metadata
        self.assertEqual(mdata['external_data']['custom'], True)


class AdminGeneratedAuthCodes(TestCase):
    def setUpTestData():
        flush_db_load_fixture()

    def setUp(self):
        # configure admin auth event
        admin_auth_event = AuthEvent.objects.get(pk=1)
        admin_auth_event.auth_method = 'user-and-password'
        admin_auth_event.extra_fields = test_data.auth_event4['extra_fields']
        admin_auth_event.save()
        self.admin_auth_event_id = admin_auth_event.id

        # create superuser
        superuser = User(
            username=test_data.admin['username'],
            email=test_data.admin['email']
        )
        superuser.is_staff = True
        superuser.is_superuser = True
        superuser.set_password(test_data.admin['password'])
        superuser.save()
        superuser.userdata.event = admin_auth_event
        superuser.userdata.save()

    def _test_generate_codes(self, auth_event, voter, credentials):
        c = JClient()

        # authenticate with voter credentials should work
        response = c.authenticate(
            auth_event.id,
            credentials
        )
        self.assertEqual(response.status_code, 200)

        # authenticate as admin
        response = c.authenticate(self.admin_auth_event_id, test_data.admin)
        self.assertEqual(response.status_code, 200)

        # before generating code for voter, the voter should not marked as
        # use_generated_auth_code=True
        self.assertEqual(
            User.objects.get(pk=voter.id).userdata.use_generated_auth_code,
            False
        )

        # generate code for user
        response = c.post(
            '/api/auth-event/%d/generate-auth-code/' % auth_event.id,
            dict(
                username=voter.username
            )
        )
        # ensure code is there
        self.assertEqual(response.status_code, 200)
        generated_code = response.json()
        self.assertTrue(
            'code' in generated_code and 
            isinstance(generated_code['code'], str)
        )
        code = generated_code['code']

        # after generating code for voter, the voter should be marked as
        # use_generated_auth_code=True
        self.assertEqual(
            User.objects.get(pk=voter.id).userdata.use_generated_auth_code,
            True
        )

        # authenticate with voter credentials should not work anymore
        response = c.authenticate(
            auth_event.id,
            credentials
        )
        self.assertEqual(response.status_code, 400)

        # try to authenticate with a wrong admin-generated code after code
        # generation also should fail
        response = c.authenticate(
            auth_event.id,
            dict(
                __username=voter.username,
                code="erroneous-code456"
            )
        )
        self.assertEqual(response.status_code, 400)

        # try to authenticate with the correct code, fails because codes can
        # only be tested once
        response = c.authenticate(
            auth_event.id,
            dict(
                __username=voter.username,
                code=code
            )
        )
        self.assertEqual(response.status_code, 400)

        # authenticate as admin again
        c = JClient()
        response = c.authenticate(self.admin_auth_event_id, test_data.admin)
        self.assertEqual(response.status_code, 200)

        # generate code for user again
        response = c.post(
            '/api/auth-event/%d/generate-auth-code/' % auth_event.id,
            dict(
                username=voter.username
            )
        )
        self.assertEqual(response.status_code, 200)

        # ensure code is there again
        generated_code2 = response.json()
        code2 = generated_code2['code']

        # try to authenticate with the correct code, works
        response = c.authenticate(
            auth_event.id,
            dict(
                __username=voter.username,
                code=code2
            )
        )
        self.assertEqual(response.status_code, 200)

        # authenticate as admin again
        response = c.authenticate(self.admin_auth_event_id, test_data.admin)
        self.assertEqual(response.status_code, 200)

        # mark the voter as voted
        vote = SuccessfulLogin(
            created=datetime(2010, 10, 10, 0, 30, 30, 0, None),
            user=voter.userdata,
            auth_event=auth_event,
            is_active=True
        )
        vote.save()

        # generate code for voter should fail if voter has already voted
        response = c.post(
            '/api/auth-event/%d/generate-auth-code/' % auth_event.id,
            dict(
                username=voter.username
            )
        )
        self.assertEqual(response.status_code, 400)

    @override_settings(
        CELERY_EAGER_PROPAGATES_EXCEPTIONS=True,
        CELERY_ALWAYS_EAGER=True,
        BROKER_BACKEND='memory'
    )
    def test_generate_codes_email_otp(self):
        auth_event, voter, credentials = test_data.generate_auth_event_and_voter_credentials('email-otp')
        self._test_generate_codes(auth_event, voter, credentials)

    @override_settings(
        CELERY_EAGER_PROPAGATES_EXCEPTIONS=True,
        CELERY_ALWAYS_EAGER=True,
        BROKER_BACKEND='memory'
    )
    def test_generate_codes_email(self):
        auth_event, voter, credentials = test_data.generate_auth_event_and_voter_credentials('email')
        self._test_generate_codes(auth_event, voter, credentials)

    @override_settings(
        CELERY_EAGER_PROPAGATES_EXCEPTIONS=True,
        CELERY_ALWAYS_EAGER=True,
        BROKER_BACKEND='memory'
    )
    def test_generate_codes_email_and_password(self):
        auth_event, voter, credentials = test_data.generate_auth_event_and_voter_credentials('email-and-password')
        self._test_generate_codes(auth_event, voter, credentials)

    @override_settings(
        CELERY_EAGER_PROPAGATES_EXCEPTIONS=True,
        CELERY_ALWAYS_EAGER=True,
        BROKER_BACKEND='memory'
    )
    def test_generate_codes_user_and_password(self):
        auth_event, voter, credentials = test_data.generate_auth_event_and_voter_credentials('user-and-password')
        self._test_generate_codes(auth_event, voter, credentials)

    @override_settings(
        CELERY_EAGER_PROPAGATES_EXCEPTIONS=True,
        CELERY_ALWAYS_EAGER=True,
        BROKER_BACKEND='memory'
    )
    def test_generate_codes_smart_link(self):
        auth_event, voter, credentials = test_data.generate_auth_event_and_voter_credentials('smart-link')
        self._test_generate_codes(auth_event, voter, credentials)

    @override_settings(
        CELERY_EAGER_PROPAGATES_EXCEPTIONS=True,
        CELERY_ALWAYS_EAGER=True,
        BROKER_BACKEND='memory'
    )
    def test_generate_codes_sms_otp(self):
        auth_event, voter, credentials = test_data.generate_auth_event_and_voter_credentials('sms-otp')
        self._test_generate_codes(auth_event, voter, credentials)

    @override_settings(
        CELERY_EAGER_PROPAGATES_EXCEPTIONS=True,
        CELERY_ALWAYS_EAGER=True,
        BROKER_BACKEND='memory'
    )
    def test_generate_codes_sms(self):
        auth_event, voter, credentials = test_data.generate_auth_event_and_voter_credentials('sms')
        self._test_generate_codes(auth_event, voter, credentials)

class TestOTPCodeExtraField(TestCase):
    def setUpTestData():
        flush_db_load_fixture()

    def setUp(self):
        # configure admin auth event
        admin_auth_event = AuthEvent.objects.get(pk=1)
        admin_auth_event.auth_method = 'user-and-password'
        admin_auth_event.extra_fields = test_data.auth_event4['extra_fields']
        admin_auth_event.save()
        self.admin_auth_event_id = admin_auth_event.id

        # create superuser
        superuser = User(
            username=test_data.admin['username'],
            email=test_data.admin['email']
        )
        superuser.is_staff = True
        superuser.is_superuser = True
        superuser.set_password(test_data.admin['password'])
        superuser.save()
        superuser.userdata.event = admin_auth_event
        superuser.userdata.save()

    @override_settings(
        CELERY_EAGER_PROPAGATES_EXCEPTIONS=True,
        CELERY_ALWAYS_EAGER=True,
        BROKER_BACKEND='memory'
    )
    def test_resend_auth_codes_email(self):
        auth_event, voter, credentials = test_data\
            .generate_auth_event_and_voter_credentials('email')
        self._test_resend_auth_codes(
            auth_event,
            voter,
            credentials,
            resend_auth_codes_data=dict(
                email=voter.email
            ),
            source_field_name="email"
        )

    @override_settings(
        CELERY_EAGER_PROPAGATES_EXCEPTIONS=True,
        CELERY_ALWAYS_EAGER=True,
        BROKER_BACKEND='memory'
    )
    def test_resend_auth_codes_email_otp(self):
        auth_event, voter, credentials = test_data\
            .generate_auth_event_and_voter_credentials('email-otp')
        self._test_resend_auth_codes(
            auth_event,
            voter,
            credentials,
            resend_auth_codes_data=dict(
                email=voter.email
            ),
            source_field_name="email"
        )

    @override_settings(
        CELERY_EAGER_PROPAGATES_EXCEPTIONS=True,
        CELERY_ALWAYS_EAGER=True,
        BROKER_BACKEND='memory'
    )
    def test_resend_auth_codes_sms(self):
        auth_event, voter, credentials = test_data\
            .generate_auth_event_and_voter_credentials('sms')
        self._test_resend_auth_codes(
            auth_event,
            voter,
            credentials,
            resend_auth_codes_data=dict(
                tlf=voter.userdata.tlf
            ),
            source_field_name="tlf"
        )

    @override_settings(
        CELERY_EAGER_PROPAGATES_EXCEPTIONS=True,
        CELERY_ALWAYS_EAGER=True,
        BROKER_BACKEND='memory'
    )
    def test_resend_auth_codes_sms_otp(self):
        auth_event, voter, credentials = test_data\
            .generate_auth_event_and_voter_credentials('sms-otp')
        self._test_resend_auth_codes(
            auth_event,
            voter,
            credentials,
            resend_auth_codes_data=dict(
                tlf=voter.userdata.tlf
            ),
            source_field_name="tlf"
        )

    @override_settings(
        CELERY_EAGER_PROPAGATES_EXCEPTIONS=True,
        CELERY_ALWAYS_EAGER=True,
        BROKER_BACKEND='memory'
    )
    def test_resend_auth_codes_user_and_password(self):
        auth_event, voter, credentials = test_data\
            .generate_auth_event_and_voter_credentials('user-and-password')

        auth_event.extra_fields.append(
            {
                "name": "email",
                "type": "email",
                "required": False,
                "unique": True,
                "private": True,
                "min": 4,
                "max": 255,
                "required_on_authentication": False
            }
        )
        auth_event.save()

        voter.email = "test@sequentech.io"
        voter.save()

        self._test_resend_auth_codes(
            auth_event,
            voter,
            credentials,
            resend_auth_codes_data=dict(
                username=voter.username,
                password=credentials['password']
            ),
            source_field_name="email"
        )

    @override_settings(
        CELERY_EAGER_PROPAGATES_EXCEPTIONS=True,
        CELERY_ALWAYS_EAGER=True,
        BROKER_BACKEND='memory'
    )
    def test_resend_auth_codes_email_and_password(self):
        auth_event, voter, credentials = test_data\
            .generate_auth_event_and_voter_credentials('email-and-password')
        self._test_resend_auth_codes(
            auth_event,
            voter,
            credentials,
            resend_auth_codes_data=dict(
                email=voter.email,
                password=credentials['password']
            ),
            source_field_name="email"
        )

    @override_settings(
        CELERY_EAGER_PROPAGATES_EXCEPTIONS=True,
        CELERY_ALWAYS_EAGER=True,
        BROKER_BACKEND='memory'
    )
    def test_resend_auth_codes_smart_link(self):
        auth_event, voter, credentials = test_data\
            .generate_auth_event_and_voter_credentials('smart-link')

        auth_event.extra_fields.append(
            {
                "name": "email",
                "type": "email",
                "required": False,
                "unique": True,
                "min": 4,
                "max": 255,
                "required_on_authentication": True
            }
        )
        auth_event.save()

        voter.email = "test@sequentech.io"
        voter.save()
        credentials['email'] = voter.email

        self._test_resend_auth_codes(
            auth_event,
            voter,
            credentials,
            resend_auth_codes_data=dict(
                email=voter.email,
                user_id=voter.userdata.metadata['user_id']
            ),
            source_field_name="email"
        )

    def _test_resend_auth_codes(
        self,
        auth_event,
        voter,
        credentials,
        resend_auth_codes_data,
        source_field_name
    ):
        auth_event.auth_method_config['config']['allow_user_resend'] = False
        auth_event.auth_method_config['pipeline'] = {
            "give_perms": [
                {
                    'object_type': 'UserData',
                    'perms': ['edit',],
                    'object_id': 'UserDataId'
                },
                {
                    'object_type': 'AuthEvent',
                    'perms': ['vote',],
                    'object_id': 'AuthEventId'
                }
            ],
            "register-pipeline": [],
            "authenticate-pipeline": [],
            "resend-auth-pipeline": []
        }
        auth_event.save()
        client = JClient()
        initial_codes_count = voter.userdata.codes.count()

        # resend auth code should not work as this auth event is not email-otp
        # nor sms-otp and has no otp-code field 
        is_otp = auth_event.auth_method in ['email-otp', 'sms-otp']
        auth_event.save()
        response = client.post(
            f'/api/auth-event/{auth_event.id}/resend_auth_code/',
            resend_auth_codes_data
        )
        self.assertEqual(response.status_code, 200 if is_otp else 400)

        # Check that the number of codes associated with this voter did not
        # change
        expected_count = initial_codes_count + 1 if is_otp else initial_codes_count
        self.assertEqual(voter.userdata.codes.count(), expected_count)

        # add the otp-code field to the auth event
        auth_event.extra_fields.append(
            dict(
                name="otp-code",
                type="otp-code",
                required=False,
                min=1,
                max=255,
                unique=False,
                required_on_authentication=True,
                source_field=source_field_name,
                templates=dict(
                    message_body="Your code is __CODE__",
                    message_subject="Your OTP Code"
                )
            )
        )
        auth_event.save()

        # the resend_auth_code call should still fail because the auth event
        # does not have the allow_user_resend property enabled yet
        response = client.post(
            f'/api/auth-event/{auth_event.id}/resend_auth_code/',
            resend_auth_codes_data
        )
        self.assertEqual(response.status_code, 200 if is_otp else 400)

        # Check that the number of codes associated with this voter did not
        # change
        expected_count = expected_count + 1 if is_otp else initial_codes_count
        self.assertEqual(voter.userdata.codes.count(), expected_count)

        auth_event.auth_method_config['config']['allow_user_resend'] = True
        auth_event.save()

        # the resend_auth_code call should now work
        response = client.post(
            f'/api/auth-event/{auth_event.id}/resend_auth_code/',
            resend_auth_codes_data
        )
        self.assertEqual(response.status_code, 200)

        # Check that there's still one more new code associated with this voter
        expected_count = expected_count + 1 if is_otp else initial_codes_count + 1
        self.assertEqual(voter.userdata.codes.count(), expected_count)

        # get the code and authenticate with it
        code = voter.userdata.codes.order_by('-created')[0]
        credentials['code'] = code.code
        response = client.authenticate(auth_event.id, credentials)
        self.assertEqual(response.status_code, 200)

        # the code is one time: it cannot be reused so trying to login again 
        # with it fails
        response = client.authenticate(auth_event.id, credentials)
        self.assertEqual(response.status_code, 400)

        # if we try to login with a bogus code it also fails
        credentials['code'] = '11111111'
        response = client.authenticate(auth_event.id, credentials)
        self.assertEqual(response.status_code, 400)

        # but if we obtain a new one, we can use it to authenticate
        # the resend_auth_code call should now work
        response = client.post(
            f'/api/auth-event/{auth_event.id}/resend_auth_code/',
            resend_auth_codes_data
        )
        self.assertEqual(response.status_code, 200)

        expected_count = expected_count + 1 if is_otp else initial_codes_count + 2
        self.assertEqual(voter.userdata.codes.count(), expected_count)
        code = voter.userdata.codes.order_by('-created')[0]
        credentials['code'] = code.code
        response = client.authenticate(auth_event.id, credentials)
        self.assertEqual(response.status_code, 200)

        # generating a code from the admin api should work as any extra field
        # should not interfere there, and thus also authentication using that
        # admin-generated code should work too

        # authenticate as admin
        response = client.authenticate(
            self.admin_auth_event_id,
            test_data.admin
        )
        self.assertEqual(response.status_code, 200)

        # generate code for user
        response = client.post(
            '/api/auth-event/%d/generate-auth-code/' % auth_event.id,
            dict(
                username=voter.username
            )
        )
        # ensure code is there
        self.assertEqual(response.status_code, 200)
        generated_code = response.json()
        self.assertTrue(
            'code' in generated_code and
            isinstance(generated_code['code'], str)
        )
        code = generated_code['code']

        # authenticate with admin-generated voter credentials should work
        response = client.authenticate(
            auth_event.id,
            dict(
                __username=voter.username,
                code=code
            )
        )
        self.assertEqual(response.status_code, 200)
