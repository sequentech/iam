from django.contrib.auth.models import User
from django.core import mail
from django.test import TestCase
from django.test.utils import override_settings

import json
import time
from api import test_data
from api.tests import JClient
from api.models import AuthEvent, ACL
from .m_email import Email
from .m_sms import Sms
from .models import Message, Code, Connection


class AuthMethodTestCase(TestCase):
    fixtures = ['initial.json']
    def setUp(self):
        ae = AuthEvent(auth_method=test_data.auth_event4['auth_method'],
                status='started', census=test_data.auth_event4['census'])
        ae.save()
        self.aeid = ae.pk

        u = User(pk=1, username=test_data.pwd_auth['username'])
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

        data = { 'username': 'test', 'password': 'cxzvcx' }
        response = c.authenticate(self.aeid, data)
        self.assertEqual(response.status_code, 400)


class AuthMethodEmailTestCase(TestCase):
    fixtures = ['initial.json']
    def setUp(self):
        auth_method_config = test_data.authmethod_config_email_default
        ae = AuthEvent(auth_method=test_data.auth_event3['auth_method'],
                auth_method_config=auth_method_config,
                status='started', census=test_data.auth_event3['census'])
        ae.save()
        self.aeid = ae.pk

        u = User(pk=1, username='test1', email='test1@agoravoting.com')
        u.save()
        u.userdata.event = ae
        u.userdata.metadata = json.dumps({
                'email': 'test@test.com',
                'code': 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
                'email_verified': True
        })
        u.userdata.save()
        self.userid = u.pk

        u2 = User(pk=2, username='test2')
        u2.is_active = False
        u2.save()
        u2.userdata.event = ae
        u2.userdata.metadata = json.dumps({
                'email': 'test2@test.com',
                'code': 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
                'email_verified': False
        })
        u2.userdata.save()

        code = Code(user=u.userdata, code='AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA')
        code.save()
        code = Code(user=u2.userdata, code='AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA')
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
                'email': 'test1@agoravoting.com',
                'code': 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'
        }
        response = c.authenticate(self.aeid, data)
        self.assertEqual(response.status_code, 200)
        r = json.loads(response.content.decode('utf-8'))
        self.assertTrue(r['auth-token'].startswith('khmac:///sha-256'))

    def test_method_email_authenticate_invalid_code(self):
        c = JClient()
        data = {
                'email': 'test2@agoravoting.com',
                'code': 'AAAAAA'
        }
        response = c.authenticate(self.aeid, data)
        self.assertEqual(response.status_code, 400)


class AuthMethodSmsTestCase(TestCase):
    fixtures = ['initial.json']
    def setUp(self):
        auth_method_config = test_data.authmethod_config_sms_default
        ae = AuthEvent(auth_method=test_data.auth_event2['auth_method'],
                auth_method_config=auth_method_config,
                extra_fields=test_data.auth_event2['extra_fields'],
                status='started',
                census=test_data.auth_event2['census'])
        ae.save()
        self.aeid = ae.pk

        u = User(pk=1, username='test1', email='test@test.com')
        u.save()
        u.userdata.event = ae
        u.userdata.tlf = '+34666666666'
        u.userdata.metadata = json.dumps({ 'dni': '11111111H' })
        u.userdata.save()
        self.u = u.userdata
        code = Code(user=u.userdata, code='AAAAAAAA')
        code.save()
        m = Message(tlf=u.userdata.tlf)
        m.save()

        u2 = User(pk=2, username='test2', email='test2@agoravoting.com')
        u2.is_active = False
        u2.save()
        u2.userdata.tlf = '+34766666666'
        u2.userdata.event = ae
        u2.userdata.metadata = json.dumps({ 'dni': '11111111H' })
        u2.userdata.save()
        code = Code(user=u2.userdata, code='AAAAAAAA')
        code.save()
        self.c = JClient()

    @override_settings(CELERY_EAGER_PROPAGATES_EXCEPTIONS=True,
                       CELERY_ALWAYS_EAGER=True,
                       BROKER_BACKEND='memory')
    def test_method_sms_register(self):
        data = {'tlf': '+34666666667', 'code': 'AAAAAAAA',
                    'email': 'test@test.com', 'dni': '11111111H'}
        response = self.c.register(self.aeid, data)
        self.assertEqual(response.status_code, 200)
        r = json.loads(response.content.decode('utf-8'))
        self.assertEqual(r['status'], 'ok')

    def test_method_sms_register_valid_dni(self):
        data = {'tlf': '+34666666666', 'code': 'AAAAAAAA', 'dni': '11111111H'}
        response = self.c.register(self.aeid, data)
        self.assertEqual(response.status_code, 400)
        r = json.loads(response.content.decode('utf-8'))
        self.assertEqual(r['msg'].find('Invalid dni'), -1)

    def test_method_sms_register_invalid_dni(self):
        data = {'tlf': '+34666666666', 'code': 'AAAAAAAA', 'dni': '999', 'email': 'test@test.com'}
        response = self.c.register(self.aeid, data)
        self.assertEqual(response.status_code, 400)
        r = json.loads(response.content.decode('utf-8'))
        self.assertNotEqual(r['msg'].find('dni regex incorrect'), -1)

    def test_method_sms_register_valid_email(self):
        data = {'tlf': '+34666666666', 'code': 'AAAAAAAA',
                'email': 'test@test.com'}
        response = self.c.register(self.aeid, data)
        self.assertEqual(response.status_code, 400)
        r = json.loads(response.content.decode('utf-8'))
        self.assertEqual(r['msg'].find('Invalid email'), -1)

    def test_method_sms_register_invalid_email(self):
        data = {'tlf': '+34666666666', 'code': 'AAAAAAAA', 'email': 'test@@', 'dni': '11111111H'}
        response = self.c.register(self.aeid, data)
        self.assertEqual(response.status_code, 400)
        r = json.loads(response.content.decode('utf-8'))
        self.assertNotEqual(r['msg'].find('email regex incorrect'), -1)

    def test_method_sms_valid_code(self):
        data = {'tlf': '+34666666666', 'code': 'AAAAAAAA', 'dni': '11111111H', 'email': 'test@test.com'}
        response = self.c.authenticate(self.aeid, data)
        self.assertEqual(response.status_code, 200)
        r = json.loads(response.content.decode('utf-8'))
        self.assertEqual(r['status'], 'ok')
        #self.assertGreaterEqual(Connection.objects.filter(tlf='+34666666666').count(), 1)
        self.assertTrue(r['auth-token'].startswith('khmac:///sha-256'))

    def test_method_sms_valid_code_timeout(self): # Fix
        time.sleep(test_data.pipe_timestamp)
        data = {'tlf': '+34666666666', 'code': 'AAAAAAAA', 'dni': '11111111H', 'email': 'test@test.com'}
        response = self.c.authenticate(self.aeid, data)
        self.assertEqual(response.status_code, 400)
        r = json.loads(response.content.decode('utf-8'))
        self.assertEqual(r['message'], 'Invalid code.')

    def test_method_sms_invalid_code(self):
        data = {'tlf': '+34666666666', 'code': 'BBBBBBBB', 'dni': '11111111H', 'email': 'test@test.com'}
        response = self.c.authenticate(self.aeid, data)
        self.assertEqual(response.status_code, 400)
        r = json.loads(response.content.decode('utf-8'))
        self.assertEqual(r['message'], 'Invalid code.')

    def _test_method_sms_invalid_code_x_times(self):
        for i in range(test_data.pipe_times + 1):
            data = {'tlf': '+34666666666', 'code': 'BBBBBBBB', 'dni': '11111111H', 'email': 'test@test.com'}
            response = self.c.authenticate(self.aeid, data)
        self.assertEqual(response.status_code, 400)
        r = json.loads(response.content.decode('utf-8'))
        self.assertEqual(r['message'], 'Exceeded the level os attempts')

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
        self.assertEqual(response.status_code, 200)
        response = self.c.post('/api/get-perms/', data1)
        self.assertEqual(response.status_code, 200)
        response = self.c.post('/api/get-perms/', data2)
        self.assertEqual(response.status_code, 400)

    def test_method_sms_authenticate_valid_code(self):
        data = { 'tlf': '+34666666666', 'code': 'AAAAAAAA',
                'email': 'test@test.com', 'dni': '11111111H'}
        response = self.c.authenticate(self.aeid, data)
        self.assertEqual(response.status_code, 200)
        r = json.loads(response.content.decode('utf-8'))
        self.assertTrue(r['auth-token'].startswith('khmac:///sha-256'))

    def test_method_sms_authenticate_invalid_code(self):
        data = {
                'email': 'test2@agoravoting.com',
                'code': 'AAAAAA'
        }
        response = self.c.authenticate(self.aeid, data)
        self.assertEqual(response.status_code, 400)

    @override_settings(CELERY_EAGER_PROPAGATES_EXCEPTIONS=True,
                       CELERY_ALWAYS_EAGER=True,
                       BROKER_BACKEND='memory')
    def _test_method_sms_register_max_tlf(self):
        data = {'tlf': '+34666666666', 'code': 'AAAAAA',
                'email': 'test@test.com', 'dni': '11111111H'}
        x = 0
        while x < test_data.pipe_total_max_tlf + 1:
            x += 1
            response = self.c.register(self.aeid, data)
        response = self.c.register(self.aeid, data)
        self.assertEqual(response.status_code, 400)
        r = json.loads(response.content.decode('utf-8'))
        self.assertNotEqual(r['message'].find('Blacklisted'), -1)

    @override_settings(CELERY_EAGER_PROPAGATES_EXCEPTIONS=True,
                       CELERY_ALWAYS_EAGER=True,
                       BROKER_BACKEND='memory')
    def _test_method_sms_register_max_tlf_period(self):
        data = {'tlf': '+3476666666', 'code': 'AAAAAA',
                'email': 'test@test.com', 'dni': '11111111H'}
        x = 0
        time_now = time.time()
        while x < test_data.pipe_total_max_tlf_with_period + 1:
            x += 1
            data['tlf'] = data['tlf'] + str(x)
            response = self.c.register(self.aeid, data)
        response = self.c.register(self.aeid, data)
        total_time = time.time() - time_now
        if total_time < test_data.pipe_total_max_period:
            self.assertEqual(response.status_code, 400)
            r = json.loads(response.content.decode('utf-8'))
            self.assertNotEqual(r['message'].find('Blacklisted'), -1)
        else:
            self.assertEqual(response.status_code, 200)
