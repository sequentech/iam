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
    def setUp(self):
        auth_method_config = test_data.auth_event4['config']
        auth_method_config.update(test_data.auth_event4['pipeline'])
        ae = AuthEvent(pk=1, name='test', auth_method=test_data.auth_event4['auth_method'],
                auth_method_config=auth_method_config,
                metadata=test_data.auth_event4['metadata'],
                status='start',
                census=test_data.auth_event4['census'])
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
        response = c.login(self.aeid, test_data.pwd_auth)
        self.assertEqual(response.status_code, 200)
        r = json.loads(response.content.decode('utf-8'))
        self.assertEqual(r['status'], 'ok')

        data = { 'username': 'test', 'password': 'cxzvcx' }
        response = c.login(self.aeid, data)
        self.assertEqual(response.status_code, 400)


class AuthMethodEmailTestCase(TestCase):
    def setUp(self):
        auth_method_config = test_data.auth_event3['config']
        auth_method_config.update(test_data.auth_event3['pipeline'])
        ae = AuthEvent(pk=1, name='test', auth_method=test_data.auth_event3['auth_method'],
                auth_method_config=auth_method_config,
                metadata=test_data.auth_event3['metadata'],
                status='start',
                census=test_data.auth_event3['census'])
        ae.save()
        self.aeid = ae.pk

        u = User(pk=1, username='test1', email='test1@agoravoting.com')
        u.set_password('123456')
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
        u2.set_password('123456')
        u2.save()
        u2.userdata.event = ae
        u2.userdata.metadata = json.dumps({
                'email': 'test2@test.com',
                'code': 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
                'email_verified': False
        })
        u2.userdata.save()


    @override_settings(CELERY_EAGER_PROPAGATES_EXCEPTIONS=True,
                       CELERY_ALWAYS_EAGER=True,
                       BROKER_BACKEND='memory')
    def test_method_email_register(self):
        c = JClient()
        data = {'email': 'test@test.com', 'user': 'test', 'password': '123456'}
        response = c.register(self.aeid, data)
        self.assertEqual(response.status_code, 200)
        r = json.loads(response.content.decode('utf-8'))
        self.assertEqual(r['status'], 'ok')

    def test_method_email_valid_code(self):
        code = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'

        c = JClient()
        data = { 'userid': self.userid, 'code': code }
        response = c.validate(self.aeid, data)
        self.assertEqual(response.status_code, 200)
        r = json.loads(response.content.decode('utf-8'))
        self.assertEqual(r['status'], 'ok')

    def test_method_email_invalid_code(self):
        code = 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'

        c = JClient()
        data = { 'userid': self.userid, 'code': code }
        response = c.validate(self.aeid, data)
        self.assertEqual(response.status_code, 400)

    def test_method_email_login_valid_code(self):
        c = JClient()
        data = {
                'email': 'test1@agoravoting.com',
                'password': '123456'
        }
        response = c.login(self.aeid, data)
        self.assertEqual(response.status_code, 200)
        r = json.loads(response.content.decode('utf-8'))
        self.assertTrue(r['auth-token'].startswith('khmac:///sha-256'))

    def test_method_email_login_invalid_code(self):
        c = JClient()
        data = {
                'email': 'test2@agoravoting.com',
                'password': '123456'
        }
        response = c.login(self.aeid, data)
        self.assertEqual(response.status_code, 400)

    def test_method_email_create_census(self):
        auth = {
            'email': 'test1@agoravoting.com',
            'password': '123456'
        }
        c = JClient()
        c.login(self.aeid, auth)

        data = []
        x = 0
        while x <= 10:
            x += 1
            data.append({
                    'email': 'test%d@test.com' % x,
                    'password': '123456',
            })
        response = c.census(self.aeid, data)
        self.assertEqual(response.status_code, 200)


class AuthMethodSmsTestCase(TestCase):
    def setUp(self):
        auth_method_config = test_data.auth_event2['config']
        auth_method_config.update(test_data.auth_event2['pipeline'])
        ae = AuthEvent(pk=1, name='test', auth_method=test_data.auth_event2['auth_method'],
                auth_method_config=auth_method_config,
                metadata=test_data.auth_event2['metadata'],
                status='start',
                census=test_data.auth_event2['census'])
        ae.save()
        self.aeid = ae.pk

        u = User(pk=1, username='test1', email='test1@agoravoting.com')
        u.set_password('123456')
        u.save()
        u.userdata.event = ae
        u.userdata.metadata = json.dumps({
                'tlf': '+34666666666',
                'code': 'AAAAAAAA',
                'dni': '11111111H',
                'sms_verified': True
        })
        u.userdata.save()
        self.u = u.userdata
        code = Code(user=u.userdata, tlf='+34666666666', dni='11111111H',
                code='AAAAAAAA')
        code.save()
        m = Message(tlf='+34666666666')
        m.save()
        pipe = auth_method_config.get('validate-pipeline')
        for p in pipe:
            if p[0] == 'check_total_connection':
                self.times = p[1].get('times')
            if p[0] == 'check_sms_code':
                self.timestamp = p[1].get('timestamp')

        u2 = User(pk=2, username='test2', email='test2@agoravoting.com')
        u2.set_password('123456')
        u2.save()
        u2.userdata.event = ae
        u2.userdata.metadata = json.dumps({
                'tlf': '+34766666666',
                'code': 'AAAAAAAA',
                'dni': '11111111H',
                'sms_verified': False
        })
        u2.userdata.save()
        code = Code(user=u2.userdata, tlf='+34766666666', dni='22222222J',
                code='AAAAAAAA')
        code.save()
        self.c = JClient()
        pipe = auth_method_config.get('register-pipeline')
        for p in pipe:
            if p[0] == 'check_total_max':
                if p[1].get('field') == 'tlf':
                    if p[1].get('period'):
                        self.period_tlf = p[1].get('period')
                        self.total_max_tlf_period = p[1].get('max')
                    else:
                        self.total_max_tlf = p[1].get('max')
                elif p[1].get('field') == 'ip':
                    self.total_max_ip = p[1].get('max')

    @override_settings(CELERY_EAGER_PROPAGATES_EXCEPTIONS=True,
                       CELERY_ALWAYS_EAGER=True,
                       BROKER_BACKEND='memory')
    def test_method_sms_register(self):
        data = {'tlf': '+34666666666', 'password': '123456',
                    'email': 'test@test.com', 'dni': '11111111H'}
        response = self.c.register(self.aeid, data)
        self.assertEqual(response.status_code, 200)
        r = json.loads(response.content.decode('utf-8'))
        self.assertEqual(r['status'], 'ok')
        self.assertGreaterEqual(Code.objects.filter(tlf='+34666666666',
            dni='11111111H').count(), 1)

    def test_method_sms_register_valid_dni(self):
        data = {'tlf': '+34666666666', 'password': '123456', 'dni': '11111111H'}
        response = self.c.register(self.aeid, data)
        self.assertEqual(response.status_code, 400)
        r = json.loads(response.content.decode('utf-8'))
        self.assertEqual(r['msg'].find('Invalid dni'), -1)

    def test_method_sms_register_invalid_dni(self):
        data = {'tlf': '+34666666666', 'password': '123456', 'dni': '999'}
        response = self.c.register(self.aeid, data)
        self.assertEqual(response.status_code, 400)
        r = json.loads(response.content.decode('utf-8'))
        self.assertNotEqual(r['msg'].find('Invalid dni'), -1)

    def test_method_sms_register_valid_email(self):
        data = {'tlf': '+34666666666', 'password': '123456',
                'email': 'test@test.com'}
        response = self.c.register(self.aeid, data)
        self.assertEqual(response.status_code, 400)
        r = json.loads(response.content.decode('utf-8'))
        self.assertEqual(r['msg'].find('Invalid email'), -1)

    def test_method_sms_register_invalid_email(self):
        data = {'tlf': '+34666666666', 'password': '123456', 'email': 'test@@'}
        response = self.c.register(self.aeid, data)
        self.assertEqual(response.status_code, 400)
        r = json.loads(response.content.decode('utf-8'))
        self.assertNotEqual(r['msg'].find('Invalid email'), -1)

    def test_method_sms_valid_code(self):
        data = {'tlf': '+34666666666', 'code': 'AAAAAAAA', 'dni': '11111111H'}
        response = self.c.validate(self.aeid, data)
        self.assertEqual(response.status_code, 200)
        r = json.loads(response.content.decode('utf-8'))
        self.assertEqual(r['status'], 'ok')
        self.assertGreaterEqual(Connection.objects.filter(tlf='+34666666666',
                dni='11111111H').count(), 1)
        self.assertTrue(r['auth-token'].startswith('khmac:///sha-256'))

    def test_method_sms_valid_code_timeout(self):
        time.sleep(self.timestamp)
        data = {'tlf': '+34666666666', 'code': 'AAAAAAAA', 'dni': '11111111H'}
        response = self.c.validate(self.aeid, data)
        self.assertEqual(response.status_code, 400)
        r = json.loads(response.content.decode('utf-8'))
        self.assertEqual(r['message'], 'Timeout.')

    def test_method_sms_invalid_code(self):
        data = {'tlf': '+34666666666', 'code': 'BBBBBBBB', 'dni': '11111111H'}
        response = self.c.validate(self.aeid, data)
        self.assertEqual(response.status_code, 400)
        r = json.loads(response.content.decode('utf-8'))
        self.assertEqual(r['message'], 'Invalid code.')

    def test_method_sms_invalid_code_x_times(self):
        for i in range(self.times + 1):
            data = {'tlf': '+34666666666', 'code': 'BBBBBBBB', 'dni': '11111111H'}
            response = self.c.validate(self.aeid, data)
        self.assertEqual(response.status_code, 400)
        r = json.loads(response.content.decode('utf-8'))
        self.assertEqual(r['message'], 'Exceeded the level os attempts')

    def test_method_sms_get_perm(self):
        auth = {
            'email': 'test1@agoravoting.com',
            'password': '123456'
        }
        data1 = { "object_type": "Vote", "permission": "create", }
        data2 = { "object_type": "Vote", "permission": "remove", }

        response = self.c.post('/api/get-perms', data1)
        self.assertEqual(response.status_code, 301)
        response = self.c.post('/api/get-perms', data2)
        self.assertEqual(response.status_code, 301)

        acl = ACL(user=self.u, object_type='Vote', perm='create')
        acl.save()
        self.c.login(self.aeid, auth)
        response = self.c.post('/api/get-perms/', data1)
        self.assertEqual(response.status_code, 200)
        response = self.c.post('/api/get-perms/', data2)
        self.assertEqual(response.status_code, 400)

    def test_method_sms_login_valid_code(self):
        data = {
                'email': 'test1@agoravoting.com',
                'password': '123456'
        }
        response = self.c.login(self.aeid, data)
        self.assertEqual(response.status_code, 200)
        r = json.loads(response.content.decode('utf-8'))
        self.assertTrue(r['auth-token'].startswith('khmac:///sha-256'))

    def test_method_sms_login_invalid_code(self):
        data = {
                'email': 'test2@agoravoting.com',
                'password': '123456'
        }
        response = self.c.login(self.aeid, data)
        self.assertEqual(response.status_code, 400)

    @override_settings(CELERY_EAGER_PROPAGATES_EXCEPTIONS=True,
                       CELERY_ALWAYS_EAGER=True,
                       BROKER_BACKEND='memory')
    def test_method_sms_register_max_tlf(self):
        x = 0
        while x < self.total_max_tlf + 1:
            x += 1
            data = {'tlf': '+34666666666', 'password': '123456',
                    'email': 'test@test.com', 'dni': '11111111H'}
            response = self.c.register(self.aeid, data)
        data = {'tlf': '+34666666666', 'password': '123456',
                'email': 'test@test.com', 'dni': '11111111H'}
        response = self.c.register(self.aeid, data)
        self.assertEqual(response.status_code, 400)
        r = json.loads(response.content.decode('utf-8'))
        self.assertNotEqual(r['message'].find('Blacklisted'), -1)

    @override_settings(CELERY_EAGER_PROPAGATES_EXCEPTIONS=True,
                       CELERY_ALWAYS_EAGER=True,
                       BROKER_BACKEND='memory')
    def test_method_sms_register_max_tlf_period(self):
        x = 0
        time_now = time.time()
        while x < self.total_max_tlf_period + 1:
            x += 1
            data = {'tlf': '+34666666666', 'password': '123456',
                    'email': 'test@test.com', 'dni': '11111111H'}
            response = self.c.register(self.aeid, data)
        data = {'tlf': '+34666666666', 'password': '123456',
                'email': 'test@test.com', 'dni': '11111111H'}
        response = self.c.register(self.aeid, data)
        total_time = time.time() - time_now
        if total_time < self.period_tlf:
            self.assertEqual(response.status_code, 400)
            r = json.loads(response.content.decode('utf-8'))
            self.assertNotEqual(r['message'].find('Blacklisted'), -1)
        else:
            self.assertEqual(response.status_code, 200)

    def test_method_sms_create_census(self):
        auth = {
            'email': 'test1@agoravoting.com',
            'password': '123456'
        }
        self.c.login(self.aeid, auth)

        data = []
        x = 0
        while x <= 10:
            x += 1
            data.append({
                    'tlf': '+34666666666',
                    'password': '123456',
                    'email': 'test%d@test.com' % x,
                    'dni': '11111111H'
            })
        response = self.c.census(self.aeid, data)
        self.assertEqual(response.status_code, 200)
