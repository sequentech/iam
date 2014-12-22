from django.contrib.auth.models import User
from django.core import mail
from django.test import TestCase

import json
import time
from api.tests import JClient
from api.models import AuthEvent, ACL
from .m_email import Email
from .m_sms import Sms
from .models import Message, Code, Connection


class AuthMethodTestCase(TestCase):
    def setUp(self):
        pass

    def test_method_custom_view(self):
        c = JClient()
        response = c.get('/api/authmethod/user-and-password/test/asdfdsf/', {})
        self.assertEqual(response.status_code, 200)
        r = json.loads(response.content.decode('utf-8'))
        self.assertEqual(r['status'], 'ok')

        response = c.get('/api/authmethod/user-and-password/test/asdfdsf/cxzvcx/', {})
        self.assertEqual(response.status_code, 404)


class AuthMethodEmailTestCase(TestCase):
    def setUp(self):
        ae = AuthEvent(pk=1, name='test', auth_method='email',
                auth_method_config=json.dumps(Email.TPL_CONFIG),
                metadata=json.dumps(Email.METADATA_DEFAULT))
        ae.save()

        u = User(pk=1, username='test1')
        u.set_password('123456')
        u.save()
        u.userdata.event = ae
        u.userdata.metadata = json.dumps({
                'email': 'test@test.com',
                'code': 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
                'email_verified': True
        })
        u.userdata.save()

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


    def test_method_email_register(self):
        c = JClient()
        response = c.post('/api/authmethod/email/register/1/',
                {'email': 'test@test.com', 'user': 'test', 'password': '123456'})
        self.assertEqual(response.status_code, 200)
        r = json.loads(response.content.decode('utf-8'))
        self.assertEqual(r['status'], 'ok')

    def test_method_email_valid_code(self):
        user = 'test1'
        code = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'

        c = JClient()
        response = c.get('/api/authmethod/email/validate/%s/%s/' % (user, code), {})
        self.assertEqual(response.status_code, 200)
        r = json.loads(response.content.decode('utf-8'))
        self.assertEqual(r['status'], 'ok')

    def test_method_email_invalid_code(self):
        user = 'test1'
        code = 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'

        c = JClient()
        response = c.get('/api/authmethod/email/validate/%s/%s/' % (user, code), {})
        self.assertEqual(response.status_code, 400)

    def test_method_email_login_valid_code(self):
        c = JClient()
        response = c.post('/api/login/',
                {'auth-method': 'email', 'auth-data':
                    {'user': 'test1', 'password': '123456'}})
        self.assertEqual(response.status_code, 200)
        r = json.loads(response.content.decode('utf-8'))
        self.assertTrue(r['auth-token'].startswith('khmac:///sha-256'))

    def test_method_email_login_invalid_code(self):
        c = JClient()
        response = c.post('/api/login/',
                {'auth-method': 'email', 'auth-data':
                    {'user': 'test2', 'password': '123456'}})
        self.assertEqual(response.status_code, 400)


class AuthMethodSmsTestCase(TestCase):
    def setUp(self):
        ae = AuthEvent(pk=1, name='test', auth_method='sms-code',
                auth_method_config=json.dumps(Sms.TPL_CONFIG),
                metadata=json.dumps(Sms.METADATA_DEFAULT))
        ae.save()

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
        code = Code(user=u.userdata, tlf='+34666666666', dni='11111111H',
                code='AAAAAAAA')
        code.save()
        m = Message(tlf='+34666666666')
        m.save()
        pipe = Sms.TPL_CONFIG.get('feedback-pipeline')
        for p in pipe:
            if p[0] == 'check_total_connection':
                self.times = p[1].get('times')
            if p[0] == 'check_sms_code':
                self.timestamp = p[1].get('timestamp')
            if p[0] == 'give_perms':
                obj = p[1].get('object_type')
                for perm in p[1].get('perms'):
                    acl = ACL(user=u.userdata, object_type=obj, perm=perm)
                    acl.save()

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
        pipe = Sms.TPL_CONFIG.get('register-pipeline')
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

    def test_method_sms_regiter(self):
        response = self.c.post('/api/authmethod/sms-code/register/1/',
                {'tlf': '+34666666666', 'password': '123456',
                    'email': 'test@test.com', 'dni': '11111111H'})
        self.assertEqual(response.status_code, 200)
        r = json.loads(response.content.decode('utf-8'))
        self.assertEqual(r['status'], 'ok')
        self.assertGreaterEqual(Code.objects.filter(tlf='+34666666666',
            dni='11111111H').count(), 1)

    def test_method_sms_register_valid_dni(self):
        response = self.c.post('/api/authmethod/sms-code/register/1/',
                {'tlf': '+34666666666', 'password': '123456', 'dni': '11111111H'})
        self.assertEqual(response.status_code, 400)
        r = json.loads(response.content.decode('utf-8'))
        self.assertEqual(r['msg'].find('Invalid dni'), -1)

    def test_method_sms_register_invalid_dni(self):
        response = self.c.post('/api/authmethod/sms-code/register/1/',
                {'tlf': '+34666666666', 'password': '123456', 'dni': '999'})
        self.assertEqual(response.status_code, 400)
        r = json.loads(response.content.decode('utf-8'))
        self.assertNotEqual(r['msg'].find('Invalid dni'), -1)

    def test_method_sms_register_valid_email(self):
        response = self.c.post('/api/authmethod/sms-code/register/1/',
                {'tlf': '+34666666666', 'password': '123456',
                    'email': 'test@test.com'})
        self.assertEqual(response.status_code, 400)
        r = json.loads(response.content.decode('utf-8'))
        self.assertEqual(r['msg'].find('Invalid email'), -1)

    def test_method_sms_register_invalid_email(self):
        response = self.c.post('/api/authmethod/sms-code/register/1/',
                {'tlf': '+34666666666', 'password': '123456', 'email': 'test@@'})
        self.assertEqual(response.status_code, 400)
        r = json.loads(response.content.decode('utf-8'))
        self.assertNotEqual(r['msg'].find('Invalid email'), -1)

    def test_method_sms_valid_code(self):
        response = self.c.post('/api/authmethod/sms-code/validate/1/',
                {'tlf': '+34666666666', 'code': 'AAAAAAAA', 'dni': '11111111H'})
        self.assertEqual(response.status_code, 200)
        r = json.loads(response.content.decode('utf-8'))
        self.assertEqual(r['status'], 'ok')
        self.assertGreaterEqual(Connection.objects.filter(tlf='+34666666666',
                dni='11111111H').count(), 1)
        self.assertTrue(r['auth-token'].startswith('khmac:///sha-256'))

    def test_method_sms_valid_code_timeout(self):
        time.sleep(self.timestamp)
        response = self.c.post('/api/authmethod/sms-code/validate/1/',
                {'tlf': '+34666666666', 'code': 'AAAAAAAA', 'dni': '11111111H'})
        self.assertEqual(response.status_code, 400)
        r = json.loads(response.content.decode('utf-8'))
        self.assertEqual(r['message'], 'Timeout.')

    def test_method_sms_invalid_code(self):
        response = self.c.post('/api/authmethod/sms-code/validate/1/',
                {'tlf': '+34666666666', 'code': 'BBBBBBBB', 'dni': '11111111H'})
        self.assertEqual(response.status_code, 400)
        r = json.loads(response.content.decode('utf-8'))
        self.assertEqual(r['message'], 'Invalid code.')

    def test_method_sms_invalid_code_x_times(self):
        for i in range(self.times + 1):
            response = self.c.post('/api/authmethod/sms-code/validate/1/',
                    {'tlf': '+34666666666', 'code': 'BBBBBBBB', 'dni': '11111111H'})
        self.assertEqual(response.status_code, 400)
        r = json.loads(response.content.decode('utf-8'))
        self.assertEqual(r['message'], 'Exceeded the level os attempts')

    def test_method_sms_get_perm(self):
        auth = {
            'auth-method': 'sms-code',
            'auth-data': {
                'email': 'test1@agoravoting.com',
                'password': '123456'
            }
        }
        data1 = { "object_type": "Vote", "permission": "create", }
        data2 = { "object_type": "Vote", "permission": "remove", }

        response = self.c.post('/api/get-perms', data1)
        self.assertEqual(response.status_code, 301)
        response = self.c.post('/api/get-perms', data2)
        self.assertEqual(response.status_code, 301)

        self.c.login(auth)
        response = self.c.post('/api/get-perms/', data1)
        self.assertEqual(response.status_code, 200)
        response = self.c.post('/api/get-perms/', data2)
        self.assertEqual(response.status_code, 400)

    def test_method_sms_login_valid_code(self):
        response = self.c.post('/api/login/',
                {'auth-method': 'sms-code', 'auth-data':
                    {'email': 'test1@agoravoting.com', 'password': '123456'}})
        self.assertEqual(response.status_code, 200)
        r = json.loads(response.content.decode('utf-8'))
        self.assertTrue(r['auth-token'].startswith('khmac:///sha-256'))

    def test_method_sms_login_invalid_code(self):
        response = self.c.post('/api/login/',
                {'auth-method': 'sms-code', 'auth-data':
                    {'email': 'test2@agoravoting.com', 'password': '123456'}})
        self.assertEqual(response.status_code, 400)

    def test_method_sms_regiter_max_tlf(self):
        x = 0
        while x < self.total_max_tlf + 1:
            x += 1
            response = self.c.post('/api/authmethod/sms-code/register/1/',
                    {'tlf': '+34666666666', 'password': '123456',
                        'email': 'test@test.com', 'dni': '11111111H'})
        response = self.c.post('/api/authmethod/sms-code/register/1/',
                {'tlf': '+34666666666', 'password': '123456',
                    'email': 'test@test.com', 'dni': '11111111H'})
        self.assertEqual(response.status_code, 400)
        r = json.loads(response.content.decode('utf-8'))
        self.assertNotEqual(r['message'].find('Blacklisted'), -1)

    def test_method_sms_regiter_max_tlf_period(self):
        x = 0
        time_now = time.time()
        while x < self.total_max_tlf_period + 1:
            x += 1
            response = self.c.post('/api/authmethod/sms-code/register/1/',
                    {'tlf': '+34666666666', 'password': '123456',
                        'email': 'test@test.com', 'dni': '11111111H'})
        response = self.c.post('/api/authmethod/sms-code/register/1/',
                {'tlf': '+34666666666', 'password': '123456',
                    'email': 'test@test.com', 'dni': '11111111H'})

        total_time = time.time() - time_now
        if total_time < self.period_tlf:
            self.assertEqual(response.status_code, 400)
            r = json.loads(response.content.decode('utf-8'))
            self.assertNotEqual(r['message'].find('Blacklisted'), -1)
        else:
            self.assertEqual(response.status_code, 200)
