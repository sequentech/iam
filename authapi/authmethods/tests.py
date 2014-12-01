from django.contrib.auth.models import User
from django.core import mail
from django.test import TestCase

import json
from api.tests import JClient
from api.models import AuthEvent
from .m_email import Email
from .m_sms import Sms


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
                auth_method_config=json.dumps(Email.TPL_CONFIG))
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
        response = c.get('/api/authmethod/email/validate/%s/bad/' % (user), {})
        self.assertEqual(response.status_code, 200)
        r = json.loads(response.content.decode('utf-8'))
        self.assertEqual(r['status'], 'nok')

    def test_method_email_login_valid_code(self):
        c = JClient()
        response = c.post('/api/login/',
                {'auth-method': 'email', 'auth-data':
                    {'user': 'test1', 'password': '123456'}})
        self.assertEqual(response.status_code, 200)
        r = json.loads(response.content.decode('utf-8'))
        self.assertTrue(r['auth-token'].startswith('khmac:///sha256'))

    def test_method_email_login_invalid_code(self):
        c = JClient()
        response = c.post('/api/login/',
                {'auth-method': 'email', 'auth-data':
                    {'user': 'test2', 'password': '123456'}})
        self.assertEqual(response.status_code, 200)
        r = json.loads(response.content.decode('utf-8'))
        self.assertEqual(r['status'], 'nok')


class AuthMethodSmsTestCase(TestCase):
    def setUp(self):
        ae = AuthEvent(pk=1, name='test', auth_method='sms-code',
                auth_method_config=json.dumps(Sms.TPL_CONFIG))
        ae.save()

        u = User(pk=1, username='test')
        u.save()
        u.userdata.event = ae
        u.userdata.metadata = json.dumps({
                'tlf': '+34666666666',
                'code': 'AAAAAAAA',
                'sms_verified': False
        })
        u.userdata.save()

    def test_method_sms_regiter(self):
        c = JClient()
        response = c.post('/api/authmethod/sms-code/register/1/',
                {'tlf': '+34666666666'})
        self.assertEqual(response.status_code, 200)
        r = json.loads(response.content.decode('utf-8'))
        self.assertEqual(r['status'], 'ok')

    def test_method_sms_valid_code(self):
        user = 1
        code = 'AAAAAAAA'

        c = JClient()
        response = c.get('/api/authmethod/sms-code/validate/%s/%s/' % (user, code), {})
        self.assertEqual(response.status_code, 200)
        r = json.loads(response.content.decode('utf-8'))
        self.assertEqual(r['status'], 'ok')

    def test_method_sms_invalid_code(self):
        user = 1
        code = 'BBBBBBBB'

        c = JClient()
        response = c.get('/api/authmethod/sms-code/validate/%s/bad/' % (user), {})
        self.assertEqual(response.status_code, 200)
        r = json.loads(response.content.decode('utf-8'))
        self.assertEqual(r['status'], 'nok')
