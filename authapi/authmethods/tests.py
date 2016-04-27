from django.contrib.auth.models import User
from django.core import mail
from django.test import TestCase
from django.test.utils import override_settings

import json
import time
from api import test_data
from api.tests import JClient
from api.models import AuthEvent, ACL, UserData
from .m_email import Email
from .m_sms import Sms
from .models import Message, Code, Connection


class AuthMethodTestCase(TestCase):
    fixtures = ['initial.json']
    def setUp(self):
        ae = AuthEvent(auth_method=test_data.auth_event4['auth_method'],
                status='started', census=test_data.auth_event4['census'],
                auth_method_config=test_data.authmethod_config_email_default)
        ae.save()
        self.aeid = ae.pk

        u = User(pk=1, email=test_data.pwd_auth['email'])
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

        data = { 'email': 'test@agoravoting.com', 'password': 'cxzvcx' }
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

        acl = ACL(user=u.userdata, object_type='AuthEvent', perm='edit', object_id=ae.pk)
        acl.save()

        u2 = User(pk=2, email='test2@agoravoting.com')
        u2.is_active = False
        u2.save()
        u2.userdata.event = ae
        u2.userdata.metadata = json.dumps({
                'email': 'test2@test.com',
                'code': 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
                'email_verified': False
        })
        u2.userdata.save()

        code = Code(user=u.userdata, code='AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA', auth_event_id=ae.pk)
        code.save()
        code = Code(user=u2.userdata, code='AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA', auth_event_id=ae.pk)
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
        code = Code(user=u.userdata, code='AAAAAAAA', auth_event_id=ae.pk)
        code.save()
        m = Message(tlf=u.userdata.tlf, auth_event_id=ae.pk)
        m.save()

        u2 = User(pk=2, email='test2@agoravoting.com')
        u2.is_active = False
        u2.save()
        u2.userdata.tlf = '+34766666666'
        u2.userdata.event = ae
        u2.userdata.metadata = json.dumps({ 'dni': '11111111H' })
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
        self.assertEqual(r['error_codename'], 'invalid_credentials')

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
                'email': 'test2@agoravoting.com',
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
        import utils
        from authmethods.sms_provider import TestSMSProvider
        sms_count0 = TestSMSProvider.sms_count
        utils.send_codes(users=[3], ip='127.0.0.1', 
                         config={'msg':'url[__URL2__], code[__CODE__]',
                                 'subject':'subject'})
        self.assertEqual(1+sms_count0, TestSMSProvider.sms_count)
        import re
        o = re.match('url\[(.+)\], code\[([A-Z0-9]+)\]', TestSMSProvider.last_sms.get('content'))
        self.assertEqual(2, len(o.groups()))
        test_url = 'public/login/\\' + data.get('tlf') + '/' + o.groups()[1]
        e = re.search(test_url, o.groups()[0])
        self.assertTrue(e.group(0) == test_url.replace('\\',''))


class ExtraFieldPipelineTestCase(TestCase):
    fixtures = ['initial.json']
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
        u = User(email='admin6@agoravoting.com')
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
        self.assertEqual(json.loads(user.metadata).get('dni'), '39873625C')

        data = {'email': 'test1@test.com', 'user': 'test',
                'dni': '39873625c'}
        response = c.register(self.aeid, data)
        self.assertEqual(response.status_code, 200)
        user = UserData.objects.get(user__email=data['email'])
        self.assertEqual(json.loads(user.metadata).get('dni'), '39873625C')

        data = {'email': 'test2@test.com', 'user': 'test',
                'dni': '39873625X'}
        response = c.register(self.aeid, data)
        self.assertEqual(response.status_code, 400)


class ExternalCheckPipelineTestCase(TestCase):
    fixtures = ['initial.json']
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

    def _test_method_external_pipeline(self):
        # TODO: Fixed external api for validate dni, else is_active will be False
        c = JClient()
        data = {'email': 'test@test.com', 'user': 'test',
                'dni': '39873625C'}
        response = c.register(self.aeid, data)
        self.assertEqual(response.status_code, 200)

        u = User.objects.get(email='test@test.com')
        self.assertEqual(u.is_active, True)
        mdata = json.loads(u.userdata.metadata)
        self.assertEqual(mdata['external_data']['custom'], True)
