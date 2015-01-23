import time
import json
from django.test import TestCase
from django.test import Client
from utils import verifyhmac
from django.conf import settings


from django.contrib.auth.models import User
from .models import ACL, AuthEvent
from authmethods.models import Code

from . import test_data

class JClient(Client):
    def __init__(self, *args, **kwargs):
        self.auth_token = ''
        super(JClient, self).__init__(*args, **kwargs)

    def census(self, authevent, data):
        response = self.post('/api/auth-event/%d/census/' % authevent, data)
        r = json.loads(response.content.decode('utf-8'))
        return response

    def register(self, authevent, data):
        response = self.post('/api/auth-event/%d/register/' % authevent, data)
        r = json.loads(response.content.decode('utf-8'))
        self.set_auth_token(r.get('auth-token'))
        return response

    def authenticate(self, authevent, data):
        response = self.post('/api/auth-event/%d/authenticate/' % authevent, data)
        r = json.loads(response.content.decode('utf-8'))
        self.set_auth_token(r.get('auth-token'))
        return response

    def set_auth_token(self, token):
        self.auth_token = token

    def get(self, url, data):
        return super(JClient, self).get(url, data,
            content_type="application/json", HTTP_AUTH=self.auth_token)

    def post(self, url, data):
        jdata = json.dumps(data)
        return super(JClient, self).post(url, jdata,
            content_type="application/json", HTTP_AUTH=self.auth_token)

    def put(self, url, data):
        jdata = json.dumps(data)
        return super(JClient, self).put(url, jdata,
            content_type="application/json", HTTP_AUTH=self.auth_token)

    def delete(self, url, data):
        jdata = json.dumps(data)
        return super(JClient, self).delete(url, jdata,
            content_type="application/json", HTTP_AUTH=self.auth_token)


class ApiTestCase(TestCase):
    def setUp(self):
        ae = AuthEvent(auth_method=test_data.auth_event4['auth_method'])
        ae.save()

        u = User(username='john', email='john@agoravoting.com')
        u.set_password('smith')
        u.save()
        u.userdata.event = ae
        u.userdata.save()
        self.userid = u.pk
        self.testuser = u
        self.aeid = ae.pk

        acl = ACL(user=u.userdata, object_type='User', perm='create')
        acl.save()

        acl = ACL(user=u.userdata, object_type='AuthEvent', perm='create')
        acl.save()

        acl = ACL(user=u.userdata, object_type='AuthEvent', perm='view')
        acl.save()

        acl = ACL(user=u.userdata, object_type='AuthEvent', perm='edit',
                object_id=self.aeid)
        acl.save()

        acl = ACL(user=u.userdata, object_type='ACL', perm='delete')
        acl.save()

        acl = ACL(user=u.userdata, object_type='ACL', perm='view')
        acl.save()

        acl = ACL(user=u.userdata, object_type='ACL', perm='create')
        acl.save()

    def test_change_status(self):
        c = JClient()
        response = c.post('/api/auth-event/%d/%s/' % (self.aeid, 'started'), {})
        self.assertEqual(response.status_code, 403)
        response = c.post('/api/auth-event/%d/%s/' % (self.aeid, 'stopped'), {})
        self.assertEqual(response.status_code, 403)

        c.authenticate(self.aeid, test_data.pwd_auth)

        response = c.post('/api/auth-event/%d/%s/' % (self.aeid, 'started'), {})
        self.assertEqual(response.status_code, 200)
        response = c.post('/api/auth-event/%d/%s/' % (self.aeid, 'stopped'), {})
        self.assertEqual(response.status_code, 200)
        response = c.post('/api/auth-event/%d/%s/' % (self.aeid, 'stopped'), {})
        self.assertEqual(response.status_code, 400)


    def test_api(self):
        c = JClient()
        data = {'username': 'john', 'password': 'smith'}
        response = c.post('/api/test/', data)

        self.assertEqual(response.status_code, 200)
        r = json.loads(response.content.decode('utf-8'))
        self.assertEqual(r['status'], 'ok')
        self.assertEqual(r['post']['username'], 'john')
        self.assertEqual(r['post']['password'], 'smith')

        response = c.get('/api/test/', data)
        self.assertEqual(response.status_code, 200)
        r = json.loads(response.content.decode('utf-8'))
        self.assertEqual(r['status'], 'ok')
        self.assertEqual(r['get']['username'], 'john')
        self.assertEqual(r['get']['password'], 'smith')

    def test_authenticate(self):
        c = JClient()
        data = {'username': 'john', 'password': 'smith'}
        response = c.authenticate(self.aeid, data)

        self.assertEqual(response.status_code, 200)
        r = json.loads(response.content.decode('utf-8'))
        self.assertEqual(r['status'], 'ok')
        self.assertEqual(verifyhmac(settings.SHARED_SECRET,
            r['auth-token']), True)
        time.sleep(3)
        self.assertEqual(verifyhmac(settings.SHARED_SECRET,
            r['auth-token'], seconds=3), False)

        data = {'username': 'john', 'password': 'fake'}
        response = c.authenticate(self.aeid, data)
        self.assertEqual(response.status_code, 400)

    def test_getperms_noauth(self):
        c = JClient()

        data = {
            "permission": "delete_user",
            "permission_data": "newuser"
        }
        response = c.post('/api/get-perms/', data)
        self.assertEqual(response.status_code, 403)

    def test_getperms_noperm(self):
        c = JClient()
        c.authenticate(self.aeid, test_data.pwd_auth)
        data = {
            "object_type": "User",
            "permission": "delete"
        }
        response = c.post('/api/get-perms/', data)

        self.assertEqual(response.status_code, 400)

    def test_getperms_perm(self):
        c = JClient()
        c.authenticate(self.aeid, test_data.pwd_auth)
        data = {
            "object_type": "User",
            "permission": "create"
        }
        response = c.post('/api/get-perms/', data)

        self.assertEqual(response.status_code, 200)
        r = json.loads(response.content.decode('utf-8'))
        self.assertEqual(r['status'], 'ok')
        self.assertEqual(verifyhmac(settings.SHARED_SECRET,
            r['permission-token']), True)

    def test_create_event(self):
        c = JClient()
        c.authenticate(self.aeid, test_data.pwd_auth)

        data = test_data.auth_event1
        response = c.post('/api/auth-event/', data)
        self.assertEqual(response.status_code, 200)
        r = json.loads(response.content.decode('utf-8'))
        self.assertEqual(r['id'], 2)

    def test_create_event_open(self):
        aeid = 2
        c = JClient()
        c.authenticate(self.aeid, test_data.pwd_auth)

        data = test_data.auth_event3
        response = c.post('/api/auth-event/', data)
        self.assertEqual(response.status_code, 200)
        r = json.loads(response.content.decode('utf-8'))
        self.assertEqual(r['id'], aeid)
        # try register in stopped auth-event
        data = {'email': 'test@test.com', 'password': '123456'}
        response = c.register(aeid, data)
        self.assertEqual(response.status_code, 400)
        # try register in started auth-event
        c.authenticate(self.aeid, test_data.pwd_auth)
        response = c.post('/api/auth-event/%d/%s/' % (aeid, 'started'), {})
        self.assertEqual(response.status_code, 200)
        data = {'email': 'test@test.com', 'password': '123456'}
        response = c.register(aeid, data)
        self.assertEqual(response.status_code, 200)

    def test_list_event(self):
        self.test_create_event()
        c = JClient()
        c.authenticate(self.aeid, test_data.pwd_auth)

        response = c.get('/api/auth-event/', {})
        self.assertEqual(response.status_code, 200)
        r = json.loads(response.content.decode('utf-8'))
        self.assertEqual(len(r['events']), 2)

    def test_edit_event_success(self):
        c = JClient()
        c.authenticate(self.aeid, test_data.pwd_auth)

        response = c.post('/api/auth-event/%d/' % self.aeid, test_data.auth_event5)
        self.assertEqual(response.status_code, 200)
        r = json.loads(response.content.decode('utf-8'))
        self.assertEqual(r['status'], 'ok')

        response = c.post('/api/auth-event/%d/' % self.aeid, test_data.ae_email_fields_incorrect1)
        self.assertEqual(response.status_code, 400)
        r = json.loads(response.content.decode('utf-8'))
        self.assertEqual(r['msg'], 'Maximum number of fields reached')

        response = c.get('/api/auth-event/', {})
        self.assertEqual(response.status_code, 200)
        r = json.loads(response.content.decode('utf-8'))
        self.assertEqual(len(r['events']), 1)

    def test_delete_event_success(self):
        self.test_create_event()
        c = JClient()
        c.authenticate(self.aeid, test_data.pwd_auth)

        response = c.delete('/api/auth-event/1/', {})
        self.assertEqual(response.status_code, 200)
        r = json.loads(response.content.decode('utf-8'))
        self.assertEqual(r['status'], 'ok')

    def test_create_acl(self):
        c = JClient()
        c.authenticate(self.aeid, test_data.pwd_auth)
        data = {
                'userid': self.userid,
                'perms': [{
                    'object_type': 'AuthEvent',
                    'perm': 'vote',
                    'user': self.testuser.username}, ]
        }
        response = c.post('/api/acl/', data)
        self.assertEqual(response.status_code, 200)
        self.assertNotEqual(0, ACL.objects.filter(user=self.userid, perm='vote').count())

    def test_delete_acl(self):
        c = JClient()
        c.authenticate(self.aeid, test_data.pwd_auth)
        response = c.delete('/api/acl/%s/%s/%s/' % (self.testuser.username, 'election', 'vote'), {})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(0, ACL.objects.filter(user=self.userid, perm='vote').count())

    def test_view_acl(self):
        c = JClient()
        c.authenticate(self.aeid, test_data.pwd_auth)
        response = c.get('/api/acl/%s/%s/%s/' % (self.testuser.username, 'User', 'create'), {})
        self.assertEqual(response.status_code, 200)
        r = json.loads(response.content.decode('utf-8'))
        self.assertEqual(r['perm'], True)

        response = c.get('/api/acl/%s/%s/%s/' % (self.testuser.username, 'Vote', 'create'), {})
        self.assertEqual(response.status_code, 200)
        r = json.loads(response.content.decode('utf-8'))
        self.assertEqual(r['perm'], False)

    def test_acl_mine(self):
        c = JClient()
        c.authenticate(self.aeid, test_data.pwd_auth)
        response = c.get('/api/acl/mine/', {})
        self.assertEqual(response.status_code, 200)
        r = json.loads(response.content.decode('utf-8'))
        self.assertEqual(len(r['perms']), 7)

        response = c.get('/api/acl/mine/?object_type=ACL', {})
        self.assertEqual(response.status_code, 200)
        r = json.loads(response.content.decode('utf-8'))
        self.assertEqual(len(r['perms']), 3)

    def test_available_packs(self):
        c = JClient()
        response = c.get('/api/available-packs/', {})
        self.assertEqual(response.status_code, 200)
        r = json.loads(response.content.decode('utf-8'))
        self.assertEqual(r, settings.AVAILABLE_PACKS)

    def test_available_payment_methods(self):
        c = JClient()
        response = c.get('/api/available-payment-methods/', {})
        self.assertEqual(response.status_code, 200)
        r = json.loads(response.content.decode('utf-8'))
        self.assertEqual(r, settings.AVAILABLE_PAYMENT_METHODS)

    def test_get_user_info(self):
        c = JClient()
        c.authenticate(self.aeid, test_data.pwd_auth)
        response = c.get('/api/user/' + str(self.userid) + '/', {})
        self.assertEqual(response.status_code, 403)
        acl = ACL(user=self.testuser.userdata, object_type='UserData',
                perm='view', object_id=self.userid)
        acl.save()
        response = c.get('/api/user/' + str(self.userid) + '/', {})
        self.assertEqual(response.status_code, 200)
        r = json.loads(response.content.decode('utf-8'))
        self.assertEqual(r['email'], test_data.pwd_auth_email['email'])

    def test_action_add_credits(self):
        c = JClient()
        c.authenticate(self.aeid, test_data.pwd_auth)
        data = {
            "pack_id": 0,
            "num_credits": 500,
            "payment_method": "paypal"
        }
        response = c.post('/api/user/add-credits/', data)
        self.assertEqual(response.status_code, 200)
        r = json.loads(response.content.decode('utf-8'))
        self.assertEqual(r, {'paypal_url': 'foo'})


def create_authevent(authevent):
    c = JClient()
    c.authenticate(0, test_data.admin)
    return c.post('/api/auth-event/', authevent)


class TestAuthEvent(TestCase):
    def setUp(self):
        u = User(username=test_data.admin['username'])
        u.set_password(test_data.admin['password'])
        u.save()
        u.userdata.save()
        self.user = u

        u2 = User(username="noperm")
        u2.set_password("qwerty")
        u2.save()
        u2.userdata.save()

        acl = ACL(user=u.userdata, object_type='AuthEvent', perm='create')
        acl.save()

    def test_create_auth_event_without_perm(self):
        data = test_data.ae_email_default
        user = {'username': 'noperm', 'password': 'qwerty'}

        c = JClient()
        response = c.post('/api/auth-event/', data)
        self.assertEqual(response.status_code, 403)

        c.authenticate(0, user)
        response = c.post('/api/auth-event/', data)
        self.assertEqual(response.status_code, 403)

    def test_create_auth_event_with_perm(self):
        acl = ACL(user=self.user.userdata, object_type='AuthEvent', perm='create')
        acl.save()

        c = JClient()
        c.authenticate(0, test_data.admin)
        response = c.post('/api/auth-event/', test_data.ae_email_default)
        self.assertEqual(response.status_code, 200)
        response = c.post('/api/auth-event/', test_data.ae_sms_default)
        self.assertEqual(response.status_code, 200)

    def test_create_authevent_email(self):
        response = create_authevent(test_data.ae_email_default)
        self.assertEqual(response.status_code, 200)

    def test_create_authevent_sms(self):
        response = create_authevent(test_data.ae_sms_default)
        self.assertEqual(response.status_code, 200)

    def test_create_authevent_email_incorrect(self):
        response = create_authevent(test_data.ae_email_fields_incorrect)
        self.assertEqual(response.status_code, 400)
        response = create_authevent(test_data.ae_email_config_incorrect1)
        self.assertEqual(response.status_code, 400)
        response = create_authevent(test_data.ae_email_config_incorrect2)
        self.assertEqual(response.status_code, 400)

    def test_create_authevent_sms_incorrect(self):
        response = create_authevent(test_data.ae_sms_config_incorrect)
        self.assertEqual(response.status_code, 400)
        response = create_authevent(test_data.ae_sms_fields_incorrect)
        self.assertEqual(response.status_code, 400)

    def test_create_authevent_email_change(self):
        response = create_authevent(test_data.ae_email_config)
        self.assertEqual(response.status_code, 200)
        response = create_authevent(test_data.ae_email_fields)
        self.assertEqual(response.status_code, 200)

    def test_create_authevent_sms_change(self):
        response = create_authevent(test_data.ae_sms_config)
        self.assertEqual(response.status_code, 200)
        response = create_authevent(test_data.ae_sms_fields)
        self.assertEqual(response.status_code, 200)


class TestRegisterAndAuthenticateEmail(TestCase):
    def setUp(self):
        ae = AuthEvent(auth_method="email",
                auth_method_config=test_data.authmethod_config_email_default,
                status='started',
                census="open")
        ae.save()
        self.aeid = ae.pk

        u_email = User(username=test_data.admin['username'])
        u_email.set_password(test_data.admin['password'])
        u_email.save()
        u_email.userdata.event = ae
        u_email.userdata.save()
        self.u_email = u_email.userdata

        acl = ACL(user=u_email.userdata, object_type='AuthEvent', perm='edit',
            object_id=self.aeid)
        acl.save()

        u = User(username=test_data.auth_email_default['email'])
        u.is_active = False
        u.save()
        u.userdata.event = ae
        u.userdata.save()
        self.u = u.userdata

        c = Code(user=u.userdata, code=test_data.auth_email_default['code'])
        c.save()
        self.code = c

    def test_add_census_authevent_email_default(self):
        c = JClient()
        c.authenticate(0, test_data.admin)
        response = c.census(self.aeid, test_data.census_email_default)
        self.assertEqual(response.status_code, 200)

    def test_add_census_authevent_email_fields(self):
        c = JClient()
        c.authenticate(0, test_data.admin)
        response = c.census(self.aeid, test_data.census_email_fields)
        self.assertEqual(response.status_code, 200)

    def test_add_census_authevent_email_default_incorrect(self):
        c = JClient()
        c.authenticate(0, test_data.admin)
        response = c.census(self.aeid, test_data.census_sms_default)
        self.assertEqual(response.status_code, 400)
        response = c.census(self.aeid, test_data.census_sms_fields)
        self.assertEqual(response.status_code, 400)

    def test_add_census_authevent_email_fields_incorrect(self):
        c = JClient()
        c.authenticate(0, test_data.admin)
        response = c.census(self.aeid, test_data.census_sms_default)
        self.assertEqual(response.status_code, 400)
        response = c.census(self.aeid, test_data.census_sms_fields)
        self.assertEqual(response.status_code, 400)

    def test_add_register_authevent_email_default(self):
        c = JClient()
        response = c.register(self.aeid, test_data.register_email_default)
        self.assertEqual(response.status_code, 200)

    def test_add_register_authevent_email_fields(self):
        c = JClient()
        response = c.register(self.aeid, test_data.register_email_fields)
        self.assertEqual(response.status_code, 200)

    def test_add_register_authevent_email_fields_incorrect(self):
        c = JClient()
        response = c.register(self.aeid, test_data.register_sms_default)
        self.assertEqual(response.status_code, 400)

    def _test_authenticate_authevent_email_default(self):
        c = JClient()
        response = c.authenticate(self.aeid, test_data.auth_email_default)
        self.assertEqual(response.status_code, 200)

    def _test_authenticate_authevent_email_fields(self):
        c = JClient()
        self.u.metadata = {"name": test_data.auth_email_fields['name']}
        self.u.save()
        response = c.authenticate(self.aeid, test_data.auth_email_fields)
        self.assertEqual(response.status_code, 200)


class TestRegisterAndAuthenticateSMS(TestCase):
    def setUp(self):
        ae = AuthEvent(auth_method="sms",
                auth_method_config=test_data.authmethod_config_sms_default,
                status='started',
                census="open")
        ae.save()
        self.aeid = ae.pk

        u_sms = User(username=test_data.admin['username'])
        u_sms.set_password(test_data.admin['password'])
        u_sms.save()
        u_sms.userdata.event = ae
        u_sms.userdata.save()
        self.u_sms = u_sms.userdata

        acl = ACL(user=u_sms.userdata, object_type='AuthEvent', perm='edit',
            object_id=self.aeid)
        acl.save()

        u = User(username=test_data.auth_sms_default['tlf'])
        u.is_active = False
        u.save()
        u.userdata.event = ae
        u.userdata.save()
        self.u = u.userdata

        self.code = Code(u.userdata, test_data.auth_sms_default['code'])

    def test_add_census_authevent_sms_default(self):
        c = JClient()
        c.authenticate(0, test_data.admin)
        response = c.census(self.aeid, test_data.census_sms_default)
        self.assertEqual(response.status_code, 200)

    def test_add_census_authevent_sms_fields(self):
        c = JClient()
        c.authenticate(0, test_data.admin)
        response = c.census(self.aeid, test_data.census_sms_fields)
        self.assertEqual(response.status_code, 200)

    def test_add_register_authevent_sms_default(self):
        c = JClient()
        response = c.register(self.aeid, test_data.register_sms_default)
        self.assertEqual(response.status_code, 200)

    def test_add_register_authevent_sms_fields(self):
        c = JClient()
        response = c.register(self.aeid, test_data.register_sms_fields)
        self.assertEqual(response.status_code, 200)

    def _test_authenticate_authevent_sms_default(self):
        c = JClient()
        response = c.authenticate(self.aeid, test_data.auth_sms_default)
        self.assertEqual(response.status_code, 200)

    def _test_authenticate_authevent_sms_fields(self):
        c = JClient()
        self.u.metadata = {"name": test_data.auth_sms_fields['name']}
        response = c.authenticate(self.aeid, test_data.auth_sms_fields)
        self.assertEqual(response.status_code, 200)
