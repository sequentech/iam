import time
import json
from django.test import TestCase
from django.test import Client
from utils import verifyhmac
from django.conf import settings


from django.contrib.auth.models import User
from .models import ACL, AuthEvent

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

    def validate(self, authevent, data):
        response = self.post('/api/auth-event/%d/validate/' % authevent, data)
        r = json.loads(response.content.decode('utf-8'))
        self.set_auth_token(r.get('auth-token'))
        return response

    def login(self, authevent, data):
        response = self.post('/api/auth-event/%d/login/' % authevent, data)
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
        auth_method_config = test_data.auth_event4['config']
        auth_method_config.update(test_data.auth_event4['pipeline'])
        ae = AuthEvent(pk=1,
                name='test 1',
                auth_method=test_data.auth_event4['auth_method'],
                auth_method_config=auth_method_config,
                metadata=test_data.auth_event4['metadata'])
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
        response = c.post('/api/auth-event/%d/%s/' % (self.aeid, 'start'), {})
        self.assertEqual(response.status_code, 403)
        response = c.post('/api/auth-event/%d/%s/' % (self.aeid, 'stop'), {})
        self.assertEqual(response.status_code, 403)

        c.login(self.aeid, test_data.pwd_auth)

        response = c.post('/api/auth-event/%d/%s/' % (self.aeid, 'start'), {})
        self.assertEqual(response.status_code, 200)
        response = c.post('/api/auth-event/%d/%s/' % (self.aeid, 'stop'), {})
        self.assertEqual(response.status_code, 200)
        response = c.post('/api/auth-event/%d/%s/' % (self.aeid, 'stop'), {})
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

    def test_login(self):
        c = JClient()
        data = {'username': 'john', 'password': 'smith'}
        response = c.login(self.aeid, data)

        self.assertEqual(response.status_code, 200)
        r = json.loads(response.content.decode('utf-8'))
        self.assertEqual(r['status'], 'ok')
        self.assertEqual(verifyhmac(settings.SHARED_SECRET,
            r['auth-token']), True)
        time.sleep(3)
        self.assertEqual(verifyhmac(settings.SHARED_SECRET,
            r['auth-token'], seconds=3), False)

        data = {'username': 'john', 'password': 'fake'}
        response = c.login(self.aeid, data)
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
        c.login(self.aeid, test_data.pwd_auth)
        data = {
            "object_type": "User",
            "permission": "delete"
        }
        response = c.post('/api/get-perms/', data)

        self.assertEqual(response.status_code, 400)

    def test_getperms_perm(self):
        c = JClient()
        c.login(self.aeid, test_data.pwd_auth)
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
        c.login(self.aeid, test_data.pwd_auth)

        data = test_data.auth_event1
        response = c.post('/api/auth-event/', data)
        self.assertEqual(response.status_code, 200)
        r = json.loads(response.content.decode('utf-8'))
        self.assertEqual(r['id'], 2)

    def test_list_event(self):
        self.test_create_event()
        c = JClient()
        c.login(self.aeid, test_data.pwd_auth)

        response = c.get('/api/auth-event/', {})
        self.assertEqual(response.status_code, 200)
        r = json.loads(response.content.decode('utf-8'))
        self.assertEqual(len(r['events']), 2)
        self.assertEqual(r['events'][1]['name'], 'foo election')

    def test_edit_event_success(self):
        c = JClient()
        c.login(self.aeid, test_data.pwd_auth)

        data = test_data.auth_event2
        response = c.post('/api/auth-event/%d/' % self.aeid, data)
        self.assertEqual(response.status_code, 200)
        r = json.loads(response.content.decode('utf-8'))
        self.assertEqual(r['status'], 'ok')

        response = c.get('/api/auth-event/', {})
        self.assertEqual(response.status_code, 200)
        r = json.loads(response.content.decode('utf-8'))
        self.assertEqual(len(r['events']), 1)
        self.assertEqual(r['events'][0]['name'], 'bar election')

    def test_delete_event_success(self):
        self.test_create_event()
        c = JClient()
        c.login(self.aeid, test_data.pwd_auth)

        response = c.delete('/api/auth-event/1/', {})
        self.assertEqual(response.status_code, 200)
        r = json.loads(response.content.decode('utf-8'))
        self.assertEqual(r['status'], 'ok')

    def test_create_acl(self):
        c = JClient()
        c.login(self.aeid, test_data.pwd_auth)
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
        c.login(self.aeid, test_data.pwd_auth)
        response = c.delete('/api/acl/%s/%s/%s/' % (self.testuser.username, 'election', 'vote'), {})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(0, ACL.objects.filter(user=self.userid, perm='vote').count())

    def test_view_acl(self):
        c = JClient()
        c.login(self.aeid, test_data.pwd_auth)
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
        c.login(self.aeid, test_data.pwd_auth)
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
        c.login(self.aeid, test_data.pwd_auth)
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
        c.login(self.aeid, test_data.pwd_auth)
        data = {
            "pack_id": 0,
            "num_credits": 500,
            "payment_method": "paypal"
        }
        response = c.post('/api/user/add-credits/', data)
        self.assertEqual(response.status_code, 200)
        r = json.loads(response.content.decode('utf-8'))
        self.assertEqual(r, {'paypal_url': 'foo'})
