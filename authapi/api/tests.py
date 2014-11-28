import time
import json
from django.test import TestCase
from django.test import Client
from utils import verifyhmac
from django.conf import settings


from django.contrib.auth.models import User
from .models import ACL

PWD_AUTH_DATA = {
    'auth-method': 'user-and-password',
    'auth-data': {'username': 'john', 'password': 'smith'}
}


class JClient(Client):
    def __init__(self, *args, **kwargs):
        self.auth_token = ''
        super(JClient, self).__init__(*args, **kwargs)

    def login(self, data):
        response = self.post('/api/login/', data)
        r = json.loads(response.content.decode('utf-8'))
        self.set_auth_token(r['auth-token'])
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
        u = User(username='john')
        u.set_password('smith')
        u.save()

        acl = ACL(user=u.userdata, perm='create_user')
        acl.save()

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
        data = {
            'auth-method': 'user-and-password',
            'auth-data': {'username': 'john', 'password': 'smith'}
        }
        response = c.post('/api/login/', data)

        self.assertEqual(response.status_code, 200)
        r = json.loads(response.content.decode('utf-8'))
        self.assertEqual(r['status'], 'ok')
        self.assertEqual(verifyhmac(settings.SHARED_SECRET,
            r['auth-token']), True)
        time.sleep(3)
        self.assertEqual(verifyhmac(settings.SHARED_SECRET,
            r['auth-token'], seconds=3), False)

        data = {
            'auth-method': 'user-and-password',
            'auth-data': {'username': 'john', 'password': 'fake'}
        }
        response = c.post('/api/login/', data)

        self.assertEqual(response.status_code, 200)
        r = json.loads(response.content.decode('utf-8'))
        self.assertEqual(r['status'], 'nok')

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
        c.login(PWD_AUTH_DATA)

        data = {
            "permission": "delete_user",
            "permission_data": "newuser"
        }
        response = c.post('/api/get-perms/', data)

        self.assertEqual(response.status_code, 200)
        r = json.loads(response.content.decode('utf-8'))
        self.assertEqual(r['status'], 'nok')

    def test_getperms_noperm(self):
        c = JClient()
        c.login(PWD_AUTH_DATA)

        data = {
            "permission": "create_user",
            "permission_data": "newuser"
        }
        response = c.post('/api/get-perms/', data)

        self.assertEqual(response.status_code, 200)
        r = json.loads(response.content.decode('utf-8'))
        self.assertEqual(r['status'], 'ok')
        self.assertEqual(verifyhmac(settings.SHARED_SECRET,
            r['permission-token']), True)
