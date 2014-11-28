import json
from django.test import TestCase
from django.test import Client
from utils import verifyhmac
from django.conf import settings


from django.contrib.auth.models import User


class ApiTestCase(TestCase):
    def setUp(self):
        pass

    def test_api(self):
        c = Client()
        data = {'username': 'john', 'password': 'smith'}
        json_data = json.dumps(data)

        json_data = json.dumps(data)
        response = c.post('/api/test/', json_data, content_type="application/json")

        self.assertEqual(response.status_code, 200)
        r = json.loads(response.content.decode('utf-8'))
        self.assertEqual(r['status'], 'ok')
        self.assertEqual(r['post']['username'], 'john')
        self.assertEqual(r['post']['password'], 'smith')

    def test_login(self):
        c = Client()
        data = {
            'auth-method': 'user-and-password',
            'auth-data': {'username': 'john', 'password': 'smith'}
        }
        json_data = json.dumps(data)
        response = c.post('/api/login/', json_data, content_type="application/json")

        self.assertEqual(response.status_code, 200)
        r = json.loads(response.content.decode('utf-8'))
        self.assertEqual(r['status'], 'ok')
        self.assertEqual(verifyhmac(settings.SHARED_SECRET, r['auth-token']), True)
