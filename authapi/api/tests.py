import json
from django.test import TestCase
from django.test import Client


class ApiTestCase(TestCase):
    def setUp(self):
        pass

    def test_api(self):
        c = Client()
        data = {'username': 'john', 'password': 'smith'}
        response = c.post('/api/test/', data)

        self.assertEqual(response.status_code, 200)
        r = json.loads(response.content.decode('utf-8'))
        self.assertEqual(r['status'], 'ok')
        self.assertEqual(r['post']['username'][0], 'john')
        self.assertEqual(r['post']['password'][0], 'smith')
