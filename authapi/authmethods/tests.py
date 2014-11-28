from django.test import TestCase

import json
from api.tests import JClient


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
