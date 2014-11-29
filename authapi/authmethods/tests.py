from django.core import mail
from django.test import TestCase

import json
from api.tests import JClient
from api.models import AuthEvent


class AuthMethodTestCase(TestCase):
    def setUp(self):
        j = {
               'subject': 'subject',
               'timestamp': 5,
               'url': 'http://localhost:80',
               'msg': 'This is a validator link: ',
               'mail_from': 'mail_from' }
        ae = AuthEvent(pk=1, name='test', auth_method='email',
                auth_method_config=json.dumps(j))
        ae.save()

    def test_method_custom_view(self):
        c = JClient()
        response = c.get('/api/authmethod/user-and-password/test/asdfdsf/', {})
        self.assertEqual(response.status_code, 200)
        r = json.loads(response.content.decode('utf-8'))
        self.assertEqual(r['status'], 'ok')

        response = c.get('/api/authmethod/user-and-password/test/asdfdsf/cxzvcx/', {})
        self.assertEqual(response.status_code, 404)

    def test_method_email(self):
        c = JClient()
        response = c.post('/api/authmethod/email/register/1/',
                {'email': 'test@test.com'})
        self.assertEqual(response.status_code, 200)
        r = json.loads(response.content.decode('utf-8'))
        self.assertEqual(r['status'], 'ok')

        body = mail.outbox[0].body
        for word in body.split():
            if word.startswith('http://'):
                user = word.split('/')[-2]
                code = word.split('/')[-1]
                break

        # valid code
        response = c.get('/api/authmethod/email/validate/%s/%s/' % (user, code), {})
        self.assertEqual(response.status_code, 200)
        r = json.loads(response.content.decode('utf-8'))
        self.assertEqual(r['status'], 'ok')

        # invalid code
        response = c.get('/api/authmethod/email/validate/%s/bad/' % (user), {})
        self.assertEqual(response.status_code, 200)
        r = json.loads(response.content.decode('utf-8'))
        self.assertEqual(r['status'], 'nok')
