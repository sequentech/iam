import json
from django.contrib.auth.models import User
from django.test import TestCase

from api import test_data
from api.models import ACL, AuthEvent
from api.tests import JClient
from authmethods.models import Code
from captcha.models import Captcha

# Create your tests here.

class TestProcessCaptcha(TestCase):
    fixtures = ['initial.json']
    def setUp(self):
        ae = AuthEvent(auth_method="email",
                auth_method_config=test_data.authmethod_config_email_default,
                extra_fields=test_data.ae_email_fields_captcha['extra_fields'],
                status='started',
                census="open")
        ae.save()
        self.ae = ae
        self.aeid = ae.pk

        u_admin = User(username=test_data.admin['username'])
        u_admin.set_password(test_data.admin['password'])
        u_admin.save()
        u_admin.userdata.event = ae
        u_admin.userdata.save()

        acl = ACL(user=u_admin.userdata, object_type='AuthEvent', perm='edit',
            object_id=self.aeid)
        acl.save()


    def test_create_new_captcha(self):
        c = JClient()
        self.assertEqual(0, Captcha.objects.count())
        response = c.get('/api/captcha/new/', {})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(1, Captcha.objects.count())

    def test_create_authevent_email_with_captcha(self):
        c = JClient()

        #captcha
        response = c.get('/api/captcha/new/', {})
        self.assertEqual(response.status_code, 200)
        captcha = Captcha.objects.all()[0]
        data = test_data.register_email_fields
        data.update({'captcha_code': captcha.code, 'captcha_answer': captcha.challenge})

        # add census without problem with captcha
        c.authenticate(0, test_data.admin)
        response = c.census(self.aeid, test_data.census_email_default)
        self.assertEqual(response.status_code, 200)
        response = c.get('/api/auth-event/%d/census/' % self.aeid, {})
        self.assertEqual(response.status_code, 200)
        r = json.loads(response.content.decode('utf-8'))
        self.assertEqual(len(r['userids']), 4)

        # add register
        response = c.register(self.aeid, data)
        self.assertEqual(response.status_code, 200)

    def test_create_authevent_sms_with_captcha(self):
        self.ae.auth_method = 'sms'
        self.ae.auth_method_config = test_data.authmethod_config_sms_default
        self.ae.save()
        c = JClient()

        #captcha
        response = c.get('/api/captcha/new/', {})
        self.assertEqual(response.status_code, 200)
        captcha = Captcha.objects.all()[0]
        data = test_data.register_sms_default
        data.update({'captcha_code': captcha.code, 'tlf': '999999999',
                'captcha_answer': captcha.challenge})

        # add census without problem with captcha
        c.authenticate(0, test_data.admin)
        response = c.census(self.aeid, test_data.census_sms_default)
        self.assertEqual(response.status_code, 200)
        response = c.get('/api/auth-event/%d/census/' % self.aeid, {})
        self.assertEqual(response.status_code, 200)
        r = json.loads(response.content.decode('utf-8'))
        self.assertEqual(len(r['userids']), 4)

        # add register
        response = c.register(self.aeid, data)
        self.assertEqual(response.status_code, 200)
