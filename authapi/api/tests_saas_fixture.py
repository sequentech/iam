import json
from django.test import TestCase
from django.contrib.auth.models import User

from api.models import ACL, AuthEvent, UserData
from api.tests import JClient
from authmethods.models import Code
from captcha.models import Captcha
from captcha.views import newcaptcha


class TestFixtureSaas(TestCase):
    fixtures = ['saas.json']

    def setUp(self):
        self.ae = AuthEvent.objects.get(pk=1)

    def test_register_user(self):

        captcha = newcaptcha()
        user = {
                'Email': 'test@agoravoting.com',
                'tlf': '+34666666667',
                'captcha_code': captcha.code,
                'Captcha': captcha.challenge,
                'Acepto las <a href="https://agoravoting.com/#tos">condiciones de servicio</a>': True,
        }
        c = JClient()
        init_users = UserData.objects.count()
        response = c.register(self.ae.pk, user)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(init_users + 1, UserData.objects.count())

        userdata = UserData.objects.get(tlf=user['tlf'], event=self.ae)
        self.assertTrue(ACL.objects.filter(user=userdata,
                object_type='UserData', perm='edit', object_id=userdata.pk))
        self.assertTrue(ACL.objects.filter(user=userdata,
                object_type='AuthEvent', perm='create'))


    def test_authenticate_user(self):
        u = User.objects.create_user('test', 'test@agoravoting.com', 'test')
        u.userdata.event = self.ae
        u.userdata.tlf = '+34666666667'
        u.userdata.save()

        acl = ACL(user=u.userdata, object_type='UserData', perm='edit', object_id=u.pk)
        acl.save()
        acl = ACL(user=u.userdata, object_type='AuthEvent', perm='create', object_id=0)
        acl.save()

        code = Code(user=u.userdata, code='abcdef', auth_event_id=self.ae.pk)
        code.save()

        auth = {
                'Email': 'test@agoravoting.com',
                'tlf': '+34666666667',
                'code': code.code,
        }

        c = JClient()
        response = c.authenticate(1, auth)
        self.assertEqual(response.status_code, 200)
