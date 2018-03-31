# This file is part of authapi.
# Copyright (C) 2014-2016  Agora Voting SL <agora@agoravoting.com>

# authapi is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License.

# authapi  is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.

# You should have received a copy of the GNU Affero General Public License
# along with authapi.  If not, see <http://www.gnu.org/licenses/>.

import time
import json
import copy
from datetime import datetime
from django.core import mail
from django.test import TestCase
from django.test import Client
from django.test.utils import override_settings
from django.conf import settings
from django.contrib.auth.models import User

from . import test_data
from .models import ACL, AuthEvent, Action, BallotBox, TallySheet
from authmethods.models import Code, MsgLog
from utils import verifyhmac, reproducible_json_dumps
from authmethods.utils import get_cannonical_tlf

def flush_db_load_fixture(ffile="initial.json"):
    from django.core import management
    management.call_command("flush", verbosity=0, interactive=False)
    management.call_command("loaddata", ffile, verbosity=0)

override_celery_data = dict(CELERY_EAGER_PROPAGATES_EXCEPTIONS=True,
                       CELERY_ALWAYS_EAGER=True,
                       BROKER_BACKEND='memory')

def parse_json_response(response):
    return json.loads(response.content.decode('utf-8'))

def static_isodates(data):
    '''
    Returns a deepcopy of a list or dict with static iso 8601 dates
    '''
    static_date = '2018-01-01T00:00:00.000000+00:00'
    def is_isodate(obj):
        try:
            datetime.strptime(obj[:-6], "%Y-%m-%dT%H:%M:%S.%f")
            return True
        except:
            return False

    def visit_dict(obj):
        keys = list(obj.keys())
        for key in keys:
            if isinstance(obj[key], str) and is_isodate(obj[key]):
                obj[key] = static_date
            else:
                visit_el(obj[key])

    def visit_list(l):
        l2 = []
        for el in l:
            if isinstance(el, str):
              if is_isodate(el):
                  l2.append(static_date)
              else:
                  l2.append(el)
            else:
                visit_el(el)
                l2.append(el)
        l[:] = l2

    def visit_el(el):
        if isinstance(el, list):
            visit_list(el)
        elif isinstance(el, dict):
            visit_dict(el)

    data2 = copy.deepcopy(data)
    visit_el(data2)
    return data2


class JClient(Client):
    def __init__(self, *args, **kwargs):
        self.auth_token = ''
        super(JClient, self).__init__(*args, **kwargs)

    def census(self, authevent, data):
        response = self.post('/api/auth-event/%d/census/' % authevent, data)
        r = parse_json_response(response)
        return response

    def register(self, authevent, data):
        response = self.post('/api/auth-event/%d/register/' % authevent, data)
        r = parse_json_response(response)
        self.set_auth_token(r.get('auth-token'))
        return response

    def authenticate(self, authevent, data):
        response = self.post('/api/auth-event/%d/authenticate/' % authevent, data)
        r = parse_json_response(response)
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



class ApiTestCreateNotReal(TestCase):
    def setUpTestData():
        flush_db_load_fixture()

    def setUp(self):
        self.ae = AuthEvent(auth_method=test_data.auth_event4['auth_method'],
                auth_method_config=test_data.authmethod_config_email_default)
        self.ae.save()

        u = User(username=test_data.admin['username'], email=test_data.admin['email'])
        u.set_password(test_data.admin['password'])
        u.save()
        u.userdata.event = self.ae
        u.userdata.save()
        self.user = u

        u2 = User(username='noperm', email="noperm@agoravoting.com")
        u2.set_password("qwerty")
        u2.save()
        u2.userdata.save()

        self.aeid_special = 1

    def create_authevent(self, authevent):
        c = JClient()
        c.authenticate(self.ae.pk, test_data.admin)
        return c.post('/api/auth-event/', authevent)

    def test_create_authevent_test_and_real_create(self):
        acl = ACL(user=self.user.userdata, object_type='AuthEvent', perm='create',
                object_id=0)
        acl.save()
        # test 1
        response = self.create_authevent(test_data.ae_email_default)
        self.assertEqual(response.status_code, 200)

        # real based_in previous: ok
        data = test_data.ae_email_real_based_in.copy()
        data['based_in'] = AuthEvent.objects.last().pk
        response = self.create_authevent(data)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(AuthEvent.objects.last().based_in, data['based_in'])

    def test_create_authevent_test_and_real_create_notreal(self):
        acl = ACL(user=self.user.userdata, object_type='AuthEvent', perm='create',
                object_id=0)
        acl.save()
        # test 1
        response = self.create_authevent(test_data.ae_email_default)
        self.assertEqual(response.status_code, 200)

        # real based_in previous: error create perm missing
        data = test_data.ae_email_real_based_in.copy()
        data['based_in'] = AuthEvent.objects.last().pk
        response = self.create_authevent(data)
        self.assertEqual(response.status_code, 200)

    def test_create_authevent_test_and_real_create_create_notreal(self):
        acl = ACL(user=self.user.userdata, object_type='AuthEvent', perm='create',
                object_id=0)
        acl.save()
        # test 1
        response = self.create_authevent(test_data.ae_email_default)
        self.assertEqual(response.status_code, 200)

        # real based_in previous: ok
        data = test_data.ae_email_real_based_in.copy()
        data['based_in'] = AuthEvent.objects.last().pk
        response = self.create_authevent(data)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(AuthEvent.objects.last().based_in, data['based_in'])

class UserDataDraftTestCase(TestCase):
    def setUpTestData():
        flush_db_load_fixture()

    def setUp(self):
        self.aeid = settings.ADMIN_AUTH_ID
        ae = AuthEvent.objects.get(pk=self.aeid)
        ae.auth_method = "user-and-password"
        ae.census = "open"
        ae.save()

        u = User(username=test_data.admin['username'], email=test_data.admin['email'])
        u.set_password('smith')
        u.save()
        u.userdata.event = ae
        u.userdata.save()
        self.userid = u.pk
        self.testuser = u

    @override_settings(CELERY_ALWAYS_EAGER=True)
    def test_draft(self):
        acl = ACL(user=self.testuser.userdata, object_type='UserData', perm='edit', object_id=self.userid)
        acl.save()

        c = JClient()
        c.authenticate(self.aeid, test_data.pwd_auth)
        no_draft = {}
        response = c.post('/api/user/draft/', {"draft_election": no_draft})
        self.assertEqual(response.status_code, 200)

        response = c.get('/api/user/draft/', {})
        self.assertEqual(response.status_code, 200)
        r = parse_json_response(response)
        self.assertEqual(r, no_draft)

        response = c.post('/api/user/draft/', {"draft_election": test_data.auth_event1})
        self.assertEqual(response.status_code, 200)

        response = c.get('/api/user/draft/', {})
        self.assertEqual(response.status_code, 200)
        r = parse_json_response(response)
        self.assertEqual(r, test_data.auth_event1)

class ApiTestCase(TestCase):
    def setUpTestData():
        flush_db_load_fixture()

    def setUp(self):
        ae = AuthEvent(auth_method=test_data.auth_event4['auth_method'],
                auth_method_config=test_data.authmethod_config_email_default)
        ae.save()

        u = User(username=test_data.admin['username'], email=test_data.admin['email'])
        u.set_password('smith')
        u.save()
        u.userdata.event = ae
        u.userdata.save()
        self.userid = u.pk
        self.testuser = u
        self.aeid = ae.pk

        acl = ACL(user=u.userdata, object_type='User', perm='create', object_id=0)
        acl.save()

        acl = ACL(user=u.userdata, object_type='AuthEvent', perm='create', object_id=0)
        acl.save()

        acl = ACL(user=u.userdata, object_type='AuthEvent', perm='view', object_id=0)
        acl.save()

        acl = ACL(user=u.userdata, object_type='AuthEvent', perm='edit', object_id=self.aeid)
        acl.save()

        acl = ACL(user=u.userdata, object_type='ACL', perm='delete', object_id=0)
        acl.save()

        acl = ACL(user=u.userdata, object_type='ACL', perm='view', object_id=0)
        acl.save()

        acl = ACL(user=u.userdata, object_type='ACL', perm='create', object_id=0)
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

    def test_authenticate(self):
        c = JClient()
        data = test_data.pwd_auth
        response = c.authenticate(self.aeid, data)

        self.assertEqual(response.status_code, 200)
        r = parse_json_response(response)
        self.assertEqual(r['status'], 'ok')
        self.assertEqual(verifyhmac(settings.SHARED_SECRET,
            r['auth-token']), True)
        time.sleep(3)
        self.assertEqual(verifyhmac(settings.SHARED_SECRET,
            r['auth-token'], seconds=3), False)

        data = {'email': 'john@agoravoting.com', 'password': 'fake'}
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
        r = parse_json_response(response)
        self.assertEqual(r['status'], 'ok')
        self.assertEqual(verifyhmac(settings.SHARED_SECRET,
            r['permission-token']), True)

    def test_getperms_perm_invalid(self):
        c = JClient()
        c.authenticate(self.aeid, test_data.pwd_auth)
        data = { "permission": "create" }
        response = c.post('/api/get-perms/', data)
        self.assertEqual(response.status_code, 400)

    def test_create_event(self):
        c = JClient()
        c.authenticate(self.aeid, test_data.pwd_auth)

        data = test_data.auth_event1
        response = c.post('/api/auth-event/', data)
        self.assertEqual(response.status_code, 200)
        r = parse_json_response(response)
        self.assertTrue('id' in  r and isinstance(r['id'], int))

    @override_settings(CELERY_ALWAYS_EAGER=True)
    def test_create_event_open(self):
        c = JClient()
        c.authenticate(self.aeid, test_data.pwd_auth)

        data = test_data.auth_event3
        response = c.post('/api/auth-event/', data)
        self.assertEqual(response.status_code, 200)
        r = parse_json_response(response)
        self.assertEqual(r['id'], self.aeid + 1)
        # try register in stopped auth-event
        data = {'email': 'test@test.com', 'password': '123456'}
        response = c.register(self.aeid + 1, data)
        self.assertEqual(response.status_code, 400)
        # try register in started auth-event
        c.authenticate(self.aeid, test_data.pwd_auth)
        response = c.post('/api/auth-event/%d/%s/' % (self.aeid + 1, 'started'), {})
        self.assertEqual(response.status_code, 200)
        data = {'email': 'test@test.com', 'password': '123456'}
        response = c.register(self.aeid + 1, data)
        self.assertEqual(response.status_code, 200)

    def test_list_event(self):
        self.test_create_event()
        c = JClient()
        c.authenticate(self.aeid, test_data.pwd_auth)

        response = c.get('/api/auth-event/', {})
        self.assertEqual(response.status_code, 200)
        r = parse_json_response(response)
        self.assertEqual(len(r['events']), 3)

    def test_edit_event_success(self):
        c = JClient()
        c.authenticate(self.aeid, test_data.pwd_auth)

        response = c.post('/api/auth-event/%d/' % self.aeid, test_data.auth_event5)
        self.assertEqual(response.status_code, 200)
        r = parse_json_response(response)
        self.assertEqual(r['status'], 'ok')

        response = c.get('/api/auth-event/', {})
        self.assertEqual(response.status_code, 200)
        r = parse_json_response(response)
        self.assertEqual(len(r['events']), 2)

    def test_delete_event_success(self):
        self.test_create_event()
        c = JClient()
        c.authenticate(self.aeid, test_data.pwd_auth)

        response = c.delete('/api/auth-event/%d/' % self.aeid, {})
        self.assertEqual(response.status_code, 200)
        r = parse_json_response(response)
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
        r = parse_json_response(response)
        self.assertEqual(r['perm'], True)

        response = c.get('/api/acl/%s/%s/%s/' % (self.testuser.username, 'Vote', 'create'), {})
        self.assertEqual(response.status_code, 200)
        r = parse_json_response(response)
        self.assertEqual(r['perm'], False)

    def test_acl_mine(self):
        c = JClient()
        c.authenticate(self.aeid, test_data.pwd_auth)
        response = c.get('/api/acl/mine/', {})
        self.assertEqual(response.status_code, 200)
        r = parse_json_response(response)
        self.assertEqual(len(r['perms']), 7)

        response = c.get('/api/acl/mine/?object_type=ACL', {})
        self.assertEqual(response.status_code, 200)
        r = parse_json_response(response)
        self.assertEqual(len(r['perms']), 3)

        response = c.get('/api/acl/mine/?object_type=AuthEvent&?perm=edit&?object_id=%d' % self.aeid, {})
        self.assertEqual(response.status_code, 200)
        r = parse_json_response(response)
        self.assertEqual(len(r['perms']), 3)

    def test_pagination(self):
        c = JClient()
        c.authenticate(self.aeid, test_data.pwd_auth)
        response = c.get('/api/acl/mine/?page=1&n=10', {})
        self.assertEqual(response.status_code, 200)
        r = parse_json_response(response)
        self.assertEqual(len(r['perms']), 7)

        response = c.get('/api/acl/mine/?page=1&n=31', {})
        self.assertEqual(response.status_code, 200)
        r = parse_json_response(response)
        self.assertEqual(len(r['perms']), 7)

        response = c.get('/api/acl/mine/?page=x&n=x', {})
        self.assertEqual(response.status_code, 200)
        r = parse_json_response(response)
        self.assertEqual(len(r['perms']), 7)

        response = c.get('/api/acl/mine/?page=1&n=5', {})
        self.assertEqual(response.status_code, 200)
        r = parse_json_response(response)
        self.assertEqual(len(r['perms']), 5)

        response = c.get('/api/acl/mine/?page=2&n=5', {})
        self.assertEqual(response.status_code, 200)
        r = parse_json_response(response)
        self.assertEqual(len(r['perms']), 2)

        response = c.get('/api/acl/mine/?object_type=ACL&?page=1&n=2', {})
        self.assertEqual(response.status_code, 200)
        r = parse_json_response(response)
        self.assertEqual(len(r['perms']), 2)

    def test_get_user_info(self):
        c = JClient()
        c.authenticate(self.aeid, test_data.pwd_auth)
        response = c.get('/api/user/' + str(self.userid) + '/', {})
        self.assertEqual(response.status_code, 403)
        acl = ACL(user=self.testuser.userdata, object_type='UserData',
                perm='edit', object_id=self.userid)
        acl.save()
        response = c.get('/api/user/' + str(self.userid) + '/', {})
        self.assertEqual(response.status_code, 200)
        r = parse_json_response(response)
        self.assertEqual(r['email'], test_data.admin['email'])

    def test_edit_user_info(self):
        data_bad = {'new_pwd': 'test00'}
        data_invalid = {'old_pwd': 'wrong', 'new_pwd': 'test00'}
        data = {'old_pwd': 'smith', 'new_pwd': 'test00'}

        c = JClient()
        c.authenticate(self.aeid, test_data.pwd_auth)

        # without perms
        response = c.post('/api/user/', data)
        self.assertEqual(response.status_code, 403)

        acl = ACL(user=self.testuser.userdata, object_type='UserData',
                perm='edit', object_id=self.userid)
        acl.save()
        acl = ACL(user=self.testuser.userdata, object_type='AuthEvent',
                perm='create')
        acl.save()

        # data bad
        response = c.post('/api/user/', data_bad)
        self.assertEqual(response.status_code, 400)

        # data invalid
        response = c.post('/api/user/', data_invalid)
        self.assertEqual(response.status_code, 400)
        r = parse_json_response(response)
        self.assertEqual(r['error_codename'], 'INVALID_OLD_PASSWORD')

        # data ok
        response = c.post('/api/user/', data)
        self.assertEqual(response.status_code, 200)

    @override_settings(CELERY_ALWAYS_EAGER=True)
    def test_reset_password(self):
        acl = ACL(user=self.testuser.userdata, object_type='UserData', perm='edit', object_id=self.userid)
        acl.save()
        acl = ACL(user=self.testuser.userdata, object_type='AuthEvent', perm='create')
        acl.save()

        c = JClient()
        c.authenticate(self.aeid, test_data.pwd_auth)
        response = c.post('/api/user/reset-pwd/', {})
        self.assertEqual(response.status_code, 200)

        response = c.authenticate(self.aeid, test_data.pwd_auth)
        self.assertEqual(response.status_code, 400)
        self.assertEqual(len(mail.outbox), 1)
        self.assertEqual(mail.outbox[0].subject, 'Reset password')


    def test_get_authmethod(self):
        c = JClient()
        c.authenticate(self.aeid, test_data.pwd_auth)
        response = c.get('/api/auth-event/module/', {})
        self.assertEqual(response.status_code, 200)

        response = c.get('/api/auth-event/module/email/', {})
        self.assertEqual(response.status_code, 200)


class TestAuthEvent(TestCase):
    def setUpTestData():
        flush_db_load_fixture()

    def setUp(self):
        self.ae = AuthEvent(auth_method=test_data.auth_event4['auth_method'],
                auth_method_config=test_data.authmethod_config_email_default)
        self.ae.save()

        u = User(username=test_data.admin['username'], email=test_data.admin['email'])
        u.set_password(test_data.admin['password'])
        u.save()
        u.userdata.event = self.ae
        u.userdata.save()
        self.user = u

        u2 = User(username='noperm', email="noperm@agoravoting.com")
        u2.set_password("qwerty")
        u2.save()
        u2.userdata.save()

        acl = ACL(user=u.userdata, object_type='AuthEvent', perm='create',
                object_id=0)
        acl.save()
        self.aeid_special = 1

    def create_authevent(self, authevent):
        c = JClient()
        c.authenticate(self.ae.pk, test_data.admin)
        return c.post('/api/auth-event/', authevent)

    @override_settings(CELERY_ALWAYS_EAGER=True)
    def test_register_authevent_special(self):
        data = {"email": "asd@asd.com", "captcha": "asdasd"}
        c = JClient()
        # Register
        response = c.register(self.aeid_special, data)
        self.assertEqual(response.status_code, 200)
        user = User.objects.get(email=data['email'])
        code = Code.objects.get(user=user.userdata)
        data['code'] = code.code
        # Authenticate
        response = c.authenticate(self.aeid_special, data)
        self.assertEqual(response.status_code, 200)
        # Create auth-event
        response = c.post('/api/auth-event/', test_data.ae_email_default)
        self.assertEqual(response.status_code, 200)

    def test_create_auth_event_without_perm(self):
        data = test_data.ae_email_default
        user = {'email': 'noperm@agoravoting.com', 'password': 'qwerty'}

        c = JClient()
        response = c.post('/api/auth-event/', data)
        self.assertEqual(response.status_code, 403)

        c.authenticate(0, user)
        response = c.post('/api/auth-event/', data)
        self.assertEqual(response.status_code, 403)

    def test_create_auth_event_with_perm(self):
        acl = ACL(user=self.user.userdata, object_type='AuthEvent',
                perm='create', object_id=0)
        acl.save()

        c = JClient()
        c.authenticate(self.ae.pk, test_data.admin)
        response = c.post('/api/auth-event/', test_data.ae_email_default)
        self.assertEqual(response.status_code, 200)
        response = c.post('/api/auth-event/', test_data.ae_sms_default)
        self.assertEqual(response.status_code, 200)

    def test_create_authevent_email(self):
        response = self.create_authevent(test_data.ae_email_default)
        self.assertEqual(response.status_code, 200)

    def test_create_authevent_sms(self):
        response = self.create_authevent(test_data.ae_sms_default)
        self.assertEqual(response.status_code, 200)

    def test_create_incorrect_authevent(self):
        response = self.create_authevent(test_data.ae_incorrect_authmethod)
        self.assertEqual(response.status_code, 400)
        r = parse_json_response(response)
        self.assertEqual(r['message'], 'Invalid authmethod\n')

        response = self.create_authevent(test_data.ae_incorrect_census)
        self.assertEqual(response.status_code, 400)
        r = parse_json_response(response)
        self.assertEqual(r['error_codename'], 'INVALID_CENSUS_TYPE')

        response = self.create_authevent(test_data.ae_without_authmethod)
        self.assertEqual(response.status_code, 400)
        r = parse_json_response(response)
        self.assertEqual(r['message'], 'Invalid authmethod\n')

        response = self.create_authevent(test_data.ae_without_census)
        self.assertEqual(response.status_code, 400)
        r = parse_json_response(response)
        self.assertEqual(r['error_codename'], 'INVALID_CENSUS_TYPE')

    def test_create_authevent_email_incorrect(self):
        response = self.create_authevent(test_data.ae_email_fields_incorrect)
        self.assertEqual(response.status_code, 400)
        r = parse_json_response(response)
        #TODO: receive the information in structured data
        self.assertEqual(r['message'], 'Invalid extra_field: boo not possible.\n')
        response = self.create_authevent(test_data.ae_email_fields_incorrect_empty)
        self.assertEqual(response.status_code, 400)
        r = parse_json_response(response)
        self.assertEqual(r['message'], 'Invalid extra_fields: bad name.\n')
        response = self.create_authevent(test_data.ae_email_fields_incorrect_len1)
        self.assertEqual(response.status_code, 400)
        r = parse_json_response(response)
        self.assertEqual(r['message'], 'Invalid extra_fields: bad name.\n')
        response = self.create_authevent(test_data.ae_email_fields_incorrect_len2)
        self.assertEqual(response.status_code, 400)
        r = parse_json_response(response)
        self.assertEqual(r['message'], 'Invalid extra_fields: bad max.\n')
        response = self.create_authevent(test_data.ae_email_fields_incorrect_type)
        self.assertEqual(response.status_code, 400)
        r = parse_json_response(response)
        self.assertEqual(r['message'], 'Invalid extra_fields: bad type.\n')
        response = self.create_authevent(test_data.ae_email_fields_incorrect_value_int)
        self.assertEqual(response.status_code, 400)
        r = parse_json_response(response)
        self.assertEqual(r['message'], 'Invalid extra_fields: bad min.\n')
        response = self.create_authevent(test_data.ae_email_fields_incorrect_value_bool)
        self.assertEqual(response.status_code, 400)
        r = parse_json_response(response)
        self.assertEqual(r['message'], 'Invalid extra_fields: bad required_on_authentication.\n')
        response = self.create_authevent(test_data.ae_email_fields_incorrect_max_fields)
        self.assertEqual(response.status_code, 400)
        r = parse_json_response(response)
        self.assertTrue('Maximum number of fields reached\n' in r['message'])
        response = self.create_authevent(test_data.ae_email_fields_incorrect_repeat)
        self.assertEqual(response.status_code, 400)
        r = parse_json_response(response)
        self.assertTrue('Two fields with same name: surname.\n' in r['message'])
        response = self.create_authevent(test_data.ae_email_fields_incorrect_email)
        self.assertEqual(response.status_code, 400)
        r = parse_json_response(response)
        self.assertEqual(r['message'], 'Type email not allowed.\n')
        response = self.create_authevent(test_data.ae_email_fields_incorrect_status)
        self.assertEqual(response.status_code, 400)
        r = parse_json_response(response)
        self.assertEqual(r['message'], 'Two fields with same name: status.\n')
        response = self.create_authevent(test_data.ae_sms_fields_incorrect_tlf)
        self.assertEqual(response.status_code, 400)
        r = parse_json_response(response)
        self.assertEqual(r['message'], 'Type tlf not allowed.\n')

        #response = self.create_authevent(test_data.ae_email_config_incorrect1)
        #self.assertEqual(response.status_code, 400)
        #response = self.create_authevent(test_data.ae_email_config_incorrect2)
        #self.assertEqual(response.status_code, 400)

    def _test_create_authevent_sms_incorrect(self):
        response = self.create_authevent(test_data.ae_sms_config_incorrect)
        self.assertEqual(response.status_code, 400)
        response = self.create_authevent(test_data.ae_sms_fields_incorrect)
        self.assertEqual(response.status_code, 400)

    def test_create_authevent_email_change(self):
        response = self.create_authevent(test_data.ae_email_config)
        self.assertEqual(response.status_code, 200)
        response = self.create_authevent(test_data.ae_email_fields)
        self.assertEqual(response.status_code, 200)

    def test_create_authevent_sms_change(self):
        response = self.create_authevent(test_data.ae_sms_config)
        self.assertEqual(response.status_code, 200)
        response = self.create_authevent(test_data.ae_sms_fields)
        self.assertEqual(response.status_code, 200)

    def test_create_authevent_test_and_real(self):
        # test 1
        response = self.create_authevent(test_data.ae_email_default)
        self.assertEqual(response.status_code, 200)

        # real based_in previous: ok
        data = test_data.ae_email_real_based_in.copy()
        data['based_in'] = AuthEvent.objects.last().pk
        response = self.create_authevent(data)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(AuthEvent.objects.last().based_in, data['based_in'])

        # real based_in id not exist: error
        data = test_data.ae_email_real_based_in.copy()
        data['based_in'] = 1 # default fixture vot
        response = self.create_authevent(data)
        self.assertEqual(response.status_code, 400)

        # real based_in id not permission for user: error
        data = test_data.ae_email_real_based_in.copy()
        data['based_in'] = AuthEvent.objects.last().pk + 10
        response = self.create_authevent(data)
        self.assertEqual(response.status_code, 400)

        # real no based_in
        response = self.create_authevent(test_data.ae_email_real)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(AuthEvent.objects.last().based_in, None)

    def test_get_auth_events(self):
        c = JClient()
        c.authenticate(self.ae.pk, test_data.admin)
        response = c.post('/api/auth-event/', test_data.ae_email_default)
        self.assertEqual(response.status_code, 200)
        response = c.get('/api/user/auth-event/', {})
        self.assertEqual(response.status_code, 200)
        r = parse_json_response(response)
        self.assertEqual(len(r['ids-auth-event']), 1)
        response = c.post('/api/auth-event/', test_data.ae_sms_default)
        self.assertEqual(response.status_code, 200)
        response = c.get('/api/user/auth-event/', {})
        self.assertEqual(response.status_code, 200)
        r = parse_json_response(response)
        self.assertEqual(len(r['ids-auth-event']), 2)

class TestExtraFields(TestCase):
    def setUpTestData():
        flush_db_load_fixture()

    def setUp(self):
        ae = AuthEvent(auth_method="email",
                auth_method_config=test_data.authmethod_config_email_default,
                status='started',
                census="open")
        ae.save()
        self.ae = ae
        self.aeid = ae.pk

        u_admin = User(username=test_data.admin['username'], email=test_data.admin['email'])
        u_admin.set_password(test_data.admin['password'])
        u_admin.save()
        u_admin.userdata.event = ae
        u_admin.userdata.save()
        self.uid_admin = u_admin.id

        self.admin_auth_data = dict(email=test_data.admin['email'], code="ERGERG")
        c = Code(user=u_admin.userdata, code=self.admin_auth_data['code'], auth_event_id=1)
        c.save()

        acl = ACL(user=u_admin.userdata, object_type='AuthEvent', perm='edit',
            object_id=self.aeid)
        acl.save()
        acl = ACL(user=u_admin.userdata, object_type='AuthEvent', perm='create',
            object_id=self.aeid)
        acl.save()

        u = User(username='test', email=test_data.auth_email_default['email'])
        u.save()
        u.userdata.event = ae
        u.userdata.save()
        self.u = u.userdata
        self.uid = u.id

        acl = ACL(user=u.userdata, object_type='AuthEvent', perm='vote',
            object_id=self.aeid)
        acl.save()

        c = Code(user=u.userdata, code=test_data.auth_email_default['code'], auth_event_id=ae.pk)
        c.save()
        self.code = c

    @override_settings(CELERY_EAGER_PROPAGATES_EXCEPTIONS=True,
                       CELERY_ALWAYS_EAGER=True,
                       BROKER_BACKEND='memory')
    def test_autofill_activate_field(self):
        self.ae.extra_fields = test_data.extra_field_autofill
        self.ae.save()

        u = User.objects.get(id=self.uid_admin)
        u.save()
        u.userdata.metadata = {"mesa": "mesa 42"}
        u.userdata.save()

        c = JClient()
        c.authenticate(self.ae.pk, self.admin_auth_data)

        u = User.objects.get(id=self.uid)
        self.assertEqual(u.userdata.metadata.get("mesa"), None)

        data = {'user-ids': [self.uid], 'comment': 'some comment here'}
        response = c.post('/api/auth-event/%d/census/activate/' % self.aeid, data)
        self.assertEqual(response.status_code, 200)

        u = User.objects.get(id=self.uid)
        self.assertEqual(u.userdata.metadata.get("mesa"), "mesa 42")

    @override_settings(CELERY_EAGER_PROPAGATES_EXCEPTIONS=True,
                       CELERY_ALWAYS_EAGER=True,
                       BROKER_BACKEND='memory')
    def test_autofill_deactivate_field(self):
        self.ae.extra_fields = test_data.extra_field_autofill
        self.ae.save()

        u = User.objects.get(id=self.uid_admin)
        u.save()
        u.userdata.metadata = {"mesa": "mesa 42"}
        u.userdata.save()

        c = JClient()
        c.authenticate(self.ae.pk, self.admin_auth_data)

        u = User.objects.get(id=self.uid)
        self.assertEqual(u.userdata.metadata.get("mesa"), None)

        data = {'user-ids': [self.uid], 'comment': 'some comment here'}
        response = c.post('/api/auth-event/%d/census/deactivate/' % self.aeid, data)
        self.assertEqual(response.status_code, 200)

        u = User.objects.get(id=self.uid)
        self.assertEqual(u.userdata.metadata.get("mesa"), "mesa 42")

    @override_settings(CELERY_EAGER_PROPAGATES_EXCEPTIONS=True,
                       CELERY_ALWAYS_EAGER=True,
                       BROKER_BACKEND='memory')
    def test_date_field(self):
        self.ae.extra_fields = test_data.extra_field_date
        self.ae.save()

        c = JClient()
        c.authenticate(self.ae.pk, self.admin_auth_data)
        response = c.census(self.ae.pk, test_data.census_date_field_ok)
        self.assertEqual(response.status_code, 200)

        response = c.get('/api/auth-event/%d/census/' % self.aeid, {})
        self.assertEqual(response.status_code, 200)
        r = json.loads(response.content.decode('utf-8'))
        self.assertEqual(len(r['object_list']), 5)

        response = c.census(self.ae.pk, test_data.census_date_field_nok)
        self.assertEqual(response.status_code, 400)


class TestRegisterAndAuthenticateEmail(TestCase):
    def setUpTestData():
        flush_db_load_fixture()

    def setUp(self):
        ae = AuthEvent(auth_method="email",
                auth_method_config=test_data.authmethod_config_email_default,
                status='started',
                census="open")
        ae.save()
        self.ae = ae
        self.aeid = ae.pk

        u_admin = User(username=test_data.admin['username'], email=test_data.admin['email'])
        u_admin.set_password(test_data.admin['password'])
        u_admin.save()
        u_admin.userdata.event = ae
        u_admin.userdata.save()
        self.uid_admin = u_admin.id

        acl = ACL(user=u_admin.userdata, object_type='AuthEvent', perm='edit',
            object_id=self.aeid)
        acl.save()

        u = User(username='test', email=test_data.auth_email_default['email'])
        u.save()
        u.userdata.event = ae
        u.userdata.save()
        self.u = u.userdata
        self.uid = u.id

        acl = ACL(user=u.userdata, object_type='AuthEvent', perm='edit',
            object_id=self.aeid)
        acl.save()

        c = Code(user=u.userdata, code=test_data.auth_email_default['code'], auth_event_id=ae.pk)
        c.save()
        self.code = c

    @override_settings(CELERY_ALWAYS_EAGER=True)
    def test_register_and_resend_code(self):
        c = JClient()
        response = c.register(self.aeid, test_data.register_email_default)
        self.assertEqual(response.status_code, 200)

        data = test_data.auth_email_default.copy()
        # bad: self.aeid.census = close
        self.ae.census = 'close'
        self.ae.save()
        response = c.post('/api/auth-event/%d/resend_auth_code/' % self.aeid, data)
        self.assertEqual(response.status_code, 400)
        r = parse_json_response(response)
        self.assertEqual(r['error_codename'], 'AUTH_EVENT_NOT_STARTED')

        # good: self.aeid.census = close but allow_user_resend = True
        self.ae.auth_method_config['config']['allow_user_resend'] = True
        self.ae.save()
        response = c.post('/api/auth-event/%d/resend_auth_code/' % self.aeid, data)
        r = parse_json_response(response)
        self.assertEqual(response.status_code, 200)

        # bad: self.aeid.census = open and status != started
        self.ae.auth_method_config['config']['allow_user_resend'] = False
        self.ae.census = 'open'
        self.ae.status = 'stopped'
        self.ae.save()
        response = c.post('/api/auth-event/%d/resend_auth_code/' % self.aeid, data)
        self.assertEqual(response.status_code, 400)
        r = parse_json_response(response)
        self.assertEqual(r['error_codename'], 'AUTH_EVENT_NOT_STARTED')

        # bad: invalid credentials
        self.ae.status = 'started'
        self.ae.save()
        response = c.post('/api/auth-event/%d/resend_auth_code/' % self.aeid, {})
        self.assertEqual(response.status_code, 400)
        r = parse_json_response(response)
        self.assertEqual(r['error_codename'], 'invalid_credentials')

        # bad: problem user inactive
        self.u.user.is_active = False
        self.u.user.save()
        response = c.post('/api/auth-event/%d/resend_auth_code/' % self.aeid, data)
        self.assertEqual(response.status_code, 400)
        r = parse_json_response(response)
        self.assertEqual(r['error_codename'], 'invalid_credentials')

        # good
        self.u.user.is_active = True
        self.u.user.save()
        response = c.authenticate(self.aeid, test_data.auth_email_default)
        self.assertEqual(response.status_code, 200)

        response = c.post('/api/auth-event/%d/resend_auth_code/' % self.aeid, data)
        r = parse_json_response(response)
        self.assertEqual(response.status_code, 200)

        # good
        self.ae.auth_method_config['config']['allow_user_resend'] = True
        response = c.post('/api/auth-event/%d/resend_auth_code/' % self.aeid, data)
        r = parse_json_response(response)
        self.assertEqual(response.status_code, 200)

    def test_add_census_authevent_email_default(self):
        c = JClient()
        c.authenticate(self.aeid, test_data.auth_email_default)
        response = c.census(self.aeid, test_data.census_email_default)
        self.assertEqual(response.status_code, 200)
        response = c.get('/api/auth-event/%d/census/' % self.aeid, {})
        self.assertEqual(response.status_code, 200)
        r = parse_json_response(response)
        self.assertEqual(len(r['object_list']), 4)

    def test_add_census_authevent_email_fields(self):
        c = JClient()
        c.authenticate(self.aeid, test_data.auth_email_default)
        response = c.census(self.aeid, test_data.census_email_fields)
        self.assertEqual(response.status_code, 200)

    def test_add_census_authevent_email_default_incorrect(self):
        c = JClient()
        c.authenticate(self.aeid, test_data.auth_email_default)
        response = c.census(self.aeid, test_data.census_sms_default)
        self.assertEqual(response.status_code, 400)
        response = c.census(self.aeid, test_data.census_sms_fields)
        self.assertEqual(response.status_code, 400)

    def test_add_census_authevent_email_fields_incorrect(self):
        c = JClient()
        c.authenticate(self.aeid, test_data.auth_email_default)
        response = c.census(self.aeid, test_data.census_sms_default)
        self.assertEqual(response.status_code, 400)
        response = c.census(self.aeid, test_data.census_sms_fields)
        self.assertEqual(response.status_code, 400)

    def test_add_census_authevent_email_repeat(self):
        c = JClient()
        c.authenticate(self.aeid, test_data.auth_email_default)
        response = c.census(self.aeid, test_data.census_email_repeat)
        self.assertEqual(response.status_code, 400)
        r = parse_json_response(response)
        self.assertEqual(r['error_codename'], 'invalid_credentials')

    def test_add_census_authevent_email_with_spaces(self):
        c = JClient()
        c.authenticate(self.aeid, test_data.auth_email_default)
        response = c.census(self.aeid, test_data.census_email_spaces)
        self.assertEqual(response.status_code, 200)

    def _test_add_used_census(self):
        c = JClient()
        c.authenticate(self.aeid, test_data.auth_email_default)

        census = ACL.objects.filter(perm="vote", object_type="AuthEvent",
                object_id=str(self.aeid))
        self.assertEqual(len(census), 0)

        response = c.census(self.aeid, test_data.census_email_default_used)
        self.assertEqual(response.status_code, 200)
        census = ACL.objects.filter(perm="vote", object_type="AuthEvent",
                object_id=str(self.aeid))
        self.assertEqual(len(census), 4)

        response = c.register(self.aeid, test_data.census_email_default_used['census'][1])
        self.assertEqual(response.status_code, 400)
        r = parse_json_response(response)
        self.assertEqual(r['error_codename'], 'invalid_credentials')
        census = ACL.objects.filter(perm="vote", object_type="AuthEvent",
                object_id=str(self.aeid))
        self.assertEqual(len(census), 4)

    @override_settings(CELERY_ALWAYS_EAGER=True)
    def test_add_register_authevent_email_default(self):
        c = JClient()
        response = c.register(self.aeid, test_data.register_email_default)
        self.assertEqual(response.status_code, 200)

    @override_settings(CELERY_ALWAYS_EAGER=True)
    def test_add_register_authevent_email_fields(self):
        c = JClient()
        response = c.register(self.aeid, test_data.register_email_fields)
        self.assertEqual(response.status_code, 200)

    def test_add_register_authevent_email_census_close_not_possible(self):
        self.ae.census = 'close'
        self.ae.save()
        c = JClient()
        response = c.register(self.aeid, test_data.register_email_fields)
        self.assertEqual(response.status_code, 400)
        r = parse_json_response(response)
        self.assertEqual(r['error_codename'], 'REGISTER_IS_DISABLED')

    def test_add_register_authevent_email_fields_incorrect(self):
        c = JClient()
        response = c.register(self.aeid, test_data.register_sms_default)
        self.assertEqual(response.status_code, 400)

    def _test_add_register_authevent_email_repeat(self):
        user = User.objects.get(email=test_data.auth_email_default['email'])
        Code.objects.filter(user=user.userdata).delete()
        user.delete()
        ini_codes = Code.objects.count()

        c = JClient()
        c.authenticate(self.aeid, test_data.auth_email_default)
        for i in range(settings.SEND_CODES_EMAIL_MAX):
            response = c.register(self.aeid, test_data.auth_email_default)
            self.assertEqual(response.status_code, 200)
        self.assertEqual(Code.objects.count() - ini_codes, settings.SEND_CODES_EMAIL_MAX)

        response = c.register(self.aeid, test_data.auth_email_default)
        self.assertEqual(response.status_code, 400)
        r = parse_json_response(response)
        self.assertTrue(r['message'].count("Maximun number of codes sent"))
        self.assertTrue(r['message'].count("Email %s repeat" % test_data.auth_email_default['email']))
        self.assertEqual(Code.objects.count() - ini_codes, settings.SEND_CODES_EMAIL_MAX)

    def test_authenticate_authevent_email_default(self):
        c = JClient()
        response = c.authenticate(self.aeid, test_data.auth_email_default)
        self.assertEqual(response.status_code, 200)

    def test_authenticate_authevent_email_invalid_code(self):
        data = test_data.auth_email_default
        data['code'] = '654321'
        c = JClient()
        response = c.authenticate(self.aeid, data)
        self.assertEqual(response.status_code, 400)
        r = parse_json_response(response)
        self.assertEqual(r['error_codename'], 'invalid_credentials')

    @override_settings(**override_celery_data)
    def test_authenticate_authevent_email_fields(self):
        c = JClient()
        self.u.metadata = {"name": test_data.auth_email_fields['name']}
        self.u.save()
        code = self.u.codes.last()
        code.code = test_data.auth_email_fields['code'].upper()
        code.save()
        response = c.authenticate(self.aeid, test_data.auth_email_fields)
        self.assertEqual(response.status_code, 200)

    @override_settings(**override_celery_data)
    def test_send_auth_email(self):
        self.test_add_census_authevent_email_default() # Add census
        correct_tpl = {"subject": "Vote", "msg": "this is an example __CODE__ and __URL__"}
        incorrect_tpl = {"msg": 10001*"a"}

        c = JClient()
        response = c.authenticate(self.aeid, test_data.auth_email_default)
        response = c.post('/api/auth-event/%d/census/send_auth/' % self.aeid, {})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(MsgLog.objects.count(), 4)
        msg_log = MsgLog.objects.all().last().msg
        self.assertEqual(msg_log.get('subject'), 'Confirm your email - nVotes')
        self.assertTrue(msg_log.get('msg').count(' -- nVotes https://nvotes.com'))

        response = c.post('/api/auth-event/%d/census/send_auth/' % self.aeid, correct_tpl)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(MsgLog.objects.count(), 4*2)
        msg_log = MsgLog.objects.all().last().msg
        self.assertEqual(msg_log.get('subject'), correct_tpl.get('subject') + ' - nVotes')
        self.assertTrue(msg_log.get('msg').count('this is an example'))

        response = c.post('/api/auth-event/%d/census/send_auth/' % self.aeid, incorrect_tpl)
        self.assertEqual(response.status_code, 400)

    @override_settings(**override_celery_data)
    def test_send_auth_email_url2_home_url(self):
        # Add census
        c = JClient()
        c.authenticate(self.aeid, test_data.auth_email_default)
        response = c.census(self.aeid, test_data.census_email_default1)
        self.assertEqual(response.status_code, 200)
        response = c.get('/api/auth-event/%d/census/' % self.aeid, {})
        self.assertEqual(response.status_code, 200)
        r = parse_json_response(response)
        self.assertEqual(len(r['object_list']), 1)

        correct_tpl = {
          "msg" : "Vote in __URL2__ with home page __HOME_URL__",
          "subject" : "Vote now with nVotes",
          "user-ids" : None,
          "auth-method" : "email"
        }
        incorrect_tpl = {"msg": 10001*"a"}

        response = c.authenticate(self.aeid, test_data.auth_email_default)
        response = c.post('/api/auth-event/%d/census/send_auth/' % self.aeid, correct_tpl)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(MsgLog.objects.count(), 1)
        msg_log = MsgLog.objects.all().last().msg
        self.assertEqual(msg_log.get('subject'), correct_tpl.get('subject') + ' - nVotes')
        self.assertEqual(1, msg_log.get('msg').count(' -- nVotes https://nvotes.com'))
        home_url =  settings.HOME_URL.replace("__EVENT_ID__", str(self.aeid))
        self.assertEqual(1, msg_log.get('msg').count(home_url))

    @override_settings(**override_celery_data)
    def test_send_auth_email_specific(self):
        tpl_specific = {"user-ids": [self.uid, self.uid_admin]}
        c = JClient()
        response = c.authenticate(self.aeid, test_data.auth_email_default)
        response = c.post('/api/auth-event/%d/census/send_auth/' % self.aeid, tpl_specific)
        self.assertEqual(response.status_code, 200)

    @override_settings(**override_celery_data)
    def test_send_auth_email_change_authevent_status(self):
        tpl_specific = {"user-ids": [self.uid, self.uid_admin]}
        c = JClient()
        ae = self.ae
        ae.status = 'stopped'
        ae.save()
        response = c.authenticate(self.aeid, test_data.auth_email_default)
        response = c.post('/api/auth-event/%d/census/send_auth/' % self.aeid, tpl_specific)
        self.assertEqual(response.status_code, 200)

        ae.status = 'notstarted'
        ae.save()
        response = c.authenticate(self.aeid, test_data.auth_email_default)
        response = c.post('/api/auth-event/%d/census/send_auth/' % self.aeid, tpl_specific)
        self.assertEqual(response.status_code, 200)

    def _test_unique_field(self):
        self.ae.extra_fields = test_data.extra_field_unique
        self.ae.save()

        c = JClient()
        c.authenticate(0, test_data.admin)
        response = c.census(self.aeid, test_data.census_email_unique_dni)
        self.assertEqual(response.status_code, 200)
        response = c.get('/api/auth-event/%d/census/' % self.aeid, {})
        self.assertEqual(response.status_code, 200)
        r = parse_json_response(response)
        self.assertEqual(len(r['object_list']), 2)

        ini_codes = Code.objects.count()
        user = {'dni': test_data.census_email_unique_dni['census'][1]['dni'], 'email': 'zzz@zzz.com'}
        for i in range(settings.SEND_CODES_EMAIL_MAX):
            response = c.register(self.aeid, user)
            self.assertEqual(response.status_code, 200)
            user['email'] = 'zzz%d@zzz.com' % i
        self.assertEqual(Code.objects.count() - ini_codes, settings.SEND_CODES_EMAIL_MAX)

        response = c.register(self.aeid, user)
        self.assertEqual(response.status_code, 400)
        r = parse_json_response(response)
        self.assertTrue(r['message'].count("Maximun number of codes sent"))
        self.assertTrue(r['message'].count("dni %s repeat." % user['dni']))

    @override_settings(**override_celery_data)
    def _test_add_census_no_validation(self):
        self.ae.extra_fields = test_data.extra_field_unique
        self.ae.save()

        c = JClient()
        c.authenticate(0, test_data.admin)
        c.authenticate(self.aeid, test_data.auth_email_default)
        response = c.get('/api/auth-event/%d/census/' % self.aeid, {})
        self.assertEqual(response.status_code, 200)
        r = parse_json_response(response)
        self.assertEqual(len(r['object_list']), 0)

        test_data.census_email_repeat['field-validation'] = 'disabled'
        response = c.census(self.aeid, test_data.census_email_repeat)
        self.assertEqual(response.status_code, 200)
        response = c.get('/api/auth-event/%d/census/' % self.aeid, {})
        self.assertEqual(response.status_code, 200)
        r = parse_json_response(response)
        self.assertEqual(len(r['object_list']), 1)

        response = c.census(self.aeid, test_data.census_email_no_validate)
        self.assertEqual(response.status_code, 200)
        response = c.get('/api/auth-event/%d/census/' % self.aeid, {})
        self.assertEqual(response.status_code, 200)
        r = parse_json_response(response)
        self.assertEqual(len(r['object_list']), 1 + 6)

        self.assertEqual(Code.objects.count(), 1)
        response = c.post('/api/auth-event/%d/census/send_auth/' % self.aeid, {})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(Code.objects.count(), 1 + 7 - 2)


class TestRegisterAndAuthenticateSMS(TestCase):
    def setUpTestData():
        flush_db_load_fixture()

    def setUp(self):
        ae = AuthEvent(auth_method="sms",
                auth_method_config=test_data.authmethod_config_sms_default,
                status='started',
                census="open")
        ae.save()
        self.ae = ae
        self.aeid = ae.pk

        u_admin = User(username=test_data.admin['username'], email=test_data.admin['email'])
        u_admin.set_password(test_data.admin['password'])
        u_admin.save()
        u_admin.userdata.event = ae
        u_admin.userdata.save()
        self.uid_admin = u_admin.id

        acl = ACL(user=u_admin.userdata, object_type='AuthEvent', perm='edit',
            object_id=self.aeid)
        acl.save()

        u = User()
        u.save()
        u.userdata.event = ae
        u.userdata.tlf = get_cannonical_tlf(test_data.auth_sms_default['tlf'])
        u.userdata.save()
        self.u = u.userdata
        self.uid = u.id

        acl = ACL(user=u.userdata, object_type='AuthEvent', perm='edit',
            object_id=self.aeid)
        acl.save()

        c = Code(user=u.userdata, code=test_data.auth_sms_default['code'], auth_event_id=ae.pk)
        c.save()
        self.code = c

    def test_add_census_authevent_sms_default(self):
        c = JClient()
        c.authenticate(self.aeid, test_data.auth_sms_default)
        response = c.census(self.aeid, test_data.census_sms_default)
        self.assertEqual(response.status_code, 200)

    def test_add_census_authevent_sms_fields(self):
        c = JClient()
        c.authenticate(self.aeid, test_data.auth_sms_default)
        response = c.census(self.aeid, test_data.census_sms_fields)
        self.assertEqual(response.status_code, 200)

    def _test_add_census_authevent_sms_repeat(self):
        c = JClient()
        c.authenticate(self.aeid, test_data.auth_sms_default)
        response = c.census(self.aeid, test_data.census_sms_repeat)
        self.assertEqual(response.status_code, 400)
        r = parse_json_response(response)
        self.assertEqual(r['error_codename'], 'invalid_credentials')

    def _test_add_used_census(self):
        c = JClient()
        c.authenticate(0, test_data.admin)
        response = c.census(self.aeid, test_data.census_sms_default_used)
        self.assertEqual(response.status_code, 200)

        response = c.get('/api/auth-event/%d/census/' % self.aeid, {})
        self.assertEqual(response.status_code, 200)
        r = parse_json_response(response)
        self.assertEqual(len(r['object_list']), 4)

        response = c.register(self.aeid, test_data.census_sms_default_used['census'][1])
        self.assertEqual(response.status_code, 400)
        r = parse_json_response(response)
        self.assertEqual(r['message'], 'Incorrect data')

        c = JClient()
        c.authenticate(0, test_data.admin)
        codes = Code.objects.count()
        response = c.post('/api/auth-event/%d/census/send_auth/' % self.aeid, {})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(Code.objects.count(), codes)

    @override_settings(CELERY_ALWAYS_EAGER=True)
    def test_add_register_authevent_sms_default(self):
        c = JClient()
        response = c.register(self.aeid, test_data.register_sms_default)
        self.assertEqual(response.status_code, 200)

    @override_settings(CELERY_ALWAYS_EAGER=True)
    def test_add_register_authevent_sms_fields(self):
        c = JClient()
        self.ae.extra_fields = test_data.ae_sms_fields['extra_fields']
        self.ae.save()
        self.u.metadata = {"name": test_data.auth_sms_fields['name']}
        self.u.save()
        response = c.register(self.aeid, test_data.register_sms_fields)
        self.assertEqual(response.status_code, 200)

    @override_settings(CELERY_ALWAYS_EAGER=True)
    def test_register_and_resend_code(self):
        c = JClient()
        response = c.register(self.aeid, test_data.register_sms_default)
        self.assertEqual(response.status_code, 200)

        data = test_data.auth_sms_default.copy()
        # bad: self.aeid.census = close
        self.ae.census = 'close'
        self.ae.save()
        response = c.post('/api/auth-event/%d/resend_auth_code/' % self.aeid, data)
        self.assertEqual(response.status_code, 400)
        r = parse_json_response(response)
        self.assertEqual(r['error_codename'], 'AUTH_EVENT_NOT_STARTED')

        # good: self.aeid.census = close but allow_user_resend = True
        self.ae.auth_method_config['config']['allow_user_resend'] = True
        self.ae.save()
        response = c.post('/api/auth-event/%d/resend_auth_code/' % self.aeid, data)
        r = parse_json_response(response)
        self.assertEqual(response.status_code, 200)

        # bad: self.aeid.census = open and status != started
        self.ae.auth_method_config['config']['allow_user_resend'] = False
        self.ae.census = 'open'
        self.ae.status = 'stopped'
        self.ae.save()
        response = c.post('/api/auth-event/%d/resend_auth_code/' % self.aeid, data)
        self.assertEqual(response.status_code, 400)
        r = parse_json_response(response)
        self.assertEqual(r['error_codename'], 'AUTH_EVENT_NOT_STARTED')

        # bad: invalid credentials
        self.ae.status = 'started'
        self.ae.save()
        response = c.post('/api/auth-event/%d/resend_auth_code/' % self.aeid, {})
        self.assertEqual(response.status_code, 400)
        r = parse_json_response(response)
        self.assertEqual(r['error_codename'], 'invalid_credentials')

        # bad: problem user inactive
        self.u.user.is_active = False
        self.u.user.save()
        response = c.post('/api/auth-event/%d/resend_auth_code/' % self.aeid, data)
        self.assertEqual(response.status_code, 400)
        r = parse_json_response(response)
        self.assertEqual(r['error_codename'], 'invalid_credentials')

        # good
        self.u.user.is_active = True
        self.u.user.save()
        response = c.authenticate(self.aeid, test_data.auth_sms_default)
        self.assertEqual(response.status_code, 200)

        response = c.post('/api/auth-event/%d/resend_auth_code/' % self.aeid, data)
        r = parse_json_response(response)
        self.assertEqual(response.status_code, 200)

        # good
        self.ae.auth_method_config['config']['allow_user_resend'] = True
        response = c.post('/api/auth-event/%d/resend_auth_code/' % self.aeid, data)
        r = parse_json_response(response)
        self.assertEqual(response.status_code, 200)


    def test_add_authevent_sms_fields_incorrect(self):
        c = JClient()
        self.ae.extra_fields = test_data.auth_event2['extra_fields']
        self.ae.save()
        self.u.metadata = {"name": test_data.auth_sms_fields['name']}
        self.u.save()
        response = c.register(self.aeid, test_data.sms_fields_incorrect_type1)
        self.assertEqual(response.status_code, 400)
        response = c.register(self.aeid, test_data.sms_fields_incorrect_type2)
        self.assertEqual(response.status_code, 400)
        response = c.register(self.aeid, test_data.sms_fields_incorrect_len1)
        self.assertEqual(response.status_code, 400)
        response = c.register(self.aeid, test_data.sms_fields_incorrect_len2)
        self.assertEqual(response.status_code, 400)

    @override_settings(**override_celery_data)
    def _test_add_register_authevent_sms_resend(self):
        c = JClient()
        c.authenticate(0, test_data.admin)
        ini_codes = Code.objects.count()
        data = {
                "tlf": "333333333",
                "code": "123456"
        }
        for i in range(settings.SEND_CODES_SMS_MAX):
            response = c.register(self.aeid, data)
            self.assertEqual(response.status_code, 200)
        self.assertEqual(Code.objects.count() - ini_codes, settings.SEND_CODES_SMS_MAX)

        response = c.register(self.aeid, data)
        self.assertEqual(response.status_code, 400)
        r = parse_json_response(response)
        self.assertTrue(r['message'].count("Maximun number of codes sent"))
        self.assertEqual(Code.objects.count() - ini_codes, settings.SEND_CODES_SMS_MAX)

    @override_settings(**override_celery_data)
    def test_add_register_authevent_sms_same_cannonical_number(self):
        data = {
            "tlf": "666666667",
            "code": "123456"
        }

        c = JClient()
        response = c.register(self.aeid, data)
        self.assertEqual(response.status_code, 200)

        data['tlf'] = "0034666666667"
        response = c.register(self.aeid, data)
        self.assertEqual(response.status_code, 400)
        r = parse_json_response(response)
        self.assertEqual(r['error_codename'], 'invalid_credentials')

        data['tlf'] = "+34666666667"
        response = c.register(self.aeid, data)
        self.assertEqual(response.status_code, 400)
        r = parse_json_response(response)
        self.assertEqual(r['error_codename'], 'invalid_credentials')

    def test_authenticate_authevent_sms_default(self):
        c = JClient()
        response = c.authenticate(self.aeid, test_data.auth_sms_default)
        self.assertEqual(response.status_code, 200)
        r = parse_json_response(response)
        self.assertTrue(r['auth-token'].startswith('khmac:///sha-256'))

    def test_authenticate_authevent_sms_invalid_code(self):
        data = test_data.auth_sms_default
        data['code'] = '654321'
        c = JClient()
        response = c.authenticate(self.aeid, data)
        self.assertEqual(response.status_code, 400)
        r = parse_json_response(response)
        self.assertEqual(r['error_codename'], 'invalid_credentials')

    def _test_authenticate_authevent_sms_fields(self):
        c = JClient()
        self.ae.extra_fields = test_data.ae_sms_fields['extra_fields']
        self.ae.save()
        self.u.metadata = {"name": test_data.auth_sms_fields['name']}
        self.u.save()
        response = c.authenticate(self.aeid, test_data.auth_sms_fields)
        self.assertEqual(response.status_code, 200)
        r = parse_json_response(response)
        self.assertTrue(r['auth-token'].startswith('khmac:///sha-256'))

    @override_settings(**override_celery_data)
    def test_send_auth_sms(self):
        self.test_add_census_authevent_sms_default() # Add census

        correct_tpl = {"msg": "this is an example __CODE__ and __URL__"}
        incorrect_tpl = {"msg": 121*"a"}

        c = JClient()
        response = c.authenticate(self.aeid, test_data.auth_sms_default)
        response = c.post('/api/auth-event/%d/census/send_auth/' % self.aeid, {})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(MsgLog.objects.count(), 4)
        msg_log = MsgLog.objects.all().last().msg
        self.assertTrue(msg_log.get('msg').count('-- nVotes'))

        response = c.post('/api/auth-event/%d/census/send_auth/' % self.aeid, correct_tpl)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(MsgLog.objects.count(), 4*2)
        msg_log = MsgLog.objects.all().last().msg
        self.assertTrue(msg_log.get('msg').count('this is an example'))

        response = c.post('/api/auth-event/%d/census/send_auth/' % self.aeid, incorrect_tpl)
        self.assertEqual(response.status_code, 400)

    @override_settings(**override_celery_data)
    def test_send_auth_sms_specific(self):
        tpl_specific = {"user-ids": [self.uid, self.uid_admin]}
        c = JClient()
        response = c.authenticate(self.aeid, test_data.auth_sms_default)
        response = c.post('/api/auth-event/%d/census/send_auth/' % self.aeid, tpl_specific)
        self.assertEqual(response.status_code, 200)


    def _test_unique_field(self):
        self.ae.extra_fields = test_data.extra_field_unique
        self.ae.save()

        c = JClient()
        c.authenticate(0, test_data.admin)
        response = c.census(self.aeid, test_data.census_sms_unique_dni)
        self.assertEqual(response.status_code, 200)
        response = c.get('/api/auth-event/%d/census/?validate' % self.aeid, {})
        self.assertEqual(response.status_code, 200)
        r = parse_json_response(response)
        self.assertEqual(len(r['object_list']), 2)

        ini_codes = Code.objects.count()

        self.assertEqual(Code.objects.count(), 1)
        user = {'dni': test_data.census_sms_unique_dni['census'][1]['dni'], 'tlf': '123123123'}
        for i in range(settings.SEND_CODES_EMAIL_MAX):
            response = c.register(self.aeid, user)
            self.assertEqual(response.status_code, 200)
            user['tlf'] = '12345789%d' % i
        self.assertEqual(Code.objects.count() - ini_codes, settings.SEND_CODES_EMAIL_MAX)

        response = c.register(self.aeid, user)
        self.assertEqual(response.status_code, 400)
        r = parse_json_response(response)
        self.assertTrue(r['message'].count("Maximun number of codes sent"))


    @override_settings(**override_celery_data)
    def _test_add_census_no_validation(self):
        self.ae.extra_fields = test_data.extra_field_unique
        self.ae.save()

        c = JClient()
        c.authenticate(0, test_data.admin)
        response = c.get('/api/auth-event/%d/census/' % self.aeid, {})
        self.assertEqual(response.status_code, 200)
        r = parse_json_response(response)
        self.assertEqual(len(r['object_list']), 0)

        test_data.census_sms_repeat['field-validation'] = 'disabled'
        response = c.census(self.aeid, test_data.census_sms_repeat)
        self.assertEqual(response.status_code, 200)
        response = c.get('/api/auth-event/%d/census/' % self.aeid, {})
        self.assertEqual(response.status_code, 200)
        r = parse_json_response(response)
        self.assertEqual(len(r['object_list']), 1)

        response = c.census(self.aeid, test_data.census_sms_no_validate)
        self.assertEqual(response.status_code, 200)
        response = c.get('/api/auth-event/%d/census/' % self.aeid, {})
        self.assertEqual(response.status_code, 200)
        r = parse_json_response(response)
        self.assertEqual(len(r['object_list']), 1 + 4)

        self.assertEqual(Code.objects.count(), 1)
        response = c.post('/api/auth-event/%d/census/send_auth/' % self.aeid, {})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(Code.objects.count(), 1 + 5 - 2)


class TestSmallCensusSearch(TestCase):
    def setUpTestData():
        flush_db_load_fixture()

    def setUp(self):
        from authmethods.m_email import Email
        auth_method_config = {
                "config": Email.CONFIG,
                "pipeline": Email.PIPELINES
        }
        ae = AuthEvent(auth_method=test_data.auth_event9['auth_method'],
                auth_method_config=auth_method_config,
                extra_fields=test_data.auth_event9['extra_fields'],
                status='started', census=test_data.auth_event9['census'])
        ae.save()
        self.ae = ae
        self.aeid = ae.pk

        u_admin = User(username=test_data.admin['username'], email=test_data.admin['email'])
        u_admin.set_password(test_data.admin['password'])
        u_admin.save()
        u_admin.userdata.event = ae
        u_admin.userdata.save()
        self.uid_admin = u_admin.id

        acl = ACL(user=u_admin.userdata, object_type='AuthEvent', perm='edit',
            object_id=self.aeid)
        acl.save()

        u = User(username='test', email=test_data.auth_email_default['email'])
        u.save()
        u.userdata.event = ae
        u.userdata.metadata = {
                'email_verified': True,
                'match_field': 'match_code_555'
        }
        u.userdata.save()
        self.u = u.userdata
        self.uid = u.id

        acl = ACL(user=u.userdata, object_type='AuthEvent', perm='edit',
            object_id=self.aeid)
        acl.save()

        c = Code(user=u.userdata, code=test_data.auth_email_default['code'], auth_event_id=ae.pk)
        c.save()
        self.code = c

    def test_add_census_search_filter(self):
        c = JClient()
        res_auth = c.authenticate(self.aeid, test_data.auth_email_default)
        response = c.census(self.aeid, test_data.census_email_auth9)
        self.assertEqual(response.status_code, 200)
        response = c.get('/api/auth-event/%d/census/' % self.aeid, {"filter": "ma1"})
        self.assertEqual(response.status_code, 200)
        r = parse_json_response(response)
        self.assertEqual(len(r['object_list']), 1)
        self.assertEqual(r['object_list'][0]["metadata"]["email"], "baaa@aaa.com")

        response = c.get('/api/auth-event/%d/census/' % self.aeid, {"filter": "aaa@aaa.com"})
        self.assertEqual(response.status_code, 200)
        r = parse_json_response(response)
        self.assertEqual(len(r['object_list']), 4)

        response = c.get('/api/auth-event/%d/census/' % self.aeid, {"filter": "aaa@aaa.com"})
        self.assertEqual(response.status_code, 200)
        r = parse_json_response(response)
        self.assertEqual(len(r['object_list']), 4)

        response = c.get('/api/auth-event/%d/census/' % self.aeid, {"filter": "mc"})
        self.assertEqual(response.status_code, 200)
        r = parse_json_response(response)
        self.assertEqual(len(r['object_list']), 2)
        remaillist = [ r['object_list'][0]["metadata"]["email"],
                       r['object_list'][1]["metadata"]["email"] ]
        self.assertTrue("eaaa@aaa.com" in remaillist and "daaa@aaa.com" in remaillist)

        response = c.get('/api/auth-event/%d/census/' % self.aeid, {"filter": "md"})
        self.assertEqual(response.status_code, 200)
        r = parse_json_response(response)
        self.assertEqual(len(r['object_list']), 0)

# Check that the extra field data registers can be included in the messages
# sent to the users.
class TestSlugMessages(TestCase):
    def setUpTestData():
        flush_db_load_fixture()

    def setUp(self):
        from authmethods.m_email import Email
        auth_method_config = {
                "config": Email.CONFIG,
                "pipeline": Email.PIPELINES
        }
        ae = AuthEvent(auth_method=test_data.auth_event12['auth_method'],
                auth_method_config=auth_method_config,
                extra_fields=test_data.auth_event12['extra_fields'],
                status='started', census=test_data.auth_event12['census'])
        ae.save()
        self.ae = ae
        self.aeid = ae.pk

        u_admin = User(username=test_data.admin['username'], email=test_data.admin['email'])
        u_admin.set_password(test_data.admin['password'])
        u_admin.save()
        u_admin.userdata.event = ae
        u_admin.userdata.save()
        self.uid_admin = u_admin.id

        acl = ACL(user=u_admin.userdata, object_type='AuthEvent', perm='edit',
            object_id=self.aeid)
        acl.save()

        u = User(username='test', email=test_data.auth_email_default['email'])
        u.save()
        u.userdata.event = ae
        u.userdata.metadata = {
                'email_verified': True,
                'nº de _socio 你好': 'socio 342'
        }
        u.userdata.save()
        self.u = u.userdata
        self.uid = u.id

        acl = ACL(user=u.userdata, object_type='AuthEvent', perm='edit',
            object_id=self.aeid)
        acl.save()

        c = Code(user=u.userdata, code=test_data.auth_email_default['code'], auth_event_id=ae.pk)
        c.save()
        self.code = c

        acl = ACL(user=u.userdata, object_type='AuthEvent', perm='create', object_id=0)
        acl.save()

    @override_settings(**override_celery_data)
    def test_send_auth_email_slug(self):
        c = JClient()
        res_auth = c.authenticate(self.aeid, test_data.auth_email_default)
        response = c.census(self.aeid, test_data.census_email12)
        self.assertEqual(response.status_code, 200)
        response = c.get('/api/auth-event/%d/census/' % self.aeid, {})
        self.assertEqual(response.status_code, 200)
        r = parse_json_response(response)
        self.assertEqual(len(r['object_list']), 1)

        template_email = {"subject": "Vote", "msg": "Vote in __URL__ with code __CODE__ extra __NO_DE__SOCIO__"}
        response = c.post('/api/auth-event/%d/census/send_auth/' % self.aeid, template_email)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(MsgLog.objects.count(), 1)
        self.assertTrue("extra socio 119" in MsgLog.objects.all()[0].msg['msg'])

    def test_create_event_slug_name(self):

        c = JClient()
        res_auth = c.authenticate(self.aeid, test_data.auth_email_default)

        data = test_data.auth_event13
        response = c.post('/api/auth-event/', data)
        self.assertEqual(response.status_code, 200)
        r = parse_json_response(response)
        self.assertTrue('id' in  r and isinstance(r['id'], int))
        auth_id = r['id']
        response = c.get('/api/auth-event/%d/' % auth_id, data)
        r = parse_json_response(response)
        self.assertTrue('events' in r and 'extra_fields' in r['events'])
        self.assertEqual(1, len(r['events']['extra_fields']))
        self.assertTrue('slug' in r['events']['extra_fields'][0])
        self.assertEqual("NO_DE__SOCIO", r['events']['extra_fields'][0]['slug'])


class TestUserExtra(TestCase):
    def setUpTestData():
        flush_db_load_fixture()

    def setUp(self):
        from authmethods.m_email import Email
        auth_method_config = {
                "config": Email.CONFIG,
                "pipeline": Email.PIPELINES
        }
        self.admin_aeid = settings.ADMIN_AUTH_ID
        self.admin_ae = AuthEvent.objects.get(pk=self.admin_aeid)
        self.admin_ae.extra_fields = test_data.extra_fields16
        self.admin_ae.save()

        ae = AuthEvent(auth_method=test_data.auth_event12['auth_method'],
                auth_method_config=auth_method_config,
                extra_fields=test_data.auth_event12['extra_fields'],
                status='started', census=test_data.auth_event12['census'])
        ae.save()
        self.ae = ae
        self.aeid = ae.pk

        u_admin = User(username=test_data.admin['username'], email=test_data.admin['email'])
        u_admin.set_password(test_data.admin['password'])
        u_admin.save()
        u_admin.userdata.event = ae
        u_admin.userdata.save()
        self.uid_admin = u_admin.id

        acl = ACL(user=u_admin.userdata, object_type='AuthEvent', perm='edit',
            object_id=self.aeid)
        acl.save()

        u = User(username='test', email=test_data.auth_email_default['email'])
        u.save()
        u.userdata.event = ae
        u.userdata.metadata = test_data.userdata_metadata16
        u.userdata.save()
        self.u = u.userdata
        self.uid = u.id

        acl = ACL(user=u.userdata, object_type='AuthEvent', perm='view',
            object_id=self.admin_aeid)
        acl.save()

        acl = ACL(user=u.userdata, object_type='AuthEvent', perm='edit',
            object_id=self.aeid)
        acl.save()
        acl = ACL(user=u.userdata, object_type='UserData', perm='edit',
            object_id=self.uid)
        acl.save()

        c = Code(user=u.userdata, code=test_data.auth_email_default['code'], auth_event_id=ae.pk)
        c.save()
        self.code = c

        acl = ACL(user=u.userdata, object_type='AuthEvent', perm='create', object_id=0)
        acl.save()

    @override_settings(**override_celery_data)
    def test_user_extra_get(self):
        c = JClient()
        res_auth = c.authenticate(self.aeid, test_data.auth_email_default)
        response = c.census(self.aeid, test_data.census_email12)
        self.assertEqual(response.status_code, 200)
        response = c.get('/api/user/extra/', {})
        self.assertEqual(response.status_code, 200)
        r = parse_json_response(response)
        self.assertEqual(r['metadata'], test_data.userdata_metadata16)

    @override_settings(**override_celery_data)
    def test_user_extra_post(self):
        c = JClient()
        res_auth = c.authenticate(self.aeid, test_data.auth_email_default)
        response = c.census(self.aeid, test_data.census_email12)
        self.assertEqual(response.status_code, 200)
        meta_changes = {
           'dni': '123X'
        }
        response = c.post('/api/user/extra/', meta_changes)
        self.assertEqual(response.status_code, 200)
        meta_changes2 = {
           'other': '123X'
        }
        response = c.post('/api/user/extra/', meta_changes2)
        self.assertEqual(response.status_code, 400)
        response = c.get('/api/user/extra/', {})
        self.assertEqual(response.status_code, 200)
        r = parse_json_response(response)
        self.assertEqual(r['metadata']['dni'], meta_changes['dni'])
        self.assertEqual(r['metadata']['company name'], test_data.userdata_metadata16['company name'])


class TestCallback(TestCase):
    def setUpTestData():
        flush_db_load_fixture()

    def setUp(self):
        ae = AuthEvent(auth_method="email",
                auth_method_config=test_data.authmethod_config_email_default,
                status='started',
                census="open")
        ae.save()
        self.ae = ae
        self.aeid = ae.pk

        u = User(username='test', email=test_data.auth_email_default['email'])
        u.save()
        u.userdata.event = ae
        u.userdata.save()
        self.u = u.userdata
        self.uid = u.id

    def genhmac(self, key, msg):
        import hmac
        import datetime

        if not key or not msg:
           return

        timestamp = int(datetime.datetime.now().timestamp())
        msg = "%s:%s" % (msg, str(timestamp))

        h = hmac.new(key, msg.encode('utf-8'), "sha256")
        return 'khmac:///sha-256;' + h.hexdigest() + '/' + msg

    @override_settings(**override_celery_data)
    def test_callback(self):
        c = JClient()
        timed_auth = "test:AuthEvent:%d:Callback" % self.aeid
        hmac = self.genhmac(settings.SHARED_SECRET, timed_auth)
        c.set_auth_token(hmac)
        response = c.post('/api/auth-event/%d/callback/' % self.aeid, {})
        self.assertEqual(response.status_code, 200)
        # check the action was created
        action = Action.objects.get(executer__id=self.uid)
        self.assertEqual(action.action_name, "authevent:callback")

        c.authenticate(self.aeid, test_data.auth_email_default)
        response = c.post('/api/auth-event/%d/callback/' % self.aeid, {})
        self.assertEqual(response.status_code, 403)


class TestCsvStats(TestCase):
    def setUpTestData():
        flush_db_load_fixture()

    def setUp(self):
        from datetime import datetime, timedelta

        ae = AuthEvent(auth_method="email",
                auth_method_config=test_data.authmethod_config_email_default,
                status='started',
                census="open")
        ae.save()
        self.ae = ae
        self.aeid = ae.pk

        # convenience methods to create users and vote data

        def newUser(name):
            u = User(username=name, email=test_data.auth_email_default['email'])
            u.save()
            u.userdata.event = ae
            u.userdata.save()
            return u

        def newAction(user, date):
            action = Action(
                created=date,
                executer=user,
                receiver=user,
                action_name="authevent:callback",
                event=ae)
            action.save()
            return action

        # Create the data from which to run the query
        # the expected result is defined below the data, then used in an
        # assert in the test_csv_stats function

        # use a fixed date to get a fixed result
        date = datetime(2010, 10, 10, 0, 30, 30, 0, None)

        # some of the users will cast two votes, so we save these users here
        # we will also use the first user for hmac authorization
        self.users=[]

        # these votes will be overwritten later
        # the first hour slice will therefore have 0 votes
        for i in range(0, 4):
            user = newUser("user%s" % i)
            newAction(user, date)
            self.users.append(user)

        # in the second hour we have 3 votes
        date = date + timedelta(hours=1)
        for i in range(4, 7):
            user = newUser("user%s" % i)
            newAction(user, date)

        # here we cast votes for the same users as in the first hour,
        # effectively invalidating them
        # the third hour slice will therefore have 4 votes
        date = date + timedelta(hours=1)
        for i in range(0, 4):
            newAction(self.users[i], date)

        # in the third hour we have 5 votes
        date = date + timedelta(hours=1)
        for i in range(7, 12):
            user = newUser("user%s" % i)
            newAction(user, date)

        # the expected result as a csv string
        # corresponds to 0 votes in first hour (no data)
        # 3 votes in second hour
        # 4 votes in third hour
        # 5 votes in fourth hour
        self.expected = b"2010-10-10 01:00:00+00:00,3\n2010-10-10 02:00:00+00:00,4\n2010-10-10 03:00:00+00:00,5"

    def genhmac(self, key, msg):
        import hmac
        import datetime

        if not key or not msg:
           return

        timestamp = int(datetime.datetime.now().timestamp())
        msg = "%s:%s" % (msg, str(timestamp))

        h = hmac.new(key, msg.encode('utf-8'), "sha256")
        return 'khmac:///sha-256;' + h.hexdigest() + '/' + msg

    @override_settings(**override_celery_data)
    def test_csv_stats(self):
        c = JClient()
        timed_auth = "%s:AuthEvent:%d:CsvStats" % (self.users[0].username, self.aeid)
        hmac = self.genhmac(settings.SHARED_SECRET, timed_auth)
        c.set_auth_token(hmac)

        response = c.get('/api/auth-event/%d/csv-stats/' % self.aeid, {})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.content, self.expected)

# Check the allowed number of revotes, using AuthEvent's
# num_successful_logins_allowed field and calls to successful_login
class TestRevotes(TestCase):
    def setUpTestData():
        flush_db_load_fixture()

    def genhmac(self, key, msg):
        import hmac
        import datetime
        timestamp = int(datetime.datetime.now().timestamp())
        msg = "%s:%s" % (msg, str(timestamp))

        h = hmac.new(key, msg.encode('utf-8'), "sha256")
        return 'khmac:///sha-256;' + h.hexdigest() + '/' + msg

    def setUp(self):
        ae = AuthEvent(auth_method="email",
                auth_method_config=test_data.authmethod_config_email_default,
                status='started',
                census="open",
                num_successful_logins_allowed = 0)
        ae.save()
        self.ae = ae
        self.aeid = ae.pk

        u_admin = User(username=test_data.admin['username'], email=test_data.admin['email'])
        u_admin.set_password(test_data.admin['password'])
        u_admin.save()
        u_admin.userdata.event = ae
        u_admin.userdata.save()
        self.uid_admin = u_admin.id

        acl = ACL(user=u_admin.userdata, object_type='AuthEvent', perm='edit',
            object_id=self.aeid)
        acl.save()

        u = User(username='test', email=test_data.auth_email_default['email'])
        u.save()
        u.userdata.event = ae
        u.userdata.save()
        self.u = u.userdata
        self.uid = u.id

        acl = ACL(user=u.userdata, object_type='AuthEvent', perm='edit',
            object_id=self.aeid)
        acl.save()

        c = Code(user=u.userdata, code=test_data.auth_email_default['code'], auth_event_id=ae.pk)
        c.save()
        self.code = c

    def test_check_1_2_revotes(self):
        c = JClient()
        c.authenticate(self.aeid, test_data.auth_email_default)
        response = c.census(self.aeid, test_data.census_email_default1)
        self.assertEqual(response.status_code, 200)
        response = c.get('/api/auth-event/%d/census/' % self.aeid, {})
        self.assertEqual(response.status_code, 200)
        r = parse_json_response(response)
        self.assertEqual(len(r['object_list']), 1)
        cuid = r['object_list'][0]['id']
        cuser = User.objects.get(id=cuid)
        code = Code(user=cuser.userdata, code=test_data.auth_email_default1['code'], auth_event_id=self.aeid)
        code.save()

        # allow 1 vote
        self.ae.num_successful_logins_allowed = 1
        self.ae.save()
        response = c.authenticate(self.aeid, test_data.auth_email_default1)
        self.assertEqual(response.status_code, 200)
        response = c.authenticate(self.aeid, test_data.auth_email_default1)
        self.assertEqual(response.status_code, 200)
        response = c.authenticate(self.aeid, test_data.auth_email_default1)
        self.assertEqual(response.status_code, 200)
        auth_token = self.genhmac(settings.SHARED_SECRET, "%s:AuthEvent:%d:RegisterSuccessfulLogin" % (cuser.username, self.aeid))
        c.set_auth_token(auth_token)
        response = c.post('/api/auth-event/%d/successful_login/%s' % (self.aeid, cuser.username), {})
        self.assertEqual(response.status_code, 200)
        response = c.authenticate(self.aeid, test_data.auth_email_default1)
        self.assertEqual(response.status_code, 400)
        response = c.authenticate(self.aeid, test_data.auth_email_default1)
        self.assertEqual(response.status_code, 400)

        # allow 2 votes
        self.ae.num_successful_logins_allowed = 2
        self.ae.save()
        response = c.authenticate(self.aeid, test_data.auth_email_default1)
        self.assertEqual(response.status_code, 200)
        response = c.authenticate(self.aeid, test_data.auth_email_default1)
        self.assertEqual(response.status_code, 200)
        auth_token = self.genhmac(settings.SHARED_SECRET, "%s:AuthEvent:%d:RegisterSuccessfulLogin" % (cuser.username, self.aeid))
        c.set_auth_token(auth_token)
        response = c.post('/api/auth-event/%d/successful_login/%s' % (self.aeid, cuser.username), {})
        self.assertEqual(response.status_code, 200)
        response = c.authenticate(self.aeid, test_data.auth_email_default1)
        self.assertEqual(response.status_code, 400)

    def test_check_50_revotes_max(self):
        c = JClient()
        c.authenticate(self.aeid, test_data.auth_email_default)
        response = c.census(self.aeid, test_data.census_email_default1)
        self.assertEqual(response.status_code, 200)
        response = c.get('/api/auth-event/%d/census/' % self.aeid, {})
        self.assertEqual(response.status_code, 200)
        r = parse_json_response(response)
        self.assertEqual(len(r['object_list']), 1)
        cuid = r['object_list'][0]['id']
        cuser = User.objects.get(id=cuid)
        code = Code(user=cuser.userdata, code=test_data.auth_email_default1['code'], auth_event_id=self.aeid)
        code.save()
        # allow 50 votes
        self.ae.num_successful_logins_allowed = 50
        self.ae.save()

        # vote 50 times
        for i in range(0, 50):
            response = c.authenticate(self.aeid, test_data.auth_email_default1)
            self.assertEqual(response.status_code, 200)
            auth_token = self.genhmac(settings.SHARED_SECRET, "%s:AuthEvent:%d:RegisterSuccessfulLogin" % (cuser.username, self.aeid))
            c.set_auth_token(auth_token)
            response = c.post('/api/auth-event/%d/successful_login/%s' % (self.aeid, cuser.username), {})

        response = c.authenticate(self.aeid, test_data.auth_email_default1)
        self.assertEqual(response.status_code, 400)

class TestAdminFields(TestCase):
    def setUpTestData():
        flush_db_load_fixture()

    def setUp(self):
        self.ae = AuthEvent(auth_method=test_data.auth_event4['auth_method'],
                auth_method_config=test_data.authmethod_config_email_default)
        self.ae.save()

        u = User(username=test_data.admin['username'], email=test_data.admin['email'])
        u.set_password(test_data.admin['password'])
        u.save()
        u.userdata.event = self.ae
        u.userdata.save()
        self.user = u

        u2 = User(username='noperm', email="noperm@agoravoting.com")
        u2.set_password("qwerty")
        u2.save()
        u2.userdata.save()

        self.aeid_special = 1


    @override_settings(**override_celery_data)
    def create_authevent(self, authevent):
        c = JClient()
        c.authenticate(self.ae.pk, test_data.admin)
        return c.post('/api/auth-event/', authevent)

    @override_settings(**override_celery_data)
    def test_create_authevent_admin_and_extra_fields(self):
        acl = ACL(user=self.user.userdata, object_type='AuthEvent', perm='create',
                object_id=0)
        acl.save()
        # test 1
        response = self.create_authevent(test_data.auth_event14)
        self.assertEqual(response.status_code, 200)

    @override_settings(**override_celery_data)
    def test_create_authevent_repeated_admin_fields(self):
        acl = ACL(user=self.user.userdata, object_type='AuthEvent', perm='create',
                object_id=0)
        acl.save()
        # test 1
        response = self.create_authevent(test_data.auth_event15)
        self.assertEqual(response.status_code, 400)

class TestAdminDeregister(TestCase):
    def setUpTestData():
        flush_db_load_fixture()

    def setUp(self):
        self.aeid_special = 1

    @override_settings(**override_celery_data)
    def test_deregister_email(self):
        data = {"email": "asd@asd.com", "captcha": "asdasd"}
        c = JClient()

        # Register
        response = c.register(self.aeid_special, data)
        self.assertEqual(response.status_code, 200)
        user = User.objects.get(email=data['email'])
        self.assertEqual(user.is_active, True)

        # re-registration is not possible
        response = c.register(self.aeid_special, data)
        self.assertEqual(response.status_code, 400)

        # authenticate
        code = Code.objects.get(user=user.userdata)
        data['code'] = code.code
        response = c.authenticate(self.aeid_special, data)
        self.assertEqual(response.status_code, 200)

        # deregister
        response = c.post('/api/user/deregister/', {})
        self.assertEqual(response.status_code, 200)

        # check deregistration effects

        # is_active is false
        user = User.objects.get(email=data['email'])
        self.assertEqual(user.is_active, False)

        # authentication gives error
        self.assertEqual(user.is_active, False)

        # authenticate gives error
        code = Code.objects.get(user=user.userdata)
        data['code'] = code.code
        response = c.authenticate(self.aeid_special, data)
        self.assertEqual(response.status_code, 400)

        # re-registration is enabled
        Code.objects.filter(user=user.userdata).delete()
        data = {"email": "asd@asd.com", "captcha": "asdasd"}
        response = c.register(self.aeid_special, data)
        self.assertEqual(response.status_code, 200)
        user = User.objects.get(email=data['email'])
        self.assertEqual(user.is_active, True)

        # authentication works
        code = Code.objects.get(user=user.userdata)
        data['code'] = code.code
        response = c.authenticate(self.aeid_special, data)
        self.assertEqual(response.status_code, 200)

    @override_settings(**override_celery_data)
    def test_deregister_sms(self):
        data = {"tlf": "+34777777777", "captcha": "asdasd"}
        c = JClient()

        ae = AuthEvent.objects.get(pk=1)
        ae.auth_method = "sms"
        ae.save()

        # Register
        response = c.register(self.aeid_special, data)
        self.assertEqual(response.status_code, 200)
        user = User.objects.get(userdata__tlf=data['tlf'], userdata__event=ae)
        self.assertEqual(user.is_active, True)

        # re-registration is not possible
        response = c.register(self.aeid_special, data)
        self.assertEqual(response.status_code, 400)

        # authenticate
        code = Code.objects.get(user=user.userdata)
        data['code'] = code.code
        response = c.authenticate(self.aeid_special, data)
        self.assertEqual(response.status_code, 200)

        # deregister
        response = c.post('/api/user/deregister/', {})
        self.assertEqual(response.status_code, 200)

        # check deregistration effects

        # is_active is false
        user = User.objects.get(userdata__tlf=data['tlf'], userdata__event=ae)
        self.assertEqual(user.is_active, False)

        # authentication gives error
        self.assertEqual(user.is_active, False)

        # authenticate gives error
        code = Code.objects.get(user=user.userdata)
        data['code'] = code.code
        response = c.authenticate(self.aeid_special, data)
        self.assertEqual(response.status_code, 400)

        # re-registration is enabled
        Code.objects.filter(user=user.userdata).delete()
        data = {"tlf": "+34777777777", "captcha": "asdasd"}
        response = c.register(self.aeid_special, data)
        self.assertEqual(response.status_code, 200)
        user = User.objects.get(userdata__tlf=data['tlf'], userdata__event=ae)
        self.assertEqual(user.is_active, True)

        # authentication works
        code = Code.objects.get(user=user.userdata)
        data['code'] = code.code
        response = c.authenticate(self.aeid_special, data)
        self.assertEqual(response.status_code, 200)

    @override_settings(**override_celery_data)
    def test_deregister_sms_otp(self):
        data = {"tlf": "+34777777777", "captcha": "asdasd"}
        c = JClient()

        ae = AuthEvent.objects.get(pk=1)
        ae.auth_method = "sms-otp"
        ae.save()

        # Register
        response = c.register(self.aeid_special, data)
        self.assertEqual(response.status_code, 200)
        user = User.objects.get(userdata__tlf=data['tlf'], userdata__event=ae)
        self.assertEqual(user.is_active, True)

        # re-registration is not possible
        response = c.register(self.aeid_special, data)
        self.assertEqual(response.status_code, 400)

        # authenticate
        Code.objects.filter(user=user.userdata).delete()
        response = c.post('/api/auth-event/%d/resend_auth_code/' % self.aeid_special, data)
        r = parse_json_response(response)
        self.assertEqual(response.status_code, 200)
        code = Code.objects.get(user=user.userdata)
        data['code'] = code.code
        response = c.authenticate(self.aeid_special, data)
        self.assertEqual(response.status_code, 200)

        # deregister
        response = c.post('/api/user/deregister/', {})
        self.assertEqual(response.status_code, 200)

        # check deregistration effects

        # is_active is false
        user = User.objects.get(userdata__tlf=data['tlf'], userdata__event=ae)
        self.assertEqual(user.is_active, False)

        # authentication gives error
        self.assertEqual(user.is_active, False)

        # authenticate gives error
        code = Code.objects.get(user=user.userdata)
        data['code'] = code.code
        response = c.authenticate(self.aeid_special, data)
        self.assertEqual(response.status_code, 400)

        # re-registration is enabled
        Code.objects.filter(user=user.userdata).delete()
        data = {"tlf": "+34777777777", "captcha": "asdasd"}
        response = c.register(self.aeid_special, data)
        self.assertEqual(response.status_code, 200)
        user = User.objects.get(userdata__tlf=data['tlf'], userdata__event=ae)
        self.assertEqual(user.is_active, True)

        # authentication works
        Code.objects.filter(user=user.userdata).delete()
        response = c.post('/api/auth-event/%d/resend_auth_code/' % self.aeid_special, data)
        r = parse_json_response(response)
        self.assertEqual(response.status_code, 200)
        code = Code.objects.get(user=user.userdata)
        data['code'] = code.code
        response = c.authenticate(self.aeid_special, data)
        self.assertEqual(response.status_code, 200)


class ApiTestActivationAndActivity(TestCase):
    def setUpTestData():
        flush_db_load_fixture()

    def setUp(self):
        ae = AuthEvent(auth_method="email",
                auth_method_config=test_data.authmethod_config_email_default,
                status='started',
                census="open",
                num_successful_logins_allowed = 1)
        ae.save()
        self.ae = ae
        self.aeid = ae.pk

        u_admin = User(username=test_data.admin['username'], email=test_data.admin['email'])
        u_admin.set_password(test_data.admin['password'])
        u_admin.save()
        u_admin.userdata.event = ae
        u_admin.userdata.save()
        self.uid_admin = u_admin.id
        self.u_admin = u_admin

        self.admin_auth_data = dict(email=test_data.admin['email'], code="ERGERG")
        c = Code(user=u_admin.userdata, code=self.admin_auth_data['code'], auth_event_id=1)
        c.save()

        # election edit permission
        acl = ACL(user=u_admin.userdata, object_type='AuthEvent', perm='edit',
            object_id=self.aeid)
        acl.save()

        # election view events permission
        acl = ACL(user=u_admin.userdata, object_type='AuthEvent',
            perm='event-view-activity', object_id=self.aeid)
        acl.save()
        self.acl_activity1 = acl

        u = User(username='test', email=test_data.auth_email_default['email'])
        u.save()
        u.userdata.event = ae
        u.userdata.save()
        self.u = u.userdata
        self.uid = u.id

        c = Code(user=u.userdata, code=test_data.auth_email_default['code'], auth_event_id=ae.pk)
        c.save()
        self.code = c

    @override_settings(**override_celery_data)
    def test_activation(self):
        c = JClient()

        # voter can authenticate
        response = c.authenticate(self.aeid, test_data.auth_email_default)
        self.assertEqual(response.status_code, 200)

        # voter has no permission to list activity
        response = c.get('/api/auth-event/%d/activity/' % self.aeid, {})
        self.assertEqual(response.status_code, 403)

        # admin login
        response = c.authenticate(self.aeid, self.admin_auth_data)
        self.assertEqual(response.status_code, 200)

        # admin can list activity and log is empty
        response = c.get('/api/auth-event/%d/activity/' % self.aeid, {})
        self.assertEqual(response.status_code, 200)
        r = parse_json_response(response)
        self.assertEqual(len(r['activity']), 0)

        # admin deactivates voter
        self.assertEqual(response.status_code, 200)
        data = {'user-ids': [self.uid], 'comment': 'some comment here'}
        response = c.post('/api/auth-event/%d/census/deactivate/' % self.aeid, data)
        self.assertEqual(response.status_code, 200)

        ## check that the deactivation was logged properly
        response = c.get('/api/auth-event/%d/activity/' % self.aeid, {})
        self.assertEqual(response.status_code, 200)
        r = parse_json_response(response)
        self.assertEqual(len(r['activity']), 1)
        self.assertEqual(r['activity'][0]['executer_id'], self.uid_admin)
        self.assertEqual(r['activity'][0]['executer_username'], 'john')
        self.assertEqual(r['activity'][0]['executer_email'], 'john@agoravoting.com')
        self.assertEqual(r['activity'][0]['receiver_id'], self.uid)
        self.assertEqual(r['activity'][0]['receiver_username'], 'test')
        self.assertEqual(r['activity'][0]['receiver_email'], 'aaaa@aaa.com')
        self.assertEqual(r['activity'][0]['action_name'], 'user:deactivate')
        self.assertEqual(r['activity'][0]['metadata']['comment'], data['comment'])

        # voter cannot authenticate
        response = c.authenticate(self.aeid, test_data.auth_email_default)
        self.assertEqual(response.status_code, 400)
        r = parse_json_response(response)
        self.assertEqual(r['error_codename'], 'invalid_credentials')

        # admin login
        response = c.authenticate(self.aeid, self.admin_auth_data)
        self.assertEqual(response.status_code, 200)

        # admin activates voter
        self.assertEqual(response.status_code, 200)
        data = {'user-ids': [self.uid], 'comment': 'comment 2'}
        response = c.post('/api/auth-event/%d/census/activate/' % self.aeid, data)
        self.assertEqual(response.status_code, 200)

        ## check that the deactivation was logged properly
        response = c.get('/api/auth-event/%d/activity/' % self.aeid, {})
        self.assertEqual(response.status_code, 200)
        r = parse_json_response(response)
        self.assertEqual(len(r['activity']), 2)
        self.assertEqual(r['activity'][0]['executer_id'], self.uid_admin)
        self.assertEqual(r['activity'][0]['executer_username'], 'john')
        self.assertEqual(r['activity'][0]['receiver_id'], self.uid)
        self.assertEqual(r['activity'][0]['receiver_username'], 'test')
        self.assertEqual(r['activity'][0]['action_name'], 'user:activate')
        self.assertEqual(r['activity'][0]['metadata']['comment'], data['comment'])

        # check that removing permission works as expected
        self.acl_activity1.delete()
        response = c.get('/api/auth-event/%d/activity/' % self.aeid, {})
        self.assertEqual(response.status_code, 403)

        # voter can authenticate
        test_data.auth_email_default['code'] = self.u.codes.last().code
        response = c.authenticate(self.aeid, test_data.auth_email_default)
        self.assertEqual(response.status_code, 200)

    @override_settings(**override_celery_data)
    def test_filter_activity(self):
        c = JClient()

        # admin login
        response = c.authenticate(self.aeid, self.admin_auth_data)
        self.assertEqual(response.status_code, 200)

        # admin deactivates voter
        self.assertEqual(response.status_code, 200)
        data = {'user-ids': [self.uid], 'comment': 'some comment here'}
        response = c.post('/api/auth-event/%d/census/deactivate/' % self.aeid, data)
        self.assertEqual(response.status_code, 200)

        # admin activates voter
        self.assertEqual(response.status_code, 200)
        data = {'user-ids': [self.uid], 'comment': 'some comment here'}
        response = c.post('/api/auth-event/%d/census/activate/' % self.aeid, data)
        self.assertEqual(response.status_code, 200)

        def check_activity(response, action='user:activate', l=2, status=200):
            ## check that the deactivation/activation was logged properly
            self.assertEqual(response.status_code, status)

            if status == 200:
                r = parse_json_response(response)
                self.assertEqual(len(r['activity']), l)
            else:
                return

            if l == 0:
                return

            self.assertEqual(r['activity'][0]['executer_id'], self.uid_admin)
            self.assertEqual(r['activity'][0]['executer_username'], 'john')
            self.assertEqual(r['activity'][0]['receiver_id'], self.uid)
            self.assertEqual(r['activity'][0]['receiver_username'], 'test')
            self.assertEqual(r['activity'][0]['action_name'], action)
            self.assertEqual(r['activity'][0]['metadata']['comment'], data['comment'])

        ## check input parameters filtering and validation
        path = '/api/auth-event/%d/activity/' % self.aeid

        # check filtering by executer_id
        response = c.get(path + '?executer_id=%d' % self.uid_admin, {})
        check_activity(response)
        # check filtering by receiver_id
        response = c.get(path + '?receiver_id=%d' % self.uid_admin, {})
        check_activity(response, l=0)
        response = c.get(path + '?receiver_id=%d' % self.uid, {})
        check_activity(response)

        # check a receiver_id that doesn't exist
        response = c.get(path + '?receiver_id=133311', {})
        check_activity(response, l=0)

        # check a receiver_id with an invalid string
        response = c.get(path + '?receiver_id=aaaa11e', {})
        check_activity(response, status=400)

        # check a receiver_id that doesn't exist
        response = c.get(path + '?executer_id=9314488', {})
        check_activity(response, l=0)

        # check a receiver_id with an invalid string
        response = c.get(path + '?executer_id=aaaa11e', {})
        check_activity(response, status=400)

        # check filtering by action
        response = c.get(path + '?actions=user:activate', {})
        check_activity(response, l=1)
        response = c.get(path + '?actions=user:deactivate', {})
        check_activity(response, l=1, action='user:deactivate')

        # check filtering with multiple actions
        response = c.get(path + '?actions=user:activate|user:deactivate', {})
        check_activity(response)

        # check filtering with multiple actions, with one action not existent
        response = c.get(path + '?actions=user:activate|user:deactivate|authevent:create', {})
        check_activity(response)

        # check filtering with invalid actions
        response = c.get(path + '?actions=user:activate|INVALID|authevent:create', {})
        check_activity(response, status=400)
        response = c.get(path + '?actions=INVALID_ACTION', {})
        check_activity(response, status=400)

        # check multiple filters
        response = c.get(path + '?executer_id=%d&receiver_id=%d' % (self.uid_admin, self.uid), {})
        check_activity(response)
        response = c.get(path + '?executer_id=%d&receiver_id=%d' % (self.uid_admin, self.uid_admin), {})
        check_activity(response, l=0)
        response = c.get(path + '?receiver_id=%d&executer_id=%d' % (self.uid, self.uid_admin), {})
        check_activity(response)
        response = c.get(path + '?actions=user:activate&receiver_id=%d&executer_id=%d' % (self.uid, self.uid_admin), {})
        check_activity(response, l=1)
        response = c.get(path + '?receiver_id=%d&actions=user:deactivate&executer_id=%d' % (self.uid, self.uid_admin), {})
        check_activity(response, l=1, action="user:deactivate")


        # check that without permissions no activity listing is allowed
        self.acl_activity1.delete()
        response = c.get(path + '?actions=user:activate|INVALID|authevent:create', {})
        check_activity(response, status=403)
        response = c.get(path + '?actions=INVALID_ACTION', {})
        check_activity(response, status=403)
        response = c.get(path + '?executer_id=%d' % self.uid_admin, {})
        check_activity(response, status=403)
        response = c.get(path + '?receiver_id=%d' % self.uid_admin, {})
        check_activity(response, status=403)

        # checking that with event-receiver-view-activity permission no activity
        # listing is allowed without filtering by receiver_id
        acl = ACL(user=self.u_admin.userdata, object_type='AuthEvent',
            perm='event-receiver-view-activity', object_id=self.aeid)
        acl.save()
        response = c.get(path + '?actions=user:activate|INVALID|authevent:create', {})
        check_activity(response, status=403)
        response = c.get(path + '?actions=INVALID_ACTION', {})
        check_activity(response, status=403)
        response = c.get(path + '?executer_id=%d' % self.uid_admin, {})
        check_activity(response, status=403)

        # checking that with event-receiver-view-activity permission activity
        # listing is allowed with filtering by receiver_id
        response = c.get(path + '?receiver_id=%d' % self.uid, {})
        check_activity(response)
        response = c.get(path + '?executer_id=%d&receiver_id=%d' % (self.uid_admin, self.uid), {})
        check_activity(response)
        response = c.get(path + '?executer_id=%d&receiver_id=%d' % (self.uid_admin, self.uid_admin), {})
        check_activity(response, l=0)
        response = c.get(path + '?receiver_id=%d&executer_id=%d' % (self.uid, self.uid_admin), {})
        check_activity(response)
        response = c.get(path + '?actions=user:activate&receiver_id=%d&executer_id=%d' % (self.uid, self.uid_admin), {})
        check_activity(response, l=1)
        response = c.get(path + '?receiver_id=%d&actions=user:deactivate&executer_id=%d' % (self.uid, self.uid_admin), {})
        check_activity(response, l=1, action="user:deactivate")

    @override_settings(**override_celery_data)
    def test_filter_activity2(self):
        c = JClient()

        # admin login
        response = c.authenticate(self.aeid, self.admin_auth_data)
        self.assertEqual(response.status_code, 200)

        # admin deactivates voter
        self.assertEqual(response.status_code, 200)
        data = {'user-ids': [self.uid], 'comment': 'some comment here'}
        response = c.post('/api/auth-event/%d/census/deactivate/' % self.aeid, data)
        self.assertEqual(response.status_code, 200)

        # admin activates voter
        self.assertEqual(response.status_code, 200)
        data = {'user-ids': [self.uid], 'comment': 'some comment here2'}
        response = c.post('/api/auth-event/%d/census/activate/' % self.aeid, data)
        self.assertEqual(response.status_code, 200)

        def check_activity(response, action='user:activate', comment='some comment here2', l=2, status=200):
            ## check that the deactivation/activation was logged properly
            self.assertEqual(response.status_code, status)

            if status == 200:
                r = parse_json_response(response)
                self.assertEqual(len(r['activity']), l)
            else:
                return

            if l == 0:
                return

            self.assertEqual(r['activity'][0]['executer_id'], self.uid_admin)
            self.assertEqual(r['activity'][0]['executer_username'], 'john')
            self.assertEqual(r['activity'][0]['receiver_id'], self.uid)
            self.assertEqual(r['activity'][0]['receiver_username'], 'test')
            self.assertEqual(r['activity'][0]['action_name'], action)
            self.assertEqual(r['activity'][0]['metadata']['comment'], comment)

        # check filtering by string query on action
        path = '/api/auth-event/%d/activity/' % self.aeid

        response = c.get(path, {})
        check_activity(response, l=2)

        # both actions are prefixed with "user:"
        response = c.get(path + '?filter=user:', {})
        check_activity(response, l=2)

        # only one action has a comment with the word "here2"
        response = c.get(path + '?filter=here2', {})
        check_activity(response, l=1)


        # only first action has the action_name "user:activate"
        response = c.get(path + '?filter=here2', {})
        check_activity(response, l=1)

        # only one action has the action_name "user:deactivate"
        response = c.get(path + '?filter=deactivate', {})
        check_activity(response, l=1, action="user:deactivate", comment='some comment here')

        # both actions have the executer "john"
        response = c.get(path + '?filter=john', {})
        check_activity(response, l=2)


class ApiTestBallotBoxes(TestCase):
    def setUpTestData():
        flush_db_load_fixture()

    def setUp(self):
        ae = AuthEvent(
            auth_method="email",
            auth_method_config=test_data.authmethod_config_email_default,
            status='stopped',
            census="open",
            num_successful_logins_allowed = 1,
            has_ballot_boxes=True)
        ae.save()
        self.ae = ae
        self.aeid = ae.pk

        u_admin = User(username=test_data.admin['username'], email=test_data.admin['email'])
        u_admin.set_password(test_data.admin['password'])
        u_admin.save()
        u_admin.userdata.event = ae
        u_admin.userdata.save()
        self.uid_admin = u_admin.id
        self.u_admin = u_admin

        self.admin_auth_data = dict(email=test_data.admin['email'], code="ERGERG")
        c = Code(user=u_admin.userdata, code=self.admin_auth_data['code'], auth_event_id=1)
        c.save()

        # election edit permission
        acl = ACL(user=u_admin.userdata, object_type='AuthEvent', perm='edit',
            object_id=self.aeid)
        acl.save()
        self.acl_edit_event = acl

        u = User(username='test', email=test_data.auth_email_default['email'])
        u.save()
        u.userdata.event = ae
        u.userdata.save()
        self.u = u.userdata
        self.uid = u.id

        ballot_box = BallotBox(auth_event=ae, name="WHAT")
        ballot_box.save()
        self.ballot_box = ballot_box

    @override_settings(**override_celery_data)
    def test_create_ballot_box(self):
        c = JClient()

        # admin login
        response = c.authenticate(self.aeid, self.admin_auth_data)
        self.assertEqual(response.status_code, 200)

        # admin create ballot box
        url = '/api/auth-event/%d/ballot-box/' % self.aeid
        data = dict(name="1A-WHATEVER_BB Ñ")
        response = c.post(url, data)
        self.assertEqual(response.status_code, 200)

    @override_settings(**override_celery_data)
    def test_create_ballot_box_invalid(self):
        c = JClient()

        # admin login
        response = c.authenticate(self.aeid, self.admin_auth_data)
        self.assertEqual(response.status_code, 200)

        # failed attempt to create ballot box, too large input
        url = '/api/auth-event/%d/ballot-box/' % self.aeid
        data = dict(name="_too_large_"*200)
        response = c.post(url, data)
        self.assertEqual(response.status_code, 400)

        # failed attempt to create ballot box, missing field name
        data = dict()
        response = c.post(url, data)
        self.assertEqual(response.status_code, 400)


    @override_settings(**override_celery_data)
    def test_create_ballot_box_no_duplicates(self):
        c = JClient()

        # admin login
        response = c.authenticate(self.aeid, self.admin_auth_data)
        self.assertEqual(response.status_code, 200)

        # create ballot box
        url = '/api/auth-event/%d/ballot-box/' % self.aeid
        data = dict(name="TEST1")
        response = c.post(url, data)
        self.assertEqual(response.status_code, 200)

        # create same ballot box should fail because it's a duplicate
        response = c.post(url, data)
        self.assertEqual(response.status_code, 400)

    @override_settings(**override_celery_data)
    def test_create_ballot_box_check_permissions(self):
        c = JClient()

        url = '/api/auth-event/%d/ballot-box/' % self.aeid
        data = dict(name="TEST")

        # failed attempt to create ballot box, not authenticated
        response = c.post(url, data)
        self.assertEqual(response.status_code, 403)

        # admin login
        response = c.authenticate(self.aeid, self.admin_auth_data)
        self.assertEqual(response.status_code, 200)

        # successful attempt to create ballot box with alt permissions
        self.acl_edit_event.perm = 'add-ballot-boxes'
        self.acl_edit_event.save()
        data['name'] = "TEST2"
        response = c.post(url, data)
        self.assertEqual(response.status_code, 200)

        # failed attempt to create ballot box with other permissions
        self.acl_edit_event.perm = 'other'
        self.acl_edit_event.save()
        data['name'] = "TEST3"
        response = c.post(url, data)
        self.assertEqual(response.status_code, 403)

    @override_settings(**override_celery_data)
    def test_list_ballot_boxes(self):
        c = JClient()

        # admin login
        response = c.authenticate(self.aeid, self.admin_auth_data)
        self.assertEqual(response.status_code, 200)

        # admin list tally sheets
        url = '/api/auth-event/%d/ballot-box/' % self.aeid
        response = c.get(url, {})
        self.assertEqual(response.status_code, 200)
        r = parse_json_response(response)

        # check data is alright, corresponding with the tally sheet
        list_bb = {
            'has_next': False,
            'total_count': 1,
            'page': 1,
            'object_list': [
                {
                    'last_updated': None,
                    'id': self.ballot_box.id,
                    'event_id': self.ae.id,
                    'creator_id': None,
                    'num_tally_sheets': 0,
                    'created': '2018-03-19T14:01:44.813607+00:00',
                    'name': 'WHAT',
                    'creator_username': None
                }
            ],
            'page_range': [1],
            'end_index': 1,
            'has_previous': False,
            'start_index': 1
        }

        self.assertEqual(
            reproducible_json_dumps(static_isodates(r)),
            reproducible_json_dumps(static_isodates(list_bb))
        )

    @override_settings(**override_celery_data)
    def test_list_ballot_boxes_two(self):
        c = JClient()

        # admin login
        response = c.authenticate(self.aeid, self.admin_auth_data)
        self.assertEqual(response.status_code, 200)

        # create ballot box
        url = '/api/auth-event/%d/ballot-box/' % self.aeid
        data = dict(name="TEST1")
        response = c.post(url, data)
        self.assertEqual(response.status_code, 200)

        # admin list tally sheets
        url = '/api/auth-event/%d/ballot-box/' % self.aeid
        response = c.get(url, {})
        self.assertEqual(response.status_code, 200)
        r = parse_json_response(response)

        # check data is alright, corresponding with the tally sheet
        list_bb = {
            'has_next': False,
            'total_count': 2,
            'page': 1,
            'object_list': [
                {
                    'last_updated': None,
                    'id': self.ballot_box.id + 1,
                    'event_id': self.ae.id,
                    'creator_id': None,
                    'num_tally_sheets': 0,
                    'created': '2018-03-19T14:01:44.813607+00:00',
                    'name': 'TEST1',
                    'creator_username': None
                },
                {
                    'last_updated': None,
                    'id': self.ballot_box.id,
                    'event_id': self.ae.id,
                    'creator_id': None,
                    'num_tally_sheets': 0,
                    'created': '2018-03-19T14:01:44.813607+00:00',
                    'name': 'WHAT',
                    'creator_username': None
                }
            ],
            'page_range': [1],
            'end_index': 2,
            'has_previous': False,
            'start_index': 1
        }

        self.assertEqual(
            reproducible_json_dumps(static_isodates(r)),
            reproducible_json_dumps(static_isodates(list_bb))
        )

    @override_settings(**override_celery_data)
    def test_list_ballot_boxes_perms(self):
        c = JClient()

        # list tally sheets without login ,fails
        url = '/api/auth-event/%d/ballot-box/' % self.aeid
        response = c.get(url, {})
        self.assertEqual(response.status_code, 403)
        r = parse_json_response(response)

        # admin login
        response = c.authenticate(self.aeid, self.admin_auth_data)
        self.assertEqual(response.status_code, 200)

        # admin lists tally sheets, works
        url = '/api/auth-event/%d/ballot-box/' % self.aeid
        response = c.get(url, {})
        self.assertEqual(response.status_code, 200)

        # alt permission to list tally sheets, works
        self.acl_edit_event.perm = 'list-ballot-boxes'
        self.acl_edit_event.save()
        url = '/api/auth-event/%d/ballot-box/' % self.aeid
        response = c.get(url, {})
        self.assertEqual(response.status_code, 200)

        # invalid permission to list tally sheets fails
        self.acl_edit_event.perm = 'whatever'
        self.acl_edit_event.save()
        url = '/api/auth-event/%d/ballot-box/' % self.aeid
        response = c.get(url, {})
        self.assertEqual(response.status_code, 403)

    @override_settings(**override_celery_data)
    def test_list_ballot_boxes_with_tally_sheet(self):
        c = JClient()

        # admin login
        response = c.authenticate(self.aeid, self.admin_auth_data)
        self.assertEqual(response.status_code, 200)

        # add an example tally sheet
        tally_sheet_obj = TallySheet(
            ballot_box=self.ballot_box,
            data=dict(
                num_votes=322,
                questions=[
                    dict(
                        title="Do you want Foo Bar to be president?",
                        blank_votes=1,
                        null_votes=1,
                        tally_type="plurality-at-large",
                        answers=[
                          dict(text="Yes", num_votes=200),
                          dict(text="No", num_votes=120)
                        ]
                    )
                ]
            ),
            creator=self.u_admin
        )
        tally_sheet_obj.save()

        # list tally sheets
        url = '/api/auth-event/%d/ballot-box/' % self.aeid
        response = c.get(url, {})
        self.assertEqual(response.status_code, 200)
        r = parse_json_response(response)

        # check data is alright, corresponding with the tally sheet and ballot
        # box
        list_bb = {
            'has_next': False,
            'total_count': 1,
            'page': 1,
            'object_list': [
                {
                    'last_updated': '2018-03-19T14:01:44.813607+00:00',
                    'id': self.ballot_box.id,
                    'event_id': self.ae.id,
                    'creator_id': self.u_admin.id,
                    'num_tally_sheets': 1,
                    'created': '2018-03-19T14:01:44.813607+00:00',
                    'name': 'WHAT',
                    'creator_username': self.u_admin.username
                }
            ],
            'page_range': [1],
            'end_index': 1,
            'has_previous': False,
            'start_index': 1
        }

        self.assertEqual(
            reproducible_json_dumps(static_isodates(r)),
            reproducible_json_dumps(static_isodates(list_bb))
        )

    @override_settings(**override_celery_data)
    def test_list_ballot_boxes_with_2tally_sheet(self):
        c = JClient()

        # admin login
        response = c.authenticate(self.aeid, self.admin_auth_data)
        self.assertEqual(response.status_code, 200)

        # add 2 example tally sheets
        tally_sheet_obj = TallySheet(
            ballot_box=self.ballot_box,
            data=dict(
                num_votes=322,
                questions=[
                    dict(
                        title="Do you want Foo Bar to be president?",
                        blank_votes=1,
                        null_votes=1,
                        tally_type="plurality-at-large",
                        answers=[
                          dict(text="Yes", num_votes=200),
                          dict(text="No", num_votes=120)
                        ]
                    )
                ]
            ),
            creator=self.u_admin
        )
        tally_sheet_obj.save()
        tally_sheet_obj.creator = self.u.user
        tally_sheet_obj.pk = None
        tally_sheet_obj.save()

        # list ballot box with tally sheets
        url = '/api/auth-event/%d/ballot-box/' % self.aeid
        response = c.get(url, {})
        self.assertEqual(response.status_code, 200)
        r = parse_json_response(response)

        # check data is alright, corresponding with the tally sheet and ballot
        # box
        list_bb = {
            'has_next': False,
            'total_count': 1,
            'page': 1,
            'object_list': [
                {
                    'last_updated': '2018-03-19T14:01:44.813607+00:00',
                    'id': self.ballot_box.id,
                    'event_id': self.ae.id,
                    'creator_id': self.u.user.id,
                    'num_tally_sheets': 2,
                    'created': '2018-03-19T14:01:44.813607+00:00',
                    'name': 'WHAT',
                    'creator_username': self.u.user.username
                }
            ],
            'page_range': [1],
            'end_index': 1,
            'has_previous': False,
            'start_index': 1
        }

        self.assertEqual(
            reproducible_json_dumps(static_isodates(r)),
            reproducible_json_dumps(static_isodates(list_bb))
        )

    @override_settings(**override_celery_data)
    def test_list_ballot_boxes_filtering(self):
        c = JClient()

        # admin login
        response = c.authenticate(self.aeid, self.admin_auth_data)
        self.assertEqual(response.status_code, 200)

        # list ballot box
        url = '/api/auth-event/%d/ballot-box/?ballotbox__name__in=FOOO' % self.aeid
        response = c.get(url, {})
        self.assertEqual(response.status_code, 200)
        r = parse_json_response(response)
        self.assertEqual(r["total_count"], 0)

        url = '/api/auth-event/%d/ballot-box/?ballotbox__name__in=WHAT' % self.aeid
        response = c.get(url, {})
        self.assertEqual(response.status_code, 200)
        r = parse_json_response(response)
        self.assertEqual(r["total_count"], 1)

        url = '/api/auth-event/%d/ballot-box/?ballotbox__name__in=FOOO|WHAT' % self.aeid
        response = c.get(url, {})
        self.assertEqual(response.status_code, 200)
        r = parse_json_response(response)
        self.assertEqual(r["total_count"], 1)

    @override_settings(**override_celery_data)
    def test_delete_ballot_boxes(self):
        c = JClient()

        # admin login
        response = c.authenticate(self.aeid, self.admin_auth_data)
        self.assertEqual(response.status_code, 200)

        # delete ballot box
        delete_url = '/api/auth-event/%d/ballot-box/%d/delete/' % (
            self.aeid,
            self.ballot_box.id
        )
        response = c.delete(delete_url, {})
        self.assertEqual(response.status_code, 200)

        # list ballot box, not found
        url = '/api/auth-event/%d/ballot-box/' % self.aeid
        response = c.get(url, {})
        self.assertEqual(response.status_code, 200)
        r = parse_json_response(response)
        list_bb = {
            'page_range': [1],
            'has_previous': False,
            'has_next': False,
            'object_list': [],
            'start_index': 0,
            'page': 1,
            'end_index': 0,
            'total_count': 0
        }
        self.assertEqual(
            reproducible_json_dumps(r),
            reproducible_json_dumps(list_bb)
        )

    @override_settings(**override_celery_data)
    def test_delete_ballot_box_not_found(self):
        c = JClient()

        # admin login
        response = c.authenticate(self.aeid, self.admin_auth_data)
        self.assertEqual(response.status_code, 200)

        # delete ballot box
        delete_url = '/api/auth-event/%d/ballot-box/%d/delete/' % (
            self.aeid,
            self.ballot_box.id+10000
        )
        response = c.delete(delete_url, {})
        self.assertEqual(response.status_code, 404)

    @override_settings(**override_celery_data)
    def test_delete_ballot_box_check_perms(self):
        c = JClient()

        # admin login
        response = c.authenticate(self.aeid, self.admin_auth_data)
        self.assertEqual(response.status_code, 200)

        # delete ballot box with alt permissions
        delete_url = '/api/auth-event/%d/ballot-box/%d/delete/' % (
            self.aeid,
            self.ballot_box.id
        )
        self.acl_edit_event.perm = 'delete-ballot-boxes'
        self.acl_edit_event.save()
        response = c.delete(delete_url, {})
        self.assertEqual(response.status_code, 200)

    @override_settings(**override_celery_data)
    def test_delete_ballot_box_check_perms_invalid(self):
        c = JClient()

        delete_url = '/api/auth-event/%d/ballot-box/%d/delete/' % (
            self.aeid,
            self.ballot_box.id+10000
        )

        # delete ballot box with anon user, fails
        response = c.delete(delete_url, {})
        self.assertEqual(response.status_code, 403)

        # admin login
        response = c.authenticate(self.aeid, self.admin_auth_data)
        self.assertEqual(response.status_code, 200)

        # delete ballot box with invalid permissions, fails
        self.acl_edit_event.perm = 'invalid'
        self.acl_edit_event.save()
        response = c.delete(delete_url, {})
        self.assertEqual(response.status_code, 403)

class ApiTestTallySheets(TestCase):
    def setUpTestData():
        flush_db_load_fixture()

    def setUp(self):
        ae = AuthEvent(
            auth_method="email",
            auth_method_config=test_data.authmethod_config_email_default,
            status='stopped',
            census="open",
            num_successful_logins_allowed = 1,
            has_ballot_boxes=True)
        ae.save()
        self.ae = ae
        self.aeid = ae.pk

        u_admin = User(username=test_data.admin['username'], email=test_data.admin['email'])
        u_admin.set_password(test_data.admin['password'])
        u_admin.save()
        u_admin.userdata.event = ae
        u_admin.userdata.save()
        self.uid_admin = u_admin.id
        self.u_admin = u_admin

        self.admin_auth_data = dict(email=test_data.admin['email'], code="ERGERG")
        c = Code(user=u_admin.userdata, code=self.admin_auth_data['code'], auth_event_id=1)
        c.save()

        # election edit permission
        acl = ACL(user=u_admin.userdata, object_type='AuthEvent', perm='edit',
            object_id=self.aeid)
        acl.save()
        self.acl_edit_event = acl

        # election view events permission
        acl = ACL(user=u_admin.userdata, object_type='AuthEvent',
            perm='event-view-activity', object_id=self.aeid)
        acl.save()
        self.acl_activity1 = acl

        u = User(username='test', email=test_data.auth_email_default['email'])
        u.save()
        u.userdata.event = ae
        u.userdata.save()
        self.u = u.userdata
        self.uid = u.id

        self.tally_data = dict(
            num_votes=322,
            observations="some observation",
            questions=[
                dict(
                    title="Do you want Foo Bar to be president?",
                    blank_votes=1,
                    null_votes=1,
                    tally_type="plurality-at-large",
                    answers=[
                      dict(text="Yes", num_votes=200),
                      dict(text="No", num_votes=120)
                    ]
                )
            ]
        )

        ballot_box = BallotBox(auth_event=ae, name="WHAT")
        ballot_box.save()
        self.ballot_box = ballot_box

    @override_settings(**override_celery_data)
    def test_create_tally_sheet(self):
        c = JClient()

        # admin login
        response = c.authenticate(self.aeid, self.admin_auth_data)
        self.assertEqual(response.status_code, 200)

        # admin create tally sheet
        url = '/api/auth-event/%d/ballot-box/%d/tally-sheet/' % (
            self.aeid,
            self.ballot_box.id
        )
        response = c.post(url, self.tally_data)
        self.assertEqual(response.status_code, 200)

    @override_settings(**override_celery_data)
    def test_create_tally_sheet_invalid(self):
        c = JClient()

        # admin login
        response = c.authenticate(self.aeid, self.admin_auth_data)
        self.assertEqual(response.status_code, 200)

        # admin create tally sheet with invalid data should fail
        url = '/api/auth-event/%d/ballot-box/%d/tally-sheet/' % (
            self.aeid,
            self.ballot_box.id
        )
        self.tally_data['num_votes'] = 101
        response = c.post(url, self.tally_data)
        self.assertEqual(response.status_code, 400)

    @override_settings(**override_celery_data)
    def test_create_tally_sheet_check_perms(self):
        c = JClient()

        # admin login
        response = c.authenticate(self.aeid, self.admin_auth_data)
        self.assertEqual(response.status_code, 200)

        # admin create tally sheet with alternative valid permissions
        self.acl_edit_event.perm = 'add-tally-sheets'
        self.acl_edit_event.save()
        url = '/api/auth-event/%d/ballot-box/%d/tally-sheet/' % (
            self.aeid,
            self.ballot_box.id
        )
        response = c.post(url, self.tally_data)
        self.assertEqual(response.status_code, 200)

        # try override and it should not work because user has no permissions
        response = c.post(url, self.tally_data)
        self.assertEqual(response.status_code, 403)

        # try override and it should work when user has edit permissions
        self.acl_edit_event.perm = 'edit'
        self.acl_edit_event.save()
        response = c.post(url, self.tally_data)
        self.assertEqual(response.status_code, 200)

        # try override and it should work when user has permissions
        self.acl_edit_event.perm = 'add-tally-sheets'
        self.acl_edit_event.save()

        override_acl = ACL(
            user=self.u_admin.userdata,
            object_type='AuthEvent',
            perm='override-tally-sheets',
            object_id=self.aeid
        )
        override_acl.save()

        response = c.post(url, self.tally_data)
        self.assertEqual(response.status_code, 200)

    @override_settings(**override_celery_data)
    def test_list_tally_sheet(self):
        c = JClient()

        # admin login
        response = c.authenticate(self.aeid, self.admin_auth_data)
        self.assertEqual(response.status_code, 200)

        # admin create tally sheet
        url = '/api/auth-event/%d/ballot-box/%d/tally-sheet/' % (
            self.aeid,
            self.ballot_box.id
        )
        response = c.post(url, self.tally_data)
        self.assertEqual(response.status_code, 200)
        r = parse_json_response(response)
        tally_sheet_id = r['id']

        # get the tally sheet
        response = c.get(url, {})
        self.assertEqual(response.status_code, 200)
        r = parse_json_response(response)

        # check data is alright, corresponding with the tally sheet
        assert(r['id'] == tally_sheet_id)
        assert(r['ballot_box_id'] == self.ballot_box.id)
        assert(reproducible_json_dumps(r['data']) == reproducible_json_dumps(self.tally_data))

    @override_settings(**override_celery_data)
    def test_list_tally_sheet_override(self):
        c = JClient()

        # admin login
        response = c.authenticate(self.aeid, self.admin_auth_data)
        self.assertEqual(response.status_code, 200)

        # admin create tally sheet
        url = '/api/auth-event/%d/ballot-box/%d/tally-sheet/' % (
            self.aeid,
            self.ballot_box.id
        )
        response = c.post(url, self.tally_data)
        self.assertEqual(response.status_code, 200)

        # create second tally sheet, overriding the previous one with different
        # data
        self.tally_data['num_votes'] = 323
        self.tally_data['questions'][0]['null_votes'] = 2
        response = c.post(url, self.tally_data)
        self.assertEqual(response.status_code, 200)
        r = parse_json_response(response)
        tally_sheet_id = r['id']

        # get the tally sheet
        response = c.get(url, {})
        self.assertEqual(response.status_code, 200)
        r = parse_json_response(response)

        # check data is alright, corresponding with the second tally sheet
        assert(r['id'] == tally_sheet_id)
        assert(r['ballot_box_id'] == self.ballot_box.id)
        assert(reproducible_json_dumps(r['data']) == reproducible_json_dumps(self.tally_data))

    @override_settings(**override_celery_data)
    def test_get_tally_sheet(self):
        c = JClient()

        # admin login
        response = c.authenticate(self.aeid, self.admin_auth_data)
        self.assertEqual(response.status_code, 200)

        # admin create tally sheet
        url = '/api/auth-event/%d/ballot-box/%d/tally-sheet/' % (
            self.aeid,
            self.ballot_box.id
        )
        tally_sheet1_data_str = reproducible_json_dumps(self.tally_data)
        response = c.post(url, self.tally_data)
        self.assertEqual(response.status_code, 200)
        r = parse_json_response(response)
        tally_sheet1_id = r['id']

        # create second tally sheet, overriding the previous one with different
        # data
        self.tally_data['num_votes'] = 323
        self.tally_data['questions'][0]['null_votes'] = 2
        tally_sheet2_data_str = reproducible_json_dumps(self.tally_data)
        response = c.post(url, self.tally_data)
        self.assertEqual(response.status_code, 200)
        r = parse_json_response(response)
        tally_sheet2_id = r['id']

        # get the tally sheet 1
        response = c.get("%s%d/" % (url, tally_sheet1_id), {})
        self.assertEqual(response.status_code, 200)
        r = parse_json_response(response)

        # check data of the tally sheet 1
        assert(r['id'] == tally_sheet1_id)
        assert(r['ballot_box_id'] == self.ballot_box.id)
        assert(reproducible_json_dumps(r['data']) == tally_sheet1_data_str)

        # get the tally sheet 2
        response = c.get("%s%d/" % (url, tally_sheet2_id), {})
        self.assertEqual(response.status_code, 200)
        r = parse_json_response(response)

        # check data of the tally sheet 2
        assert(r['id'] == tally_sheet2_id)
        assert(r['ballot_box_id'] == self.ballot_box.id)
        assert(reproducible_json_dumps(r['data']) == tally_sheet2_data_str)

    @override_settings(**override_celery_data)
    def test_list_tally_sheet_perms(self):
        c = JClient()

        # admin login
        response = c.authenticate(self.aeid, self.admin_auth_data)
        self.assertEqual(response.status_code, 200)

        # admin create tally sheet
        url = '/api/auth-event/%d/ballot-box/%d/tally-sheet/' % (
            self.aeid,
            self.ballot_box.id
        )
        response = c.post(url, self.tally_data)
        self.assertEqual(response.status_code, 200)

        # get the tally sheet should work with alternative perms
        self.acl_edit_event.perm = 'list-tally-sheets'
        self.acl_edit_event.save()
        response = c.get(url, {})
        self.assertEqual(response.status_code, 200)

        # get the tally sheet should fail with invalid
        self.acl_edit_event.perm = 'foo-bar'
        self.acl_edit_event.save()
        response = c.get(url, {})
        self.assertEqual(response.status_code, 403)

    @override_settings(**override_celery_data)
    def test_delete_tally_sheet(self):
        c = JClient()

        # admin login
        response = c.authenticate(self.aeid, self.admin_auth_data)
        self.assertEqual(response.status_code, 200)

        # admin create tally sheet
        url = '/api/auth-event/%d/ballot-box/%d/tally-sheet/' % (
            self.aeid,
            self.ballot_box.id
        )
        response = c.post(url, self.tally_data)
        self.assertEqual(response.status_code, 200)
        r = parse_json_response(response)
        tally_sheet_id = r['id']

        # get the tally sheet should work with alternative perms
        response = c.delete("%s%d/" % (url, tally_sheet_id), {})
        self.assertEqual(response.status_code, 200)

        # get the tally sheet should fail with 404 not found
        response = c.get(url, {})
        self.assertEqual(response.status_code, 404)
