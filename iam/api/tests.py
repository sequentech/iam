# This file is part of iam.
# Copyright (C) 2014-2020  Sequent Tech Inc <legal@sequentech.io>

# iam is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License.

# iam  is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.

# You should have received a copy of the GNU Affero General Public License
# along with iam.  If not, see <http://www.gnu.org/licenses/>.

import re
import time
import json
import copy
from datetime import datetime
from django.utils import timezone
from django.core import mail
from django.test import TestCase
from django.test import Client
from django.test.utils import override_settings
from django.conf import settings
from django.contrib.auth.models import User

from . import test_data
from .models import ACL, AuthEvent, Action, BallotBox, TallySheet, SuccessfulLogin
from authmethods.models import Code, MsgLog, OneTimeLink
from authmethods import m_sms_otp
from utils import HMACToken, verifyhmac, reproducible_json_dumps, ErrorCodes
from authmethods.utils import get_cannonical_tlf, get_user_code

def flush_db_load_fixture(ffile="initial.json"):
    from django.core import management
    management.call_command("flush", verbosity=0, interactive=False)
    management.call_command("loaddata", ffile, verbosity=0)

override_celery_data = dict(
    CELERY_EAGER_PROPAGATES_EXCEPTIONS=True,
    CELERY_ALWAYS_EAGER=True,
    BROKER_BACKEND='memory'
)

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

class TestHmacToken(TestCase):
    def test_verify_simple_token(self):
        cases = [
            dict(
                token="khmac:///sha-256;48a51120ffd034872c4f1fcd3e61f23bade1181309a66c79bcb33e7838423540/example@sequentech.io:AuthEvent:150017:vote:1620927640",
                digest='sha-256',
                hash='48a51120ffd034872c4f1fcd3e61f23bade1181309a66c79bcb33e7838423540',
                msg='example@sequentech.io:AuthEvent:150017:vote:1620927640',
                timestamp='1620927640',
                userid='example@sequentech.io',
                other_values=['AuthEvent', '150017', 'vote']
            )
        ]
        self._verify_cases(cases)

    def test_verify_tricky_token(self):
        '''
        This is a tricky token because the message contains the '/', ':' and ';'
        separators, meaning that the implementation might get confused if not
        implemented properly.
        '''
        cases = [
            dict(
                token="khmac:///sha-256;48a51120ffd034872c4f1fcd3e61f23bade1181309a66c79bcb33e7838423540/ex:amp./le@nvot;es.com:AuthEvent:150017:vote:1620927640",
                digest='sha-256',
                hash='48a51120ffd034872c4f1fcd3e61f23bade1181309a66c79bcb33e7838423540',
                msg='ex:amp./le@nvot;es.com:AuthEvent:150017:vote:1620927640',
                timestamp='1620927640',
                userid='ex:amp./le@nvot;es.com',
                other_values=['AuthEvent', '150017', 'vote']
            )
        ]
        self._verify_cases(cases)

    def _verify_cases(self, cases):
        for case in cases:
            token = HMACToken(case['token'])
            self.assertEqual(token.digest, case['digest'])
            self.assertEqual(token.hash, case['hash'])
            self.assertEqual(token.msg, case['msg'])
            self.assertEqual(token.timestamp, case['timestamp'])
            self.assertEqual(token.userid, case['userid'])
            self.assertEqual(token.other_values, case['other_values'])

class ApiTestHtmlEmail(TestCase):
    def setUpTestData():
        flush_db_load_fixture()

    def setUp(self):
        self.aeid_special = 1
        u = User(username=test_data.admin['username'], email=test_data.admin['email'])
        u.set_password(test_data.admin['password'])
        u.save()
        u.userdata.event = AuthEvent.objects.get(pk=1)
        u.userdata.save()
        self.user = u

        self.admin_auth_data = dict(
            email=test_data.admin['email'],
            code="ERGERG")
        c = Code(
            user=self.user.userdata,
            code=self.admin_auth_data['code'],
            auth_event_id=self.aeid_special)
        c.save()

        u2 = User(username='noperm', email="noperm@sequentech.io")
        u2.set_password("qwerty")
        u2.save()
        u2.userdata.save()

        self.aeid_special = 1

    def create_authevent(self, authevent):
        c = JClient()
        response = c.authenticate(self.aeid_special, self.admin_auth_data)
        self.assertEqual(response.status_code, 200)
        return c.post('/api/auth-event/', authevent)

    def add_census(self, aeid):
        c = JClient()
        response = c.authenticate(self.aeid_special, self.admin_auth_data)
        self.assertEqual(response.status_code, 200)

        response = c.census(aeid, test_data.census_email_default)
        self.assertEqual(response.status_code, 200)
        response = c.get('/api/auth-event/%d/census/' % aeid, {})
        self.assertEqual(response.status_code, 200)
        r = parse_json_response(response)
        self.assertEqual(len(r['object_list']), 4)

    def test_create_authevent_html_email(self):
        acl = ACL(user=self.user.userdata, object_type='AuthEvent', perm='create',
                object_id=0)
        acl.save()
        # create election with html_message set
        data = test_data.ae_email_config_html
        response = self.create_authevent(data)
        self.assertEqual(response.status_code, 200)
        ae = AuthEvent.objects.last()
        self.assertEqual(ae.auth_method_config['config']['html_message'], data['auth_method_config']['html_message'])

        # create election without html_message set and check it still works
        response = self.create_authevent(test_data.ae_email_config)
        self.assertEqual(response.status_code, 200)
        ae2 = AuthEvent.objects.last()
        self.assertFalse(ae2.id == ae.id)     
        self.assertFalse('html_message' in ae2.auth_method_config['config'])        

        aeid = ae.pk

        self.add_census(aeid) # Add census
        correct_tpl = {
            "subject": "Vote",
            "msg": "this is an example __CODE__ and __URL__",
            "html_message": "<html><head></head><body>this is an example __CODE__ and __URL__</body></html>"
        }
        incorrect_tpl = {"msg": 10001*"a"}
        incorrect_tpl2 = {
            "subject": "Vote",
            "msg": "this is an example __CODE__ and __URL__",
            "html_message": 10001*"a"
        }

        c = JClient()
        response = c.authenticate(self.aeid_special, self.admin_auth_data)
        self.assertEqual(response.status_code, 200)
        response = c.post('/api/auth-event/%d/census/send_auth/' % aeid, {})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(MsgLog.objects.count(), 4)
        msg_log = MsgLog.objects.all().last().msg
        self.assertEqual(msg_log.get('subject'),  ae.auth_method_config['config'].get('subject') + ' - Sequent')
        self.assertTrue(msg_log.get('msg').count(' -- Sequent https://sequentech.io'))
        self.assertTrue(msg_log.get('html_message').count('and put this code'))

        response = c.post('/api/auth-event/%d/census/send_auth/' % aeid, correct_tpl)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(MsgLog.objects.count(), 4*2)
        msg_log = MsgLog.objects.all().last().msg
        self.assertEqual(msg_log.get('subject'), correct_tpl.get('subject') + ' - Sequent')
        self.assertTrue(msg_log.get('msg').count('this is an example'))
        self.assertTrue(msg_log.get('html_message').count('this is an example'))

        response = c.post('/api/auth-event/%d/census/send_auth/' % aeid, incorrect_tpl)
        self.assertEqual(response.status_code, 400)

        response = c.post('/api/auth-event/%d/census/send_auth/' % aeid, incorrect_tpl2)
        self.assertEqual(response.status_code, 400)

    def test_no_html_message_with_disabled_settings(self):
        settings.ALLOW_HTML_EMAILS = False

        acl = ACL(user=self.user.userdata, object_type='AuthEvent', perm='create',
                object_id=0)
        acl.save()
        # create election with html_message set
        data = test_data.ae_email_config_html
        response = self.create_authevent(data)
        self.assertEqual(response.status_code, 200)
        ae = AuthEvent.objects.last()
        self.assertEqual(ae.auth_method_config['config']['html_message'], data['auth_method_config']['html_message'])

        aeid = ae.pk

        self.add_census(aeid) # Add census
        correct_tpl = {
            "subject": "Vote",
            "msg": "this is an example __CODE__ and __URL__",
            "html_message": "<html><head></head><body>this is an example __CODE__ and __URL__</body></html>"
        }

        c = JClient()
        response = c.authenticate(self.aeid_special, self.admin_auth_data)
        self.assertEqual(response.status_code, 200)
        response = c.post('/api/auth-event/%d/census/send_auth/' % aeid, {})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(MsgLog.objects.count(), 4)
        msg_log = MsgLog.objects.all().last().msg
        self.assertEqual(msg_log.get('subject'),  ae.auth_method_config['config'].get('subject') + ' - Sequent')
        self.assertTrue(msg_log.get('msg').count(' -- Sequent https://sequentech.io'))
        self.assertTrue(msg_log.get('html_message') is None)

        response = c.post('/api/auth-event/%d/census/send_auth/' % aeid, correct_tpl)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(MsgLog.objects.count(), 4*2)
        msg_log = MsgLog.objects.all().last().msg
        self.assertEqual(msg_log.get('subject'), correct_tpl.get('subject') + ' - Sequent')
        self.assertTrue(msg_log.get('msg').count('this is an example'))
        self.assertTrue(msg_log.get('html_message') is None)

        settings.ALLOW_HTML_EMAILS = True

class ApiTestCreateNotReal(TestCase):
    def setUpTestData():
        flush_db_load_fixture()

    def setUp(self):
        self.aeid_special = 1
        u = User(username=test_data.admin['username'], email=test_data.admin['email'])
        u.set_password(test_data.admin['password'])
        u.save()
        u.userdata.event = AuthEvent.objects.get(pk=1)
        u.userdata.save()
        self.user = u

        self.admin_auth_data = dict(
            email=test_data.admin['email'],
            code="ERGERG")
        c = Code(
            user=self.user.userdata,
            code=self.admin_auth_data['code'],
            auth_event_id=self.aeid_special)
        c.save()

        u2 = User(username='noperm', email="noperm@sequentech.io")
        u2.set_password("qwerty")
        u2.save()
        u2.userdata.save()

        self.aeid_special = 1

    def create_authevent(self, authevent):
        c = JClient()
        response = c.authenticate(self.aeid_special, self.admin_auth_data)
        self.assertEqual(response.status_code, 200)
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
        ae.extra_fields = test_data.auth_event4['extra_fields']
        ae.census = "open"
        ae.save()

        u = User(
            username=test_data.admin['username'],
            email=test_data.admin['email']
        )
        u.set_password('smith')
        u.save()
        u.userdata.event = ae
        u.userdata.save()
        self.userid = u.pk
        self.testuser = u

    @override_settings(CELERY_ALWAYS_EAGER=True)
    def test_draft(self):
        acl = ACL(
            user=self.testuser.userdata,
            object_type='UserData',
            perm='edit',
            object_id=self.userid
        )
        acl.save()

        c = JClient()
        response = c.authenticate(self.aeid, test_data.pwd_auth)
        self.assertEqual(response.status_code, 200)

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
        ae = AuthEvent(
            auth_method=test_data.auth_event4['auth_method'],
            extra_fields=test_data.auth_event4['extra_fields'],
            auth_method_config=test_data.authmethod_config_email_default
        )
        ae.save()

        self.aeid_special = 1
        u = User(username=test_data.admin['username'], email=test_data.admin['email'])
        u.set_password('smith')
        u.save()
        u.userdata.event = AuthEvent.objects.get(pk=1)
        u.userdata.save()

        self.admin_auth_data = dict(
            email=test_data.admin['email'],
            code="ERGERG")
        c = Code(
            user=u.userdata,
            code=self.admin_auth_data['code'],
            auth_event_id=self.aeid_special)
        c.save()

        self.userid = u.pk
        self.testuser = u
        self.aeid = ae.pk
        self.ae = ae

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

    def test_archive_unarchive(self):
        c = JClient()
        response = c.post('/api/auth-event/%d/archive/' % self.aeid, {})
        self.assertEqual(response.status_code, 403)
        response = c.post('/api/auth-event/%d/unarchive/' % self.aeid, {})
        self.assertEqual(response.status_code, 403)

        response = c.authenticate(self.aeid_special, self.admin_auth_data)
        self.assertEqual(response.status_code, 200)

        response = c.post('/api/auth-event/%d/unarchive/' % self.aeid, {})
        self.assertEqual(response.status_code, 403)

        def assert_perms(perms, count):
            self.assertEqual(
                ACL.objects.filter(
                    user=self.testuser.userdata,
                    perm__in=perms,
                    object_type='AuthEvent',
                    object_id=self.aeid
                ).count(),
                count
            )
        assert_perms(perms=['edit'], count=1)
        assert_perms(perms=['unarchive'], count=0)

        response = c.post('/api/auth-event/%d/archive/' % self.aeid, {})
        self.assertEqual(response.status_code, 200)

        assert_perms(perms=['edit'], count=0)
        assert_perms(perms=['unarchive'], count=1)

        response = c.post('/api/auth-event/%d/archive/' % self.aeid, {})
        self.assertEqual(response.status_code, 403)

        response = c.post('/api/auth-event/%d/unarchive/' % self.aeid, {})
        self.assertEqual(response.status_code, 200)

        assert_perms(perms=['edit'], count=1)
        assert_perms(perms=['unarchive'], count=0)

    def test_change_status(self):
        c = JClient()
        response = c.post('/api/auth-event/%d/%s/' % (self.aeid, 'started'), {})
        self.assertEqual(response.status_code, 403)
        response = c.post('/api/auth-event/%d/%s/' % (self.aeid, 'stopped'), {})
        self.assertEqual(response.status_code, 403)

        response = c.authenticate(self.aeid_special, self.admin_auth_data)
        self.assertEqual(response.status_code, 200)

        response = c.post('/api/auth-event/%d/%s/' % (self.aeid, 'started'), {})
        self.assertEqual(response.status_code, 200)
        response = c.post('/api/auth-event/%d/%s/' % (self.aeid, 'stopped'), {})
        self.assertEqual(response.status_code, 200)
        response = c.post('/api/auth-event/%d/%s/' % (self.aeid, 'stopped'), {})
        self.assertEqual(response.status_code, 200)

    def test_authenticate(self):
        c = JClient()

        response = c.authenticate(self.aeid_special, self.admin_auth_data)
        self.assertEqual(response.status_code, 200)

        self.assertEqual(response.status_code, 200)
        r = parse_json_response(response)
        self.assertEqual(r['status'], 'ok')

        # verify format of the hmac, including username
        self.assertTrue(re.match(
            "^khmac:\/\/\/sha-256;[a-f0-9]{64}\/john:[0-9]+$",
            r['auth-token']
        ))
        self.assertEqual(verifyhmac(settings.SHARED_SECRET,
            r['auth-token']), True)
        time.sleep(3)
        self.assertEqual(verifyhmac(settings.SHARED_SECRET,
            r['auth-token'], seconds=3), False)

        data = {'email': 'john@sequentech.io', 'password': 'fake'}
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
        response = c.authenticate(self.aeid_special, self.admin_auth_data)
        self.assertEqual(response.status_code, 200)
        data = {
            "object_type": "User",
            "permission": "delete"
        }
        response = c.post('/api/get-perms/', data)

        self.assertEqual(response.status_code, 400)

    def test_getperms_perm(self):
        c = JClient()
        response = c.authenticate(self.aeid_special, self.admin_auth_data)
        self.assertEqual(response.status_code, 200)
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
        response = c.authenticate(self.aeid_special, self.admin_auth_data)
        self.assertEqual(response.status_code, 200)
        data = { "permission": "create" }
        response = c.post('/api/get-perms/', data)
        self.assertEqual(response.status_code, 400)

    def test_create_event(self):
        c = JClient()
        response = c.authenticate(self.aeid_special, self.admin_auth_data)
        self.assertEqual(response.status_code, 200)

        data = test_data.auth_event1
        response = c.post('/api/auth-event/', data)
        self.assertEqual(response.status_code, 200)
        r = parse_json_response(response)
        self.assertTrue('id' in  r and isinstance(r['id'], int))

    @override_settings(CELERY_ALWAYS_EAGER=True)
    def test_create_event_open(self):
        c = JClient()
        response = c.authenticate(self.aeid_special, self.admin_auth_data)
        self.assertEqual(response.status_code, 200)

        data = test_data.auth_event3
        response = c.post('/api/auth-event/', data)
        self.assertEqual(response.status_code, 200)
        r = parse_json_response(response)
        self.assertEqual(r['id'], self.aeid + 1)
        rid = r['id']

        # try register in stopped auth-event
        c = JClient()
        data = {'email': 'test@test.com'}
        response = c.register(rid, data)
        self.assertEqual(response.status_code, 400)

        # try register in started auth-event
        c = JClient()
        response = c.authenticate(self.aeid_special, self.admin_auth_data)
        self.assertEqual(response.status_code, 200)
        response = c.post('/api/auth-event/%d/%s/' % (rid, 'started'), {})
        self.assertEqual(response.status_code, 200)

        c = JClient()
        data = {'email': 'test@test.com'}
        response = c.register(rid, data)
        self.assertEqual(response.status_code, 200)

    def test_list_event(self):
        self.test_create_event()
        c = JClient()
        response = c.authenticate(self.aeid_special, self.admin_auth_data)
        self.assertEqual(response.status_code, 200)

        response = c.get('/api/auth-event/', {})
        self.assertEqual(response.status_code, 200)
        r = parse_json_response(response)
        self.assertEqual(len(r['events']), 3)

    def test_edit_event_success(self):
        c = JClient()
        response = c.authenticate(self.aeid_special, self.admin_auth_data)
        self.assertEqual(response.status_code, 200)

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
        response = c.authenticate(self.aeid_special, self.admin_auth_data)
        self.assertEqual(response.status_code, 200)

        response = c.delete('/api/auth-event/%d/' % self.aeid, {})
        self.assertEqual(response.status_code, 200)
        r = parse_json_response(response)
        self.assertEqual(r['status'], 'ok')

    def test_create_acl(self):
        c = JClient()
        response = c.authenticate(self.aeid_special, self.admin_auth_data)
        self.assertEqual(response.status_code, 200)

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
        response = c.authenticate(self.aeid_special, self.admin_auth_data)
        self.assertEqual(response.status_code, 200)
        response = c.delete('/api/acl/%s/%s/%s/' % (self.testuser.username, 'election', 'vote'), {})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(0, ACL.objects.filter(user=self.userid, perm='vote').count())

    def test_view_acl(self):
        c = JClient()
        response = c.authenticate(self.aeid_special, self.admin_auth_data)
        self.assertEqual(response.status_code, 200)
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
        response = c.authenticate(self.aeid_special, self.admin_auth_data)
        self.assertEqual(response.status_code, 200)
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
        response = c.authenticate(self.aeid_special, self.admin_auth_data)
        self.assertEqual(response.status_code, 200)
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
        response = c.authenticate(self.aeid_special, self.admin_auth_data)
        self.assertEqual(response.status_code, 200)
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
        response = c.authenticate(self.aeid_special, self.admin_auth_data)
        self.assertEqual(response.status_code, 200)

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

        ae = AuthEvent.objects.get(pk=self.aeid_special)
        ae.auth_method = "user-and-password"
        ae.census = "open"
        ae.extra_fields = test_data.auth_event4['extra_fields']
        ae.save()
        login_data = dict(username=test_data.admin['username'], password='smith')

        c = JClient()
        response = c.authenticate(self.aeid_special, login_data)
        self.assertEqual(response.status_code, 200)
        response = c.post('/api/user/reset-pwd/', {})
        self.assertEqual(response.status_code, 200)

        response = c.authenticate(self.aeid_special, login_data)
        self.assertEqual(response.status_code, 400)
        self.assertEqual(len(mail.outbox), 1)
        self.assertEqual(mail.outbox[0].subject, 'Reset password')

    def test_get_authmethod(self):
        c = JClient()
        response = c.authenticate(self.aeid_special, self.admin_auth_data)
        self.assertEqual(response.status_code, 200)
        response = c.get('/api/auth-event/module/', {})
        self.assertEqual(response.status_code, 200)

        response = c.get('/api/auth-event/module/email/', {})
        self.assertEqual(response.status_code, 200)


class TestAuthEvent(TestCase):
    def setUpTestData():
        flush_db_load_fixture()

    def setUp(self):
        self.ae = AuthEvent(
            auth_method=test_data.auth_event4['auth_method'],
            extra_fields=test_data.auth_event4['extra_fields'],
            auth_method_config=test_data.authmethod_config_email_default
        )
        self.ae.save()

        self.aeid_special = 1
        u = User(
            username=test_data.admin['username'], 
            email=test_data.admin['email']
        )
        u.set_password(test_data.admin['password'])
        u.save()
        u.userdata.event = AuthEvent.objects.get(pk=1)
        u.userdata.save()
        self.user = u

        self.admin_auth_data = dict(
            email=test_data.admin['email'],
            code="ERGERG")
        c = Code(
            user=self.user.userdata,
            code=self.admin_auth_data['code'],
            auth_event_id=self.aeid_special
        )
        c.save()

        u2 = User(username='noperm', email="noperm@sequentech.io")
        u2.set_password("qwerty")
        u2.save()
        u2.userdata.save()

        acl = ACL(
            user=u.userdata, 
            object_type='AuthEvent', 
            perm='create',
            object_id=0
        )
        acl.save()

    def create_authevent(self, authevent):
        c = JClient()
        response = c.authenticate(self.aeid_special, self.admin_auth_data)
        self.assertEqual(response.status_code, 200)
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
        user = {'email': 'noperm@sequentech.io', 'password': 'qwerty'}

        c = JClient()
        response = c.post('/api/auth-event/', data)
        self.assertEqual(response.status_code, 403)

        response = c.authenticate(0, user)
        response = c.post('/api/auth-event/', data)
        self.assertEqual(response.status_code, 403)

    def test_create_auth_event_with_perm(self):
        acl = ACL(
            user=self.user.userdata, 
            object_type='AuthEvent',
            perm='create', object_id=0
        )
        acl.save()

        c = JClient()
        response = c.authenticate(self.aeid_special, self.admin_auth_data)
        self.assertEqual(response.status_code, 200)
        response = c.post('/api/auth-event/', test_data.ae_email_default)
        self.assertEqual(response.status_code, 200)
        response = c.post('/api/auth-event/', test_data.ae_sms_default)
        self.assertEqual(response.status_code, 200)

    def test_create_authevent_email(self):
        response = self.create_authevent(test_data.ae_email_default)
        self.assertEqual(response.status_code, 200)

    def test_create_authevent_otl(self):
        auth_event_data = copy.deepcopy(test_data.ae_email_default)
        auth_event_data['support_otl_enabled'] = True
        response = self.create_authevent(auth_event_data)
        self.assertEqual(response.status_code, 200)
        response_json = parse_json_response(response)
        auth_event_id = response_json['id']
        self.assertEqual(
            AuthEvent.objects.get(pk=auth_event_id).support_otl_enabled,
            True
        )

    def test_create_authevent_invalid_otl(self):
        auth_event_data = copy.deepcopy(test_data.ae_email_default)
        # try creating with invalid data type
        auth_event_data['support_otl_enabled'] = "foobar"
        response = self.create_authevent(auth_event_data)
        self.assertEqual(response.status_code, 400)

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
        
        response = self.create_authevent(test_data.ae_email_fields_incorrect_status)
        self.assertEqual(response.status_code, 400)
        r = parse_json_response(response)
        self.assertEqual(r['message'], 'Two fields with same name: status.\n')

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

    def _test_create_authevent_test_and_real(self):
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

    def test_get_authevent(self):
        c = JClient()
        response = c.authenticate(self.aeid_special, self.admin_auth_data)
        self.assertEqual(response.status_code, 200)

        response = c.post('/api/auth-event/', test_data.ae_email_default)
        self.assertEqual(response.status_code, 200)
        r = parse_json_response(response)
        rid = r['id']

        response = c.get('/api/auth-event/%d/' % rid, {})
        self.assertEqual(response.status_code, 200)
        r = parse_json_response(response)
        auth_event = {
            'events': {
                'allow_public_census_query': False,
                'force_census_query': False,
                'alternative_auth_methods': None,
                'auth_method': 'email',
                'created': '2018-03-29T11:20:30.656486+00:00',
                'auth_method_config': test_data.ae_email_default__method_config,
                'admin_fields': None,
                'has_ballot_boxes': False,
                'extra_fields': [
                    {
                        "name": "email",
                        "type": "email",
                        "required": True,
                        "unique": True,
                        "min": 4,
                        "max": 255,
                        "required_on_authentication": True,
                        "slug": "EMAIL"
                    }
                ],
                'based_in': None,
                'census': 'open',
                'auth_method_stats': {
                  'email': 0
                },
                'id': rid,
                'users': 0,
                'num_successful_logins_allowed': 0,
                'support_otl_enabled': False,
                'inside_authenticate_otl_period': False,
                'hide_default_login_lookup_field': False,
                'parent_id': None,
                'children_election_info': None,
                'oidc_providers': [],
                'scheduled_events': None,
                'total_votes': 0,
                'tally_status': 'notstarted',
                'children_tally_status': []
            },
            'status': 'ok'
        }
        self.assertEqual(
            reproducible_json_dumps(static_isodates(r)),
            reproducible_json_dumps(static_isodates(auth_event))
        )

    def test_get_auth_events(self):
        c = JClient()
        response = c.authenticate(self.aeid_special, self.admin_auth_data)
        self.assertEqual(response.status_code, 200)

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
        ae = AuthEvent(
            auth_method="email",
            auth_method_config=test_data.authmethod_config_email_default,
            extra_fields=test_data.ae_email_default['extra_fields'],
            status='started',
            census="open"
        )
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
        self.ae.extra_fields.extend(test_data.extra_field_autofill)
        self.ae.save()

        u = User.objects.get(id=self.uid_admin)
        u.save()
        u.userdata.metadata = {"mesa": "mesa 42"}
        u.userdata.save()

        c = JClient()
        response = c.authenticate(self.ae.pk, self.admin_auth_data)
        self.assertEqual(response.status_code, 200)

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
        self.ae.extra_fields.extend(test_data.extra_field_autofill)
        self.ae.save()

        u = User.objects.get(id=self.uid_admin)
        u.save()
        u.userdata.metadata = {"mesa": "mesa 42"}
        u.userdata.save()

        c = JClient()
        response = c.authenticate(self.ae.pk, self.admin_auth_data)
        self.assertEqual(response.status_code, 200)

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
        self.ae.extra_fields.extend(test_data.extra_field_date)
        self.ae.save()

        c = JClient()
        response = c.authenticate(self.ae.pk, self.admin_auth_data)
        self.assertEqual(response.status_code, 200)

        response = c.census(self.ae.pk, test_data.census_date_field_ok)
        self.assertEqual(response.status_code, 200)

        response = c.get('/api/auth-event/%d/census/' % self.aeid, {})
        self.assertEqual(response.status_code, 200)
        r = json.loads(response.content.decode('utf-8'))
        self.assertEqual(len(r['object_list']), 5)

        response = c.census(self.ae.pk, test_data.census_date_field_nok)
        self.assertEqual(response.status_code, 400)

class TestFilterSendAuthEmail(TestCase):
    def setUpTestData():
        flush_db_load_fixture()

    @classmethod
    def setUpClass(cls):
        super().setUpClass()

    @classmethod
    def tearDownClass(cls):
        super().tearDownClass()

    def setUp(self):
        ae = AuthEvent(
            auth_method="email",
            auth_method_config=test_data.authmethod_config_email_default,
            extra_fields=test_data.ae_email_default['extra_fields'],
            status='started',
            census="open"
        )
        ae.save()
        self.ae = ae
        self.aeid = ae.pk

        u_admin = User(
            username=test_data.admin['username'],
            email=test_data.admin['email']
        )
        u_admin.set_password(test_data.admin['password'])
        u_admin.save()
        u_admin.userdata.event = ae
        u_admin.userdata.save()
        self.uid_admin = u_admin.id

        acl = ACL(
            user=u_admin.userdata, 
            object_type='AuthEvent',
            perm='edit',
            object_id=self.aeid
        )
        acl.save()

        u = self.new_user('test', test_data.auth_email_default['email'], ae)
        self.u = u.userdata
        self.uid = u.id

        acl = ACL(
            user=u.userdata,
            object_type='AuthEvent', 
            perm='edit',
            object_id=self.aeid
        )
        acl.save()

        c = Code(
            user=u.userdata,
            code=test_data.auth_email_default['code'],
            auth_event_id=ae.pk
        )
        c.save()
        self.code = c

    def new_user(self, name, email, auth_event):
        user = User(
            username=name, 
            email=email
        )
        user.save()
        user.userdata.event = auth_event
        user.userdata.save()
        return user

    def add_vote(self, user, date, auth_event):
        vote = SuccessfulLogin(
            created=date,
            user=user.userdata,
            auth_event=auth_event,
            is_active=True
        )
        vote.save()
        return vote

    def add_census_authevent_email_default(self):
        c = JClient()
        response = c.authenticate(self.aeid, test_data.auth_email_default)
        self.assertEqual(response.status_code, 200)

        response = c.census(self.aeid, test_data.census_email_default)
        self.assertEqual(response.status_code, 200)
        response = c.get('/api/auth-event/%d/census/' % self.aeid, {})
        self.assertEqual(response.status_code, 200)
        election_users = parse_json_response(response)
        self.assertEqual(len(election_users['object_list']), 4)
        return election_users['object_list']

    def add_vote(self, user, date, auth_event):
        vote = SuccessfulLogin(
            created=date,
            user=user.userdata,
            auth_event=auth_event
        )
        vote.save()
        return vote

    @override_settings(CELERY_ALWAYS_EAGER=True)
    def test_register_and_resend_code(self):
        # add census
        users = self.add_census_authevent_email_default()

        # add vote
        user1 = User.objects.get(id=users[0]["id"])
        date = datetime(2010, 10, 10, 0, 30, 30, 0, None)
        self.add_vote(user1, date, self.ae)

        # authenticate
        c = JClient()
        response = c.authenticate(self.aeid, test_data.auth_email_default)
        self.assertEqual(response.status_code, 200)

        data = test_data.send_auth_email_filter_fields.copy()

        # send message to all those that have voted
        response = c.post('/api/auth-event/%d/census/send_auth/' % self.aeid, data)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(MsgLog.objects.count(), 1)
        msg_log = MsgLog.objects.all().last().msg
        self.assertEqual(msg_log.get('subject'), 'Test Vote now with Sequent Tech Inc. - Sequent')

        data['filter'] = 'not_voted'

        # send message to those that haven't voted yet
        response = c.post('/api/auth-event/%d/census/send_auth/' % self.aeid, data)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(MsgLog.objects.count(), 4)
        msg_log = MsgLog.objects.all().last().msg
        self.assertEqual(msg_log.get('subject'), 'Test Vote now with Sequent Tech Inc. - Sequent')

        data['filter'] = 'error'

        # send message to those that haven't voted yet
        response = c.post('/api/auth-event/%d/census/send_auth/' % self.aeid, data)
        self.assertEqual(response.status_code, 400)

class TestFilterSendAuthSms(TestCase):
    def setUpTestData():
        flush_db_load_fixture()

    def setUp(self):
        ae = AuthEvent(
            auth_method="sms",
            extra_fields=test_data.ae_sms_default['extra_fields'],
            auth_method_config=test_data.authmethod_config_sms_default,
            status='started',
            census="open"
        )
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

    def add_vote(self, user, date, auth_event):
        vote = SuccessfulLogin(
            created=date,
            user=user.userdata,
            auth_event=auth_event,
            is_active=True
        )
        vote.save()
        return vote

    def add_census_authevent_sms_default(self):
        c = JClient()
        response = c.authenticate(self.aeid, test_data.auth_sms_default)
        self.assertEqual(response.status_code, 200)

        response = c.census(self.aeid, test_data.census_sms_default)
        self.assertEqual(response.status_code, 200)

        response = c.get('/api/auth-event/%d/census/' % self.aeid, {})
        self.assertEqual(response.status_code, 200)
        election_users = parse_json_response(response)
        self.assertEqual(len(election_users['object_list']), 4)
        return election_users['object_list']

    @override_settings(CELERY_ALWAYS_EAGER=True)
    def test_register_and_resend_code(self):
        # add census
        users = self.add_census_authevent_sms_default()

        # add vote
        user1 = User.objects.get(id=users[0]["id"])
        date = datetime(2010, 10, 10, 0, 30, 30, 0, None)
        self.add_vote(user1, date, self.ae)

        # authenticate
        c = JClient()
        response = c.authenticate(self.aeid, test_data.auth_sms_default)
        self.assertEqual(response.status_code, 200)

        data = test_data.send_auth_sms_filter_fields.copy()

        # send message to all those that have voted
        response = c.post('/api/auth-event/%d/census/send_auth/' % self.aeid, data)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(MsgLog.objects.count(), 1)
        msg_log = MsgLog.objects.all().last().msg
        self.assertEqual(msg_log.get('msg'), 'Test Vote now with Sequent Tech Inc. -- Sequent')

        data['filter'] = 'not_voted'

        # send message to those that haven't voted yet
        response = c.post('/api/auth-event/%d/census/send_auth/' % self.aeid, data)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(MsgLog.objects.count(), 4)
        msg_log = MsgLog.objects.all().last().msg
        self.assertEqual(msg_log.get('msg'), 'Test Vote now with Sequent Tech Inc. -- Sequent')

        data['filter'] = 'error'

        # send message to those that haven't voted yet
        response = c.post('/api/auth-event/%d/census/send_auth/' % self.aeid, data)
        self.assertEqual(response.status_code, 400)

class TestRegisterAndAuthenticateEmail(TestCase):
    def setUpTestData():
        flush_db_load_fixture()

    @classmethod
    def setUpClass(cls):
        super().setUpClass()

    @classmethod
    def tearDownClass(cls):
        super().tearDownClass()

    def setUp(self):
        ae = AuthEvent(
            auth_method="email",
            auth_method_config=test_data.authmethod_config_email_default,
            extra_fields=test_data.ae_email_default['extra_fields'],
            status='started',
            census="open"
        )
        ae.save()
        self.ae = ae
        self.aeid = ae.pk

        u_admin = User(
            username=test_data.admin['username'],
            email=test_data.admin['email']
        )
        u_admin.set_password(test_data.admin['password'])
        u_admin.save()
        u_admin.userdata.event = ae
        u_admin.userdata.save()
        self.uid_admin = u_admin.id

        acl = ACL(
            user=u_admin.userdata, 
            object_type='AuthEvent',
            perm='edit',
            object_id=self.aeid
        )
        acl.save()

        u = User(username='test', email=test_data.auth_email_default['email'])
        u.save()
        u.userdata.event = ae
        u.userdata.save()
        self.u = u.userdata
        self.uid = u.id

        acl = ACL(
            user=u.userdata,
            object_type='AuthEvent', 
            perm='edit',
            object_id=self.aeid
        )
        acl.save()

        c = Code(
            user=u.userdata,
            code=test_data.auth_email_default['code'],
            auth_event_id=ae.pk
        )
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
        self.assertEqual(r['error_codename'], 'INVALID_REQUEST')

        # good: allow_user_resend = True
        self.ae.auth_method_config['config']['allow_user_resend'] = True
        self.ae.save()
        response = c.post('/api/auth-event/%d/resend_auth_code/' % self.aeid, data)
        r = parse_json_response(response)
        self.assertEqual(response.status_code, 200)

        # bad: status != started
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
        code = get_user_code(self.u.user)

        credentials = dict(
            email=self.u.user.email,
            code=code.code
        )

        response = c.authenticate(self.aeid, credentials)
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
        response = c.authenticate(self.aeid, test_data.auth_email_default)
        self.assertEqual(response.status_code, 200)

        response = c.census(self.aeid, test_data.census_email_default)
        self.assertEqual(response.status_code, 200)
        response = c.get('/api/auth-event/%d/census/' % self.aeid, {})
        self.assertEqual(response.status_code, 200)
        r = parse_json_response(response)
        self.assertEqual(len(r['object_list']), 4)

    def test_add_census_authevent_email_fields(self):
        c = JClient()
        response = c.authenticate(self.aeid, test_data.auth_email_default)
        self.assertEqual(response.status_code, 200)

        response = c.census(self.aeid, test_data.census_email_fields)
        self.assertEqual(response.status_code, 200)

    def test_add_census_authevent_email_default_incorrect(self):
        c = JClient()
        response = c.authenticate(self.aeid, test_data.auth_email_default)
        self.assertEqual(response.status_code, 200)

        response = c.census(self.aeid, test_data.census_sms_default)
        self.assertEqual(response.status_code, 400)
        response = c.census(self.aeid, test_data.census_sms_fields)
        self.assertEqual(response.status_code, 400)

    def test_add_census_authevent_email_fields_incorrect(self):
        c = JClient()
        response = c.authenticate(self.aeid, test_data.auth_email_default)
        self.assertEqual(response.status_code, 200)

        response = c.census(self.aeid, test_data.census_sms_default)
        self.assertEqual(response.status_code, 400)
        response = c.census(self.aeid, test_data.census_sms_fields)
        self.assertEqual(response.status_code, 400)

    def test_add_census_authevent_email_repeat(self):
        c = JClient()
        response = c.authenticate(self.aeid, test_data.auth_email_default)
        self.assertEqual(response.status_code, 200)

        response = c.census(self.aeid, test_data.census_email_repeat)
        self.assertEqual(response.status_code, 400)
        r = parse_json_response(response)
        self.assertEqual(r['error_codename'], 'invalid_credentials')

    def test_add_census_authevent_email_with_spaces(self):
        c = JClient()
        response = c.authenticate(self.aeid, test_data.auth_email_default)
        self.assertEqual(response.status_code, 200)

        response = c.census(self.aeid, test_data.census_email_spaces)
        self.assertEqual(response.status_code, 200)

    def _test_add_used_census(self):
        c = JClient()
        response = c.authenticate(self.aeid, test_data.auth_email_default)
        self.assertEqual(response.status_code, 200)


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
        response = c.authenticate(self.aeid, test_data.auth_email_default)
        self.assertEqual(response.status_code, 200)

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
        self.assertEqual(r['error_codename'], ErrorCodes.INVALID_CODE)

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
    def test_fixed_code_email(self):
        # set fixed code for election
        self.ae.auth_method_config['config']['fixed-code'] = True
        self.ae.save()

        # Add census
        self.test_add_census_authevent_email_default()

        # get user
        user_email = test_data.census_email_default["census"][0]["email"]
        user = User.objects.get(email=user_email)
        from api.models import UserData
        userdata = UserData.objects.get(event_id=self.ae.id, user=user)

        # check there are no codes for user
        ae_codes = Code.objects.filter(auth_event_id=self.ae.id, user=userdata)
        self.assertEqual(ae_codes.count(), 0)

        # send auth message
        correct_tpl = { "subject": "Vote", "msg": "This is an example __CODE__ and __URL__", "user-ids": [userdata.id] }
        c = JClient()
        response = c.authenticate(self.aeid, test_data.auth_email_default)
        self.assertEqual(response.status_code, 200)
        response = c.post('/api/auth-event/%d/census/send_auth/' % self.aeid, correct_tpl)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(MsgLog.objects.count(), 1)

        # check code was created
        ae_codes = Code.objects.filter(auth_event_id=self.ae.id, user=userdata)
        self.assertEqual(ae_codes.count(), 1)
        created_code = ae_codes[0]

        # send new auth message
        response = c.post('/api/auth-event/%d/census/send_auth/' % self.aeid, correct_tpl)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(MsgLog.objects.count(), 2)

        # check no code was created, existing code was used
        from utils import format_code
        msg_log = MsgLog.objects.all().last().msg
        self.assertEqual(msg_log.get('subject'), correct_tpl.get('subject') + ' - Sequent')
        self.assertTrue(msg_log.get('msg').count(' -- Sequent https://sequentech.io'))
        self.assertTrue(msg_log.get('msg').count("This is an example %(code)s and " % dict(code=format_code(created_code.code))))
        ae_codes = Code.objects.filter(auth_event_id=self.ae.id, user=userdata)
        self.assertEqual(ae_codes.count(), 1)
        
        del self.ae.auth_method_config['config']['fixed-code']
        self.ae.save()

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
        self.assertEqual(msg_log.get('subject'), 'Confirm your email - Sequent')
        self.assertTrue(msg_log.get('msg').count(' -- Sequent https://sequentech.io'))

        response = c.post('/api/auth-event/%d/census/send_auth/' % self.aeid, correct_tpl)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(MsgLog.objects.count(), 4*2)
        msg_log = MsgLog.objects.all().last().msg
        self.assertEqual(msg_log.get('subject'), correct_tpl.get('subject') + ' - Sequent')
        self.assertTrue(msg_log.get('msg').count('this is an example'))

        response = c.post('/api/auth-event/%d/census/send_auth/' % self.aeid, incorrect_tpl)
        self.assertEqual(response.status_code, 400)

    @override_settings(**override_celery_data)
    def test_send_auth_email_url2_home_url(self):
        # Add census
        c = JClient()
        response = c.authenticate(self.aeid, test_data.auth_email_default)
        self.assertEqual(response.status_code, 200)

        response = c.census(self.aeid, test_data.census_email_default1)
        self.assertEqual(response.status_code, 200)
        response = c.get('/api/auth-event/%d/census/' % self.aeid, {})
        self.assertEqual(response.status_code, 200)
        r = parse_json_response(response)
        self.assertEqual(len(r['object_list']), 1)

        correct_tpl = {
          "msg" : "Vote in __URL2__ with home page __HOME_URL__",
          "subject" : "Vote now with Sequent",
          "user-ids" : None,
          "auth-method" : "email"
        }
        incorrect_tpl = {"msg": 10001*"a"}

        response = c.authenticate(self.aeid, test_data.auth_email_default)
        response = c.post('/api/auth-event/%d/census/send_auth/' % self.aeid, correct_tpl)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(MsgLog.objects.count(), 1)
        msg_log = MsgLog.objects.all().last().msg
        self.assertEqual(msg_log.get('subject'), correct_tpl.get('subject') + ' - Sequent')
        self.assertEqual(1, msg_log.get('msg').count(' -- Sequent https://sequentech.io'))
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
        response = c.authenticate(self.aeid, test_data.auth_email_default)
        ae.status = 'stopped'
        ae.save()
        response = c.post('/api/auth-event/%d/census/send_auth/' % self.aeid, tpl_specific)
        self.assertEqual(response.status_code, 200)

        ae.status = 'notstarted'
        ae.save()
        response = c.post('/api/auth-event/%d/census/send_auth/' % self.aeid, tpl_specific)
        self.assertEqual(response.status_code, 200)

    def _test_unique_field(self):
        self.ae.extra_fields = test_data.extra_field_unique
        self.ae.save()

        c = JClient()
        response = c.authenticate(0, test_data.admin)
        self.assertEqual(response.status_code, 200)

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
        response = c.authenticate(0, test_data.admin)
        self.assertEqual(response.status_code, 200)

        response = c.authenticate(self.aeid, test_data.auth_email_default)
        self.assertEqual(response.status_code, 200)

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
        ae = AuthEvent(
            auth_method="sms",
            extra_fields=test_data.ae_sms_default['extra_fields'],
            auth_method_config=test_data.authmethod_config_sms_default,
            status='started',
            census="open"
        )
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
        response = c.authenticate(self.aeid, test_data.auth_sms_default)
        self.assertEqual(response.status_code, 200)

        response = c.census(self.aeid, test_data.census_sms_default)
        self.assertEqual(response.status_code, 200)

    def test_add_census_authevent_sms_fields(self):
        c = JClient()
        response = c.authenticate(self.aeid, test_data.auth_sms_default)
        self.assertEqual(response.status_code, 200)

        response = c.census(self.aeid, test_data.census_sms_fields)
        self.assertEqual(response.status_code, 200)

    def _test_add_census_authevent_sms_repeat(self):
        c = JClient()
        response = c.authenticate(self.aeid, test_data.auth_sms_default)
        self.assertEqual(response.status_code, 200)

        response = c.census(self.aeid, test_data.census_sms_repeat)
        self.assertEqual(response.status_code, 400)
        r = parse_json_response(response)
        self.assertEqual(r['error_codename'], 'invalid_credentials')

    def _test_add_used_census(self):
        c = JClient()
        response = c.authenticate(0, test_data.admin)
        self.assertEqual(response.status_code, 200)

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
        response = c.authenticate(0, test_data.admin)
        self.assertEqual(response.status_code, 200)

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
        self.assertEqual(r['error_codename'], 'INVALID_REQUEST')

        # good: self.aeid.census = close but allow_user_resend = True
        self.ae.auth_method_config['config']['allow_user_resend'] = True
        self.ae.save()
        response = c.post('/api/auth-event/%d/resend_auth_code/' % self.aeid, data)
        r = parse_json_response(response)
        self.assertEqual(response.status_code, 200)

        # bad: status != started
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
        code = get_user_code(self.u.user)

        credentials = dict(
            tlf=self.u.tlf,
            code=code.code
        )

        response = c.authenticate(self.aeid, credentials)
        self.assertEqual(response.status_code, 200)

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
        response = c.authenticate(0, test_data.admin)
        self.assertEqual(response.status_code, 200)

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
        self.assertEqual(r['error_codename'], ErrorCodes.INVALID_CODE)

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
        
        self.assertEqual(MsgLog.objects.count(), 0)
        c = JClient()
        response = c.authenticate(self.aeid, test_data.auth_sms_default)
        response = c.post('/api/auth-event/%d/census/send_auth/' % self.aeid, {})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(MsgLog.objects.count(), 4)
        msg_log = MsgLog.objects.all().last().msg
        self.assertTrue(msg_log.get('msg').count('-- Sequent'))

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
        response = c.authenticate(0, test_data.admin)
        self.assertEqual(response.status_code, 200)

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
        response = c.authenticate(0, test_data.admin)
        self.assertEqual(response.status_code, 200)

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


class TestFillIfEmptyOnRegistration(TestCase):
    def setUpTestData():
        flush_db_load_fixture()

    def setUp(self):
        from authmethods.m_email import Email
        auth_method_config = {
                "config": Email.CONFIG,
                "pipeline": Email.PIPELINES
        }
        auth_event = AuthEvent(
            auth_method=test_data.auth_event9['auth_method'],
            extra_fields=copy.deepcopy(test_data.auth_event9['extra_fields']),
            auth_method_config=auth_method_config,
            status='started',
            census=test_data.auth_event9['census']
        )
        auth_event.save()
        self.auth_event = auth_event

        admin_user = User(
            username=test_data.admin['username'],
            email=test_data.admin['email']
        )
        admin_user.set_password(test_data.admin['password'])
        admin_user.save()
        admin_user.userdata.event = AuthEvent\
            .objects\
            .get(pk=settings.ADMIN_AUTH_ID)
        admin_user.userdata.save()
        self.admin_user = admin_user
        self.uid_admin = admin_user.id

        admin_acl = ACL(
            user=admin_user.userdata,
            object_type='AuthEvent',
            perm='edit',
            object_id=self.auth_event.id
        )
        admin_acl.save()
        self.admin_acl = admin_acl

        self.admin_auth_data = dict(
            email=admin_user.email,
            code="ERGERG"
        )
        code = Code(
            user=admin_user.userdata,
            code=self.admin_auth_data['code'],
            auth_event_id=settings.ADMIN_AUTH_ID
        )
        code.save()

        # test user has email unset
        test_user = User(username='test')
        test_user.save()
        test_user.userdata.event = auth_event
        test_user.userdata.metadata = {
            'match_field': 'match_code_555'
        }
        test_user.userdata.save()
        self.test_user = test_user.userdata
        self.test_user_id = test_user.id

    def test_voter_register(self):
        '''
        Register a pre-registered voter
        '''
        c = JClient()
        voter_registration_data = dict(
            email='test-6578752@test.com',
            match_field='match_code_555'
        )

        # Before registration, the voter has no email
        self.assertEqual(
            User.objects.get(pk=self.test_user_id).email,
            ""
        )

        response = c.register(self.auth_event.id, voter_registration_data)
        self.assertEqual(response.status_code, 200)

        # now user should be registered with the new email
        self.assertEqual(
            User.objects.get(pk=self.test_user_id).email,
            voter_registration_data['email']
        )

    def test_voter_reset_email(self):
        '''
        Reset user should work as expected for email field
        '''
        c = JClient()
        # assign an email to the voter
        test_user = User.objects.get(pk=self.test_user_id)
        test_user.email = "example@example.com"
        test_user.save()

        # login as admin and reset this voter
        response = c.authenticate(settings.ADMIN_AUTH_ID, self.admin_auth_data)
        self.assertEqual(response.status_code, 200)

        response = c.post(
            '/api/auth-event/%d/census/reset-voter/' % self.auth_event.id,
            {
                "user-ids": [self.test_user_id]
            }
        )
        self.assertEqual(response.status_code, 200)

        # now user should have email reset
        self.assertEqual(User.objects.get(pk=self.test_user_id).email, '')

    def test_voter_reset_activity(self):
        '''
        Check that voter reset triggers the creation of an action
        '''
        # check the action is not registered at first
        self.assertEqual(
            Action.objects.filter(
                executer__id=self.admin_user.id,
                receiver__id=self.test_user_id,
                action_name='user:reset-voter',
                event=self.auth_event.id,
                metadata__comment="some comment"
            ).count(),
            0
        )

        # login as admin and reset the voter
        c = JClient()
        response = c.authenticate(settings.ADMIN_AUTH_ID, self.admin_auth_data)
        self.assertEqual(response.status_code, 200)

        response = c.post(
            '/api/auth-event/%d/census/reset-voter/' % self.auth_event.id,
            {
                "user-ids": [self.test_user_id],
                "comment": "some comment"
            }
        )
        self.assertEqual(response.status_code, 200)

        # check the action was created
        self.assertEqual(
            Action.objects.filter(
                executer__id=self.admin_user.id,
                receiver__id=self.test_user_id,
                action_name='user:reset-voter',
                event=self.auth_event.id,
                metadata__comment="some comment"
            ).count(),
            1
        )

    def test_voter_reset_metadata(self):
        '''
        Reset user should work as expected for metadata normal fields
        '''
        self.auth_event.extra_fields[0]['name'] = 'whatever'
        self.auth_event.extra_fields[0]['type'] = 'text'
        self.auth_event.save()

        c = JClient()
        # assign data to the whatever metadata and email fields
        test_user = User.objects.get(pk=self.test_user_id)
        test_user.userdata.metadata['whatever'] = "some data"
        test_user.userdata.save()
        test_user.email = "some@email.com"
        test_user.save()

        # login as admin and reset this voter
        response = c.authenticate(settings.ADMIN_AUTH_ID, self.admin_auth_data)
        self.assertEqual(response.status_code, 200)
        response = c.post(
            '/api/auth-event/%d/census/reset-voter/' % self.auth_event.id,
            {
                "user-ids": [self.test_user_id]
            }
        )
        self.assertEqual(response.status_code, 200)

        # now user should have the whatever field reset (but not the email)
        self.assertTrue(
            'whatever' not in User\
                .objects\
                .get(pk=self.test_user_id)\
                .userdata\
                .metadata
        )
        self.assertEqual(
            User.objects.get(pk=self.test_user_id).email,
            'some@email.com'
        )

    def test_voter_reset_tlf(self):
        '''
        Reset user should work as expected for tlf field
        '''
        self.auth_event.extra_fields[0]['name'] = 'tlf'
        self.auth_event.extra_fields[0]['type'] = 'tlf'
        self.auth_event.save()

        c = JClient()
        # assign telephone to user
        test_user = User.objects.get(pk=self.test_user_id)
        test_user.userdata.tlf = "+34123456789"
        test_user.userdata.save()

        # login as admin and reset this voter
        response = c.authenticate(settings.ADMIN_AUTH_ID, self.admin_auth_data)
        self.assertEqual(response.status_code, 200)
        response = c.post(
            '/api/auth-event/%d/census/reset-voter/' % self.auth_event.id,
            {
                "user-ids": [self.test_user_id]
            }
        )
        self.assertEqual(response.status_code, 200)

        # now user should have the tlf field reset
        self.assertEqual(
            User\
                .objects\
                .get(pk=self.test_user_id)\
                .userdata\
                .tlf, 
            ''
        )

    def test_voter_reset_no_fill(self):
        '''
        Reset user should work as expected when no field is set as 
        fill_if_empty_on_registration
        '''
        self.auth_event.extra_fields[0]['fill_if_empty_on_registration'] = False
        self.auth_event.save()

        c = JClient()
        # assign an email to the voter
        test_user = User.objects.get(pk=self.test_user_id)
        test_user.email = "example@example.com"
        test_user.save()

        # login as admin and reset this voter
        response = c.authenticate(settings.ADMIN_AUTH_ID, self.admin_auth_data)
        self.assertEqual(response.status_code, 200)
        response = c.post(
            '/api/auth-event/%d/census/reset-voter/' % self.auth_event.id,
            {
                "user-ids": [self.test_user_id]
            }
        )
        self.assertEqual(response.status_code, 200)

        # now user should still have the email field not reset
        self.assertEqual(
            User\
                .objects\
                .get(pk=self.test_user_id)\
                .email, 
            "example@example.com"
        )

    def test_voter_reset_bad_data1(self):
        '''
        Reset user should detect missing user_ids field
        '''
        # login as admin and try reset this voter
        c = JClient()
        response = c.authenticate(settings.ADMIN_AUTH_ID, self.admin_auth_data)
        self.assertEqual(response.status_code, 200)
        response = c.post(
            '/api/auth-event/%d/census/reset-voter/' % self.auth_event.id,
            {
                # this is wrong, the field should be "user-ids"
                "user_ids": [self.test_user_id]
            }
        )
        self.assertEqual(response.status_code, 400)

    def test_voter_reset_perms_alt(self):
        '''
        Reset user should work with reset-voter perms
        '''
        # change the admin perms to reset-voter
        self.admin_acl.perm = 'reset-voter'
        self.admin_acl.save()

        # login as admin and try reset this voter
        c = JClient()
        response = c.authenticate(settings.ADMIN_AUTH_ID, self.admin_auth_data)
        self.assertEqual(response.status_code, 200)
        response = c.post(
            '/api/auth-event/%d/census/reset-voter/' % self.auth_event.id,
            {
                "user-ids": [self.test_user_id]
            }
        )
        self.assertEqual(response.status_code, 200)

    def test_voter_reset_perms_invalid(self):
        '''
        Reset user should fail if the admin doesn't have perms
        '''
        # change the admin perms to reset-voter
        self.admin_acl.perm = 'reset-voter-invalid-perm'
        self.admin_acl.save()

        # login as admin and try reset this voter
        c = JClient()
        response = c.authenticate(settings.ADMIN_AUTH_ID, self.admin_auth_data)
        self.assertEqual(response.status_code, 200)
        response = c.post(
            '/api/auth-event/%d/census/reset-voter/' % self.auth_event.id,
            {
                "user-ids": [self.test_user_id]
            }
        )
        self.assertEqual(response.status_code, 403)

    def test_voter_reset_invalid_voter_data(self):
        '''
        Reset user should fail if the voter doesn't exist in this election
        '''
        # login as admin and try reset this voter
        c = JClient()
        response = c.authenticate(settings.ADMIN_AUTH_ID, self.admin_auth_data)
        self.assertEqual(response.status_code, 200)
        response = c.post(
            '/api/auth-event/%d/census/reset-voter/' % self.auth_event.id,
            {
                "user-ids": [100101]
            }
        )
        self.assertEqual(response.status_code, 404)

    def test_voter_reset_voter_already_voted(self):
        '''
        Reset user should fail if the voter has already voted
        '''
        # register vote
        vote = SuccessfulLogin(
            created=datetime(2010, 10, 10, 0, 30, 30, 0, None),
            user=self.test_user,
            auth_event=self.auth_event,
            is_active=True
        )
        vote.save()

        # login as admin and try reset this voter
        c = JClient()
        response = c.authenticate(settings.ADMIN_AUTH_ID, self.admin_auth_data)
        self.assertEqual(response.status_code, 200)

        response = c.post(
            '/api/auth-event/%d/census/reset-voter/' % self.auth_event.id,
            {
                "user-ids": [self.test_user_id]
            }
        )
        # should fail because there's a vote for this election
        self.assertEqual(response.status_code, 400)


class TestSmallCensusSearch(TestCase):
    def setUpTestData():
        flush_db_load_fixture()

    def setUp(self):
        from authmethods.m_email import Email
        auth_method_config = {
                "config": Email.CONFIG,
                "pipeline": Email.PIPELINES
        }
        ae = AuthEvent(
            auth_method=test_data.auth_event9['auth_method'],
            extra_fields=test_data.auth_event9['extra_fields'],
            auth_method_config=auth_method_config,
            status='started',
            census=test_data.auth_event9['census']
        )
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
        self.assertEqual(res_auth.status_code, 200)
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
        ae = AuthEvent(
            auth_method=test_data.auth_event12['auth_method'],
            extra_fields=test_data.auth_event12['extra_fields'],
            auth_method_config=auth_method_config,
            status='started', 
            census=test_data.auth_event12['census']
        )
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
        self.assertEqual(res_auth.status_code, 200)

        data = test_data.auth_event13
        response = c.post('/api/auth-event/', data)
        self.assertEqual(response.status_code, 200)
        r = parse_json_response(response)
        self.assertTrue('id' in  r and isinstance(r['id'], int))
        auth_id = r['id']
        response = c.get('/api/auth-event/%d/' % auth_id, data)
        r = parse_json_response(response)
        self.assertTrue('events' in r and 'extra_fields' in r['events'])
        self.assertEqual(2, len(r['events']['extra_fields']))
        self.assertTrue('slug' in r['events']['extra_fields'][1])
        self.assertEqual("NO_DE__SOCIO", r['events']['extra_fields'][1]['slug'])


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

        ae = AuthEvent(
            auth_method=test_data.auth_event12['auth_method'],
            extra_fields=test_data.auth_event12['extra_fields'],
            auth_method_config=auth_method_config,
            status='started',
            census=test_data.auth_event12['census']
        )
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
        ae = AuthEvent(
            auth_method="email",
            extra_fields=test_data.ae_email_default['extra_fields'],
            auth_method_config=test_data.authmethod_config_email_default,
            status='started',
            census="open"
        )
        ae.save()
        self.ae = ae
        self.aeid = ae.pk

        u = User(username='test', email=test_data.auth_email_default['email'])
        u.save()
        u.userdata.event = ae
        u.userdata.save()
        self.u = u.userdata
        self.uid = u.id

    def generate_access_token_hmac(self, key, msg):
        import hmac

        if not key or not msg:
           return

        timestamp = int(timezone.now().timestamp())
        validity = 120
        expiry_timestamp = timestamp + validity
        msg = "%s:%s:%s:%s" % (msg, str(expiry_timestamp), "timeout-token", str(timestamp))

        h = hmac.new(key, msg.encode('utf-8'), "sha256")
        return 'khmac:///sha-256;' + h.hexdigest() + '/' + msg

    @override_settings(**override_celery_data)
    def test_callback(self):
        c = JClient()
        timed_auth = "test:AuthEvent:%d:Callback" % self.aeid
        hmac = self.generate_access_token_hmac(settings.SHARED_SECRET, timed_auth)
        c.set_auth_token(hmac)
        response = c.post('/api/auth-event/%d/callback/' % self.aeid, {})
        self.assertEqual(response.status_code, 200)
        # check the action was created
        action = Action.objects.get(executer__id=self.uid)
        self.assertEqual(action.action_name, "authevent:callback")

        response = c.authenticate(self.aeid, test_data.auth_email_default)
        response = c.post('/api/auth-event/%d/callback/' % self.aeid, {})
        self.assertEqual(response.status_code, 403)


class TestVoteStats(TestCase):
    def setUpTestData():
        flush_db_load_fixture()

    def setUp(self):
        from datetime import datetime, timedelta

        auth_event = AuthEvent(
            auth_method="email",
            extra_fields=test_data.ae_email_default['extra_fields'],
            auth_method_config=test_data.authmethod_config_email_default,
            status='started',
            census="open"
        )
        auth_event.save()
        self.auth_event = auth_event
        self.auth_event_id = auth_event.pk
        self.aeid_special = 1

        admin = User(
            username=test_data.admin['username'], 
            email=test_data.admin['email']
        )
        admin.set_password(test_data.admin['password'])
        admin.save()
        admin.userdata.event = AuthEvent.objects.get(pk=self.aeid_special)
        admin.userdata.save()
        self.uid_admin = admin.id
        
        self.admin_auth_data = dict(
            email=test_data.admin['email'],
            code="ERGERG")
        
        c = Code(
            user=admin.userdata,
            code=self.admin_auth_data['code'],
            auth_event_id=self.aeid_special)
        c.save()

        acl = ACL(
            user=admin.userdata, 
            object_type='AuthEvent', 
            perm='edit',
            object_id=self.auth_event_id
        )
        acl.save()

        # convenience methods to create users and vote data

        def new_user(name):
            user = User(
                username=name, 
                email=test_data.auth_email_default['email']
            )
            user.save()
            user.userdata.event = auth_event
            user.userdata.save()
            return user

        def add_vote(user, date):
            vote = SuccessfulLogin(
                created=date,
                user=user.userdata,
                auth_event=auth_event
            )
            vote.save()
            return vote

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
            user = new_user("user%s" % i)
            add_vote(user, date)
            self.users.append(user)

        # in the second hour we have 3 votes
        date = date + timedelta(hours=1)
        for i in range(4, 7):
            user = new_user("user%s" % i)
            add_vote(user, date)

        # here we cast votes for the same users as in the first hour,
        # effectively invalidating them
        # the third hour slice will therefore have 4 votes
        date = date + timedelta(hours=1)
        for i in range(0, 4):
            add_vote(self.users[i], date)

        # in the third hour we have 5 votes
        date = date + timedelta(hours=1)
        for i in range(7, 12):
            user = new_user("user%s" % i)
            add_vote(user, date)

    @override_settings(**override_celery_data)
    def test_vote_stats(self):
        client = JClient()
        response = client.authenticate(
            self.aeid_special, 
            self.admin_auth_data
        )
        self.assertEqual(response.status_code, 200)

        response = client.get(
            '/api/auth-event/%d/vote-stats/' % self.auth_event_id, 
            {}
        )
        self.assertEqual(response.status_code, 200)
    
        # the expected response should be:
        # 0 votes in  hour 0 (no data)
        # 3 votes in hour 1
        # 4 votes in hour 2
        # 5 votes in hour 3
        
        self.assertEqual(
            reproducible_json_dumps(parse_json_response(response)),
            reproducible_json_dumps({
                "total_votes": 12, 
                "votes_per_hour": [
                    {"hour": "2010-10-10 01:00:00+00:00", "votes": 3}, 
                    {"hour": "2010-10-10 02:00:00+00:00", "votes": 4}, 
                    {"hour": "2010-10-10 03:00:00+00:00", "votes": 5}
                ]
            })
        )
            

# Check the allowed number of revotes, using AuthEvent's
# num_successful_logins_allowed field and calls to successful_login
class TestRevotes(TestCase):
    def setUpTestData():
        flush_db_load_fixture()

    def generate_access_token_hmac(self, key, msg):
        import hmac
        import datetime
        timestamp = int(timezone.now().timestamp())
        validity = 120
        expiry_timestamp = timestamp + validity
        msg = "%s:%s:%s:%s" % (msg, str(expiry_timestamp), "timeout-token", str(timestamp))

        h = hmac.new(key, msg.encode('utf-8'), "sha256")
        return 'khmac:///sha-256;' + h.hexdigest() + '/' + msg

    def setUp(self):
        ae = AuthEvent(
            auth_method="email",
            extra_fields=test_data.ae_email_default['extra_fields'],
            auth_method_config=test_data.authmethod_config_email_default,
            status='started',
            census="open",
            num_successful_logins_allowed=0
        )
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
        response = c.authenticate(self.aeid, test_data.auth_email_default)
        self.assertEqual(response.status_code, 200)

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
        auth_token = self.generate_access_token_hmac(settings.SHARED_SECRET, "%s:AuthEvent:%d:RegisterSuccessfulLogin" % (cuser.username, self.aeid))
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
        auth_token = self.generate_access_token_hmac(settings.SHARED_SECRET, "%s:AuthEvent:%d:RegisterSuccessfulLogin" % (cuser.username, self.aeid))
        c.set_auth_token(auth_token)
        response = c.post('/api/auth-event/%d/successful_login/%s' % (self.aeid, cuser.username), {})
        self.assertEqual(response.status_code, 200)
        response = c.authenticate(self.aeid, test_data.auth_email_default1)
        self.assertEqual(response.status_code, 400)

    def test_check_50_revotes_max(self):
        c = JClient()
        response = c.authenticate(self.aeid, test_data.auth_email_default)
        self.assertEqual(response.status_code, 200)

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
            auth_token = self.generate_access_token_hmac(settings.SHARED_SECRET, "%s:AuthEvent:%d:RegisterSuccessfulLogin" % (cuser.username, self.aeid))
            c.set_auth_token(auth_token)
            response = c.post('/api/auth-event/%d/successful_login/%s' % (self.aeid, cuser.username), {})

        response = c.authenticate(self.aeid, test_data.auth_email_default1)
        self.assertEqual(response.status_code, 400)

class TestAdminFields(TestCase):
    def setUpTestData():
        flush_db_load_fixture()

    def setUp(self):
        self.ae = AuthEvent(
            auth_method=test_data.auth_event4['auth_method'],
            extra_fields=test_data.auth_event4['extra_fields'],
            auth_method_config=test_data.authmethod_config_email_default
        )
        self.ae.save()

        self.aeid_special = 1
        u = User(username=test_data.admin['username'], email=test_data.admin['email'])
        u.set_password(test_data.admin['password'])
        u.save()
        u.userdata.event = AuthEvent.objects.get(pk=1)
        u.userdata.save()
        self.user = u

        self.admin_auth_data = dict(
            email=test_data.admin['email'],
            code="ERGERG")
        c = Code(
            user=self.user.userdata,
            code=self.admin_auth_data['code'],
            auth_event_id=self.aeid_special)
        c.save()

        u2 = User(username='noperm', email="noperm@sequentech.io")
        u2.set_password("qwerty")
        u2.save()
        u2.userdata.save()

    @override_settings(**override_celery_data)
    def create_authevent(self, authevent):
        c = JClient()

        response = c.authenticate(self.aeid_special, self.admin_auth_data)
        self.assertEqual(response.status_code, 200)

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

        # Override the pipeline max time to avoid ip blacklist
        self.sms_otp_pipeline = m_sms_otp.SmsOtp.PIPELINES["resend-auth-pipeline"]
        m_sms_otp.SmsOtp.PIPELINES["resend-auth-pipeline"] = [
            ["check_whitelisted", {"field": "tlf"}],
            ["check_whitelisted", {"field": "ip"}],
            ["check_blacklisted", {"field": "ip"}],
            ["check_blacklisted", {"field": "tlf"}],
            ["check_total_max", {"field": "ip", "period": 3600*24, "max": 20}],
            ["check_total_max", {"field": "tlf", "period": 3600*24, "max": 20}]
        ]

    def tearDown(self):
        m_sms_otp.SmsOtp.PIPELINES["resend-auth-pipeline"] = self.sms_otp_pipeline

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
        user = User.objects.get(email=data['email'], is_active=True)
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
        ae.extra_fields = [
            {
                "name": "tlf",
                "type": "tlf", 
                "required": True,
                "unique": True,
                "min": 4,
                "max": 20,
                "required_on_authentication": True
            }
        ]
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
        user = User.objects.get(userdata__tlf=data['tlf'], userdata__event=ae, is_active=True)
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
        ae.extra_fields = [
            {
                "name": "tlf",
                "type": "tlf", 
                "required": True,
                "unique": True,
                "min": 4,
                "max": 20,
                "required_on_authentication": True
            }
        ]
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
        user = User.objects.get(userdata__tlf=data['tlf'], userdata__event=ae, is_active=True)
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


class ApiTestCensusDelete(TestCase):
    def setUpTestData():
        flush_db_load_fixture()

    def setUp(self):
        # main election to test
        auth_event = AuthEvent(
            auth_method="email",
            auth_method_config=test_data.authmethod_config_email_default,
            extra_fields=test_data.ae_email_default['extra_fields'],
            status='started',
            census="open",
            num_successful_logins_allowed = 1
        )
        auth_event.save()
        self.auth_event = auth_event
        self.auth_event_id = auth_event.pk

        # admin user
        admin_user = User(
            username=test_data.admin['username'], 
            email=test_data.admin['email']
        )
        admin_user.set_password(test_data.admin['password'])
        admin_user.save()
        admin_user.userdata.event = auth_event
        admin_user.userdata.save()
        self.admin_user_id = admin_user.id
        self.admin_user = admin_user

        # admin user credentials
        self.admin_auth_data = dict(
            email=test_data.admin['email'],
            code="ERGERG"
        )
        census_user_code = Code(
            user=admin_user.userdata,
            code=self.admin_auth_data['code'],
            auth_event_id=1
        )
        census_user_code.save()

        # admin user election edit permission
        acl = ACL(
            user=admin_user.userdata,
            object_type='AuthEvent',
            perm='edit',
            object_id=self.auth_event_id
        )
        acl.save()
        self.acl_edit_event = acl

        # election view events permission
        acl = ACL(
            user=admin_user.userdata,
            object_type='AuthEvent',
            perm='event-view-activity',
            object_id=self.auth_event_id
        )
        acl.save()
        self.acl_activity1 = acl

        # census user
        census_user = User(
            username='test',
            email=test_data.auth_email_default['email']
        )
        census_user.save()
        census_user.userdata.event = auth_event
        census_user.userdata.save()
        self.census_user = census_user.userdata
        self.census_user_id = census_user.id

        # census user credentials
        census_user_code = Code(
            user=census_user.userdata,
            code=test_data.auth_email_default['code'], 
            auth_event_id=auth_event.pk
        )
        census_user_code.save()
        self.census_user_code = census_user_code

    @override_settings(**override_celery_data)
    def test_census_delete_fail1(self):
        c = JClient()

        # voter can authenticate
        response = c.authenticate(
            self.auth_event_id,
            test_data.auth_email_default
        )
        self.assertEqual(response.status_code, 200)

        # admin login
        response = c.authenticate(self.auth_event_id, self.admin_auth_data)
        self.assertEqual(response.status_code, 200)

        # admin can list activity and log has only auth events
        response = c.get(
            '/api/auth-event/%d/activity/' % self.auth_event_id,
            {}
        )
        self.assertEqual(response.status_code, 200)
        r = parse_json_response(response)
        self.assertEqual(len(r['activity']), 2)

        # admin without permission tries to delete the voter
        self.acl_edit_event.perm = 'no-perm'
        self.acl_edit_event.save()
        data = {
            'user-ids': [self.census_user_id],
            'comment': 'some comment here'
        }
        response = c.post(
            '/api/auth-event/%d/census/delete/' % self.auth_event_id,
            data
        )
        self.assertEqual(response.status_code, 403)

    @override_settings(**override_celery_data)
    def test_census_delete_fail2(self):
        c = JClient()

        # voter can authenticate
        response = c.authenticate(
            self.auth_event_id,
            test_data.auth_email_default
        )
        self.assertEqual(response.status_code, 200)

        # admin login
        response = c.authenticate(self.auth_event_id, self.admin_auth_data)
        self.assertEqual(response.status_code, 200)

        # admin can list activity and log has only auth events
        response = c.get(
            '/api/auth-event/%d/activity/' % self.auth_event_id, 
            {}
        )
        self.assertEqual(response.status_code, 200)
        r = parse_json_response(response)
        self.assertEqual(len(r['activity']), 2)

        # admin with census-delete permission tries to delete the voter, but the
        # voter has voted so it's denied because the admin doesn't has the 
        # census-delete-voted permission
        self.acl_edit_event.perm = 'census-delete'
        self.acl_edit_event.save()
        successful_login = SuccessfulLogin(
            user=self.census_user,
            auth_event_id=self.auth_event_id
        )
        successful_login.save()
        data = {
            'user-ids': [self.census_user_id],
            'comment': 'some comment here'
        }
        response = c.post(
            '/api/auth-event/%d/census/delete/' % self.auth_event_id,
            data
        )
        self.assertEqual(response.status_code, 403)

    @override_settings(**override_celery_data)
    def test_census_delete_ok(self):
        c = JClient()

        # voter can authenticate
        response = c.authenticate(
            self.auth_event_id, 
            test_data.auth_email_default
        )
        self.assertEqual(response.status_code, 200)

        # admin login
        response = c.authenticate(self.auth_event_id, self.admin_auth_data)
        self.assertEqual(response.status_code, 200)

        # admin can list activity and log has only auth events
        response = c.get(
            '/api/auth-event/%d/activity/' % self.auth_event_id,
            {}
        )
        self.assertEqual(response.status_code, 200)
        r = parse_json_response(response)
        self.assertEqual(len(r['activity']), 2)

        # admin with census-delete permission tries to delete the voter and it
        # works
        self.acl_edit_event.perm = 'census-delete'
        self.acl_edit_event.save()
        data = {
            'user-ids': [self.census_user_id],
            'comment': 'some comment here'
        }
        response = c.post(
            '/api/auth-event/%d/census/delete/' % self.auth_event_id,
            data
        )
        self.assertEqual(response.status_code, 200)

        ## check that the delete was logged properly
        response = c.get(
            '/api/auth-event/%d/activity/' % self.auth_event_id,
            {}
        )
        self.assertEqual(response.status_code, 200)
        r = parse_json_response(response)
        # a previous entry related to the voter was deleted, so the total number
        # of actions remains the same
        self.assertEqual(len(r['activity']), 2)
        self.assertEqual(r['activity'][0]['executer_id'], self.admin_user_id)
        self.assertEqual(r['activity'][0]['executer_username'], 'john')
        self.assertEqual(
            r['activity'][0]['executer_email'],
            'john@sequentech.io'
        )
        self.assertEqual(
            r['activity'][0]['action_name'],
            'user:deleted-from-census'
        )
        self.assertEqual(
            r['activity'][0]['metadata']['comment'],
            data['comment']
        )
        self.assertEqual(
            r['activity'][0]['metadata']['_id'],
            self.census_user_id
        )
        self.assertEqual(r['activity'][0]['metadata']['_username'], 'test')
        self.assertEqual(r['activity'][0]['metadata']['email'], 'aaaa@aaa.com')

        # voter cannot authenticate
        response = c.authenticate(
            self.auth_event_id,
            test_data.auth_email_default
        )
        self.assertEqual(response.status_code, 400)
        r = parse_json_response(response)
        self.assertEqual(r['error_codename'], ErrorCodes.USER_NOT_FOUND)

        # voter does not exist in database anymore
        self.assertEqual(User.objects.filter(id=self.census_user_id).count(), 0)

    @override_settings(**override_celery_data)
    def test_census_delete_voted_ok(self):
        c = JClient()

        # voter can authenticate
        response = c.authenticate(
            self.auth_event_id, 
            test_data.auth_email_default
        )
        self.assertEqual(response.status_code, 200)

        # admin login
        response = c.authenticate(self.auth_event_id, self.admin_auth_data)
        self.assertEqual(response.status_code, 200)

        # admin can list activity and log has only auth events
        response = c.get(
            '/api/auth-event/%d/activity/' % self.auth_event_id,
            {}
        )
        self.assertEqual(response.status_code, 200)
        r = parse_json_response(response)
        self.assertEqual(len(r['activity']), 2)

        # admin with census-delete permission tries to delete the voter and it
        # works
        voted_acl = ACL(
            user=self.admin_user.userdata,
            object_type='AuthEvent',
            perm='census-delete-voted',
            object_id=self.auth_event_id
        )
        voted_acl.save()
        
        self.acl_edit_event.perm = 'census-delete'
        self.acl_edit_event.save()

        successful_login = SuccessfulLogin(
            user=self.census_user,
            auth_event_id=self.auth_event_id
        )
        successful_login.save()
        
        data = {
            'user-ids': [self.census_user_id],
            'comment': 'some comment here'
        }
        response = c.post(
            '/api/auth-event/%d/census/delete/' % self.auth_event_id,
            data
        )
        self.assertEqual(response.status_code, 200)

        ## check that the delete was logged properly
        response = c.get(
            '/api/auth-event/%d/activity/' % self.auth_event_id,
            {}
        )
        self.assertEqual(response.status_code, 200)
        r = parse_json_response(response)
        # a previous entry related to the voter was deleted, so the total number
        # of actions remains the same
        self.assertEqual(len(r['activity']), 2)
        self.assertEqual(r['activity'][0]['executer_id'], self.admin_user_id)
        self.assertEqual(r['activity'][0]['executer_username'], 'john')
        self.assertEqual(
            r['activity'][0]['executer_email'],
            'john@sequentech.io'
        )
        self.assertEqual(
            r['activity'][0]['action_name'],
            'user:deleted-voted-from-census'
        )
        self.assertEqual(
            r['activity'][0]['metadata']['comment'],
            data['comment']
        )
        self.assertEqual(
            r['activity'][0]['metadata']['_id'],
            self.census_user_id
        )
        self.assertEqual(r['activity'][0]['metadata']['_username'], 'test')
        self.assertEqual(r['activity'][0]['metadata']['email'], 'aaaa@aaa.com')

        # voter cannot authenticate
        response = c.authenticate(
            self.auth_event_id,
            test_data.auth_email_default
        )
        self.assertEqual(response.status_code, 400)
        r = parse_json_response(response)
        self.assertEqual(r['error_codename'], ErrorCodes.USER_NOT_FOUND)

        # voter does not exist in database anymore
        self.assertEqual(User.objects.filter(id=self.census_user_id).count(), 0)


class ApiTestActivationAndActivity(TestCase):
    def setUpTestData():
        flush_db_load_fixture()

    def setUp(self):
        ae = AuthEvent(
            auth_method="email",
            auth_method_config=test_data.authmethod_config_email_default,
            extra_fields=test_data.ae_email_default['extra_fields'],
            status='started',
            census="open",
            num_successful_logins_allowed = 1
        )
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

        # admin can list activity and log has only auth events
        response = c.get('/api/auth-event/%d/activity/' % self.aeid, {})
        self.assertEqual(response.status_code, 200)
        r = parse_json_response(response)
        self.assertEqual(len(r['activity']), 2)

        # admin deactivates voter
        self.assertEqual(response.status_code, 200)
        data = {'user-ids': [self.uid], 'comment': 'some comment here'}
        response = c.post('/api/auth-event/%d/census/deactivate/' % self.aeid, data)
        self.assertEqual(response.status_code, 200)

        ## check that the deactivation was logged properly
        response = c.get('/api/auth-event/%d/activity/' % self.aeid, {})
        self.assertEqual(response.status_code, 200)
        r = parse_json_response(response)
        self.assertEqual(len(r['activity']), 3)
        self.assertEqual(r['activity'][0]['executer_id'], self.uid_admin)
        self.assertEqual(r['activity'][0]['executer_username'], 'john')
        self.assertEqual(r['activity'][0]['executer_email'], 'john@sequentech.io')
        self.assertEqual(r['activity'][0]['receiver_id'], self.uid)
        self.assertEqual(r['activity'][0]['receiver_username'], 'test')
        self.assertEqual(r['activity'][0]['receiver_email'], 'aaaa@aaa.com')
        self.assertEqual(r['activity'][0]['action_name'], 'user:deactivate')
        self.assertEqual(r['activity'][0]['metadata']['comment'], data['comment'])

        # voter cannot authenticate
        response = c.authenticate(self.aeid, test_data.auth_email_default)
        self.assertEqual(response.status_code, 400)
        r = parse_json_response(response)
        self.assertEqual(r['error_codename'], ErrorCodes.USER_NOT_FOUND)

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
        self.assertEqual(len(r['activity']), 5)
        self.assertEqual(r['activity'][0]['executer_id'], self.uid_admin)
        self.assertEqual(r['activity'][0]['executer_username'], 'john')
        self.assertEqual(r['activity'][0]['receiver_id'], self.uid)
        self.assertEqual(r['activity'][0]['receiver_username'], 'test')
        self.assertEqual(r['activity'][0]['action_name'], 'user:activate')
        self.assertEqual(r['activity'][0]['metadata']['comment'], data['comment'])

        # check that removing permission works as expected
        self.acl_activity1.delete()
        self.acl_edit_event.delete()
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

        def check_activity(
            response, 
            action='user:activate', 
            l=3, 
            status=200, 
            receiver=self.uid,
            receiver_username='test',
            verify_comment=True):
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
            self.assertEqual(r['activity'][0]['receiver_id'], receiver)
            self.assertEqual(r['activity'][0]['receiver_username'], receiver_username)
            self.assertEqual(r['activity'][0]['action_name'], action)
            if verify_comment:
                self.assertEqual(r['activity'][0]['metadata']['comment'], data['comment'])

        ## check input parameters filtering and validation
        path = '/api/auth-event/%d/activity/' % self.aeid
        
        # check filtering by executer_id
        response = c.get(path + '?executer_id=%d' % self.uid_admin, {})
        check_activity(response)
        # check filtering by receiver_id
        response = c.get(path + '?receiver_id=%d' % self.uid_admin, {})
        check_activity(
            response, 
            l=1, 
            receiver=self.uid_admin, 
            receiver_username='john',
            action="user:authenticate", 
            verify_comment=False)
        response = c.get(path + '?receiver_id=%d' % self.uid, {})
        check_activity(response, l=2)

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
        check_activity(response, l=2)

        # check filtering with multiple actions, with one action not registered
        response = c.get(path + '?actions=user:activate|user:deactivate|user:authenticate|authevent:create', {})
        check_activity(response)

        # check filtering with invalid actions
        response = c.get(path + '?actions=user:activate|INVALID|authevent:create', {})
        check_activity(response, status=400)
        response = c.get(path + '?actions=INVALID_ACTION', {})
        check_activity(response, status=400)

        # check multiple filters
        response = c.get(path + '?executer_id=%d&receiver_id=%d' % (self.uid_admin, self.uid), {})
        check_activity(response, l=2)
        response = c.get(path + '?executer_id=%d&receiver_id=%d' % (self.uid_admin, self.uid_admin), {})
        check_activity(
            response, 
            l=1, 
            receiver=self.uid_admin, 
            receiver_username='john',
            action="user:authenticate", 
            verify_comment=False)
        response = c.get(path + '?receiver_id=%d&executer_id=%d' % (self.uid, self.uid_admin), {})
        check_activity(response, l=2)
        response = c.get(path + '?actions=user:activate&receiver_id=%d&executer_id=%d' % (self.uid, self.uid_admin), {})
        check_activity(response, l=1)
        response = c.get(path + '?receiver_id=%d&actions=user:deactivate&executer_id=%d' % (self.uid, self.uid_admin), {})
        check_activity(response, l=1, action="user:deactivate")

        # check that without permissions no activity listing is allowed
        self.acl_activity1.delete()
        self.acl_edit_event.delete()
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
        check_activity(response, l=2)
        response = c.get(path + '?executer_id=%d&receiver_id=%d' % (self.uid_admin, self.uid), {})
        check_activity(response, l=2)
        response = c.get(path + '?executer_id=%d&receiver_id=%d' % (self.uid_admin, self.uid_admin), {})
        check_activity(
            response, 
            l=1, 
            receiver=self.uid_admin, 
            receiver_username='john',
            action="user:authenticate", 
            verify_comment=False)
        response = c.get(path + '?receiver_id=%d&executer_id=%d' % (self.uid, self.uid_admin), {})
        check_activity(response, l=2)
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
        check_activity(response, l=3)

        # all actions are prefixed with "user:"
        response = c.get(path + '?filter=user:', {})
        check_activity(response, l=3)

        # only one action has a comment with the word "here2"
        response = c.get(path + '?filter=here2', {})
        check_activity(response, l=1)


        # only first action has the action_name "user:activate"
        response = c.get(path + '?filter=here2', {})
        check_activity(response, l=1)

        # only one action has the action_name "user:deactivate"
        response = c.get(path + '?filter=deactivate', {})
        check_activity(response, l=1, action="user:deactivate", comment='some comment here')

        # all actions have the executer "john"
        response = c.get(path + '?filter=john', {})
        check_activity(response, l=3)


class ApiTestBallotBoxes(TestCase):
    def setUpTestData():
        flush_db_load_fixture()

    def setUp(self):
        ae = AuthEvent(
            auth_method="email",
            auth_method_config=test_data.authmethod_config_email_default,
            extra_fields=test_data.ae_email_default['extra_fields'],
            status='stopped',
            census="open",
            num_successful_logins_allowed = 1,
            has_ballot_boxes=True
        )
        ae.save()
        self.ae = ae
        self.aeid = ae.pk

        u_admin = User(username=test_data.admin['username'], email=test_data.admin['email'])
        u_admin.set_password(test_data.admin['password'])
        u_admin.save()
        u_admin.userdata.event = AuthEvent.objects.get(pk=1)
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
        response = c.authenticate(1, self.admin_auth_data)
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
        response = c.authenticate(1, self.admin_auth_data)
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
        response = c.authenticate(1, self.admin_auth_data)
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
        response = c.authenticate(1, self.admin_auth_data)
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
        response = c.authenticate(1, self.admin_auth_data)
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
        response = c.authenticate(1, self.admin_auth_data)
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
        response = c.authenticate(1, self.admin_auth_data)
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
        response = c.authenticate(1, self.admin_auth_data)
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
        response = c.authenticate(1, self.admin_auth_data)
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
        response = c.authenticate(1, self.admin_auth_data)
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
        response = c.authenticate(1, self.admin_auth_data)
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
        response = c.authenticate(1, self.admin_auth_data)
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
        response = c.authenticate(1, self.admin_auth_data)
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
        response = c.authenticate(1, self.admin_auth_data)
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
            extra_fields=test_data.ae_email_default['extra_fields'],
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
        u_admin.userdata.event = AuthEvent.objects.get(pk=1)
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
                    max=1,
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
        response = c.authenticate(1, self.admin_auth_data)
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
        response = c.authenticate(1, self.admin_auth_data)
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
        response = c.authenticate(1, self.admin_auth_data)
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
        response = c.authenticate(1, self.admin_auth_data)
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
        response = c.authenticate(1, self.admin_auth_data)
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
        response = c.authenticate(1, self.admin_auth_data)
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
        response = c.authenticate(1, self.admin_auth_data)
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
        response = c.authenticate(1, self.admin_auth_data)
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


class ApiTestPublicQuery(TestCase):
    def setUpTestData():
        flush_db_load_fixture()

    def setUp(self):
        self.ae1 = AuthEvent(
            auth_method=test_data.auth_event4['auth_method'],
            extra_fields=test_data.auth_event4['extra_fields'],
            auth_method_config=test_data.authmethod_config_email_default,
            allow_public_census_query=True,
            status="notstarted"
        )
        self.ae1.save()

        self.ae2 = AuthEvent(
            auth_method=test_data.auth_event4['auth_method'],
            extra_fields=test_data.auth_event4['extra_fields'],
            auth_method_config=test_data.authmethod_config_email_default,
            allow_public_census_query=False
        )
        self.ae2.save()

        u2 = User(username='test1', email="noperm@sequentech.io")
        u2.set_password("qwerty")
        u2.save()
        u2.userdata.event = self.ae1
        u2.userdata.save()

        self.acl = ACL(user=u2.userdata, object_type='AuthEvent', perm='vote',
            object_id=self.ae1.id)
        self.acl.save()

        self.aeid_special = 1

    def test_valid_public_census_query(self):
        c = JClient()

        # check user exists
        u2_data = dict(username='test1')
        url = '/api/auth-event/%d/census/public-query/' % self.ae1.id
        response = c.post(url, u2_data)
        self.assertEqual(response.status_code, 200)
        r = parse_json_response(response)
        self.assertEqual(r.get('status'), 'ok')

    def test_invalid_public_census_query(self):
        c = JClient()

        u2_data = dict(username='test2')
        url = '/api/auth-event/%d/census/public-query/' % self.ae1.id
        response = c.post(url, u2_data)
        self.assertEqual(response.status_code, 400)

    def test_different_statuses(self):
        c = JClient()

        self.ae1.status='started'
        self.ae1.save()

        u2_data = dict(username='test1')
        url = '/api/auth-event/%d/census/public-query/' % self.ae1.id
        response = c.post(url, u2_data)
        self.assertEqual(response.status_code, 200)

        self.ae1.status='stopped'
        self.ae1.save()
        response = c.post(url, u2_data)
        self.assertEqual(response.status_code, 404)

    def test_login_started_notstarted(self):
        c = JClient()
        user_data = dict(username='test1', password='qwerty')
        response = c.post('/api/auth-event/%d/authenticate/' % self.ae1.id, user_data)
        self.assertEqual(response.status_code, 400)

        self.ae1.status='started'
        self.ae1.save()
        user_data = dict(username='test1', password='qwerty')
        response = c.post('/api/auth-event/%d/authenticate/' % self.ae1.id, user_data)
        self.assertEqual(response.status_code, 200)


class ApiTestRequiredOnAuthentication(TestCase):
    def setUpTestData():
        flush_db_load_fixture()

    def setUp(self):
        self.ae = AuthEvent(
            auth_method='email',
            auth_method_config=test_data.authmethod_config_email_default,
            extra_fields=test_data.auth_event6['extra_fields'],
            status='started',
            census='open')
        self.ae.save()

        self.user = User(
            username='foo',
            email='foo@bar.com')
        self.user.set_password('qwerty')
        self.user.save()
        self.user.userdata.event = self.ae
        self.user.userdata.metadata = {'dni':'DNI1234567L'}
        self.user.userdata.save()

        c = Code(
            user=self.user.userdata,
            code='ERGERG',
            auth_event_id=self.ae.id)
        c.save()

        acl = ACL(
            user=self.user.userdata,
            object_type='AuthEvent',
            perm='vote',
            object_id=self.ae.id)
        acl.save()

        # in this test we need two user so that the narrowing of
        # finding users cannot be done simply because there's only
        # one
        self.user2 = User(
            username='foo2',
            email='foo2@bar.com')
        self.user2.set_password('qwerty2')
        self.user2.save()
        self.user2.userdata.event = self.ae
        self.user2.userdata.metadata = {'dni':'DNI34534534B'}
        self.user2.userdata.save()

    def test_required_on_authentication(self):
        c = JClient()
        user_data = dict(
            email='foo@bar.com',
            code='ERGERG',
            dni='01234567L')
        url_auth = '/api/auth-event/%d/authenticate/' % self.ae.id
        response = c.post(url_auth, user_data)
        self.assertEqual(response.status_code, 200)

        c = JClient()
        user_data = dict(
            email='foo@bar.com',
            code='ERGERG',
            dni='76543210S')
        response = c.post(url_auth, user_data)
        self.assertEqual(response.status_code, 400)

    def test_required_on_authentication2(self):
        c = JClient()
        user_data = dict(
            email='foo@bar.com',
            code='ERGERG',
            dni='01234567L')
        url_auth = '/api/auth-event/%d/authenticate/' % self.ae.id

        # login with DNI works
        response = c.post(url_auth, user_data)
        self.assertEqual(response.status_code, 200)

        # login without DNI doesn't work, it's required on authentication
        c = JClient()
        del user_data['email']
        response = c.post(url_auth, user_data)
        self.assertEqual(response.status_code, 400)

        self.ae.extra_fields[0]['required_on_authentication'] = False
        self.ae.save()

        c = JClient()
        response = c.post(url_auth, user_data)
        self.assertEqual(response.status_code, 200)


class ApiTestHideDefaultLoginLookupField(TestCase):
    def setUpTestData():
        flush_db_load_fixture()

    def setUp(self):
        self.ae = AuthEvent(
            auth_method='email',
            auth_method_config=copy.deepcopy(test_data.authmethod_config_email_default),
            extra_fields=copy.deepcopy(test_data.auth_event6['extra_fields']),
            status='started',
            census='open')
        self.ae.save()

        self.user = User(
            username='foo',
            email='foo@bar.com')
        self.user.set_password('qwerty')
        self.user.save()
        self.user.userdata.event = self.ae
        self.user.userdata.metadata = {'dni':'DNI1234567L'}
        self.user.userdata.save()

        c = Code(
            user=self.user.userdata,
            code='ERGERG',
            auth_event_id=self.ae.id)
        c.save()

        acl = ACL(
            user=self.user.userdata,
            object_type='AuthEvent',
            perm='vote',
            object_id=self.ae.id)
        acl.save()

        # in this test we need two user so that the narrowing of
        # finding users cannot be done simply because there's only
        # one
        self.user2 = User(
            username='foo2',
            email='foo2@bar.com')
        self.user2.set_password('qwerty2')
        self.user2.save()
        self.user2.userdata.event = self.ae
        self.user2.userdata.metadata = {'dni':'DNI34534534B'}
        self.user2.userdata.save()

    def _hide_default_login_lookup_field(self, is_resend=False):
        # reset data
        self.ae.extra_fields[1]["required_on_authentication"] = True
        self.ae.hide_default_login_lookup_field = False

        if is_resend:
            user_data_good = dict(dni='01234567L')
            user_data_bad = dict(dni='00011111W')
            url_auth = '/api/auth-event/%d/resend_auth_code/' % self.ae.id
        else:
            user_data_good = dict(code='ERGERG', dni='01234567L')
            user_data_bad = dict(code='ERGERG', dni='00011111W')
            url_auth = '/api/auth-event/%d/authenticate/' % self.ae.id

        # without email, it fails
        c = JClient()
        response = c.post(url_auth, user_data_good)
        self.assertEqual(response.status_code, 400)

        self.ae.extra_fields[0]['required_on_authentication'] = False
        self.ae.save()

        response = c.post(url_auth, user_data_good)
        self.assertEqual(response.status_code, 200)

        # using bad dni doesn't work
        response = c.post(url_auth, user_data_bad)
        self.assertEqual(response.status_code, 400)

        # if dni is not required_on_authentication it doesn't work
        self.ae.extra_fields[1]["required_on_authentication"] = False
        self.ae.save()
        response = c.post(url_auth, user_data_good)
        self.assertEqual(response.status_code, 400)

    def test_hide_default_login_lookup_field_email(self):
        self.ae.auth_method = 'email'
        self.ae.save()
        self._hide_default_login_lookup_field()

    @override_settings(CELERY_ALWAYS_EAGER=True)
    def test_hide_default_login_lookup_field_email_otp(self):
        self.ae.auth_method = 'email-otp'
        self.ae.save()
        self._hide_default_login_lookup_field()
        self._hide_default_login_lookup_field(is_resend=True)

    def test_hide_default_login_lookup_field_sms(self):
        self.ae.auth_method = 'sms'
        self.ae.save()
        self._hide_default_login_lookup_field()

    @override_settings(CELERY_ALWAYS_EAGER=True)
    def test_hide_default_login_lookup_field_sms_otp(self):
        self.ae.auth_method = 'sms-otp'
        self.ae.save()
        self._hide_default_login_lookup_field()
        self._hide_default_login_lookup_field(is_resend=True)


class ApiTestUserIdField(TestCase):
    def setUpTestData():
        flush_db_load_fixture()

    def setUp(self):
        pass

    @override_settings(CELERY_ALWAYS_EAGER=True, SHARED_SECRET=b"whatever")
    def test_dni(self):
        self.ae = AuthEvent(
            auth_method='email',
            auth_method_config=test_data.authmethod_config_email_default,
            extra_fields=test_data.auth_event17['extra_fields'],
            status='started',
            census='open')
        self.ae.id = 10000
        self.ae.save()

        c = JClient()
        user_data = dict(
            email='foo@bar.com',
            dni='01234567L')
        response = c.register(self.ae.id, user_data)
        self.assertEqual(response.status_code, 200)

        u = User.objects.get(email=user_data['email'])
        self.assertEqual(
            u.username,
            "65d208b58bed19558591967ea937799b5a7f266310e27d31f5209bf7e788bfdf"
        )


class ApitTestCreateParentElection(TestCase):
    def setUpTestData():
        flush_db_load_fixture()

    def setUp(self):
        self.aeid_special = 1
        u = User(
            username=test_data.admin['username'], 
            email=test_data.admin['email']
        )
        u.set_password(test_data.admin['password'])
        u.save()
        u.userdata.event = AuthEvent.objects.get(pk=1)
        u.userdata.save()
        self.user = u

        self.admin_auth_data = dict(
            email=test_data.admin['email'],
            code="ERGERG"
        )
        c = Code(
            user=self.user.userdata,
            code=self.admin_auth_data['code'],
            auth_event_id=self.aeid_special
        )
        c.save()
        
        acl = ACL(
            user=self.user.userdata, 
            object_type='AuthEvent', 
            perm='create',
            object_id=0
        )
        acl.save()

    def test_create_parent_authevent(self):
        c = JClient()
        response = c.authenticate(self.aeid_special, self.admin_auth_data)
        self.assertEqual(response.status_code, 200)
        response = c.post('/api/auth-event/', test_data.auth_event18)
        self.assertEqual(response.status_code, 200)
        r = parse_json_response(response)
        rid = r['id']

        response = c.get('/api/auth-event/%d/' % rid, {})
        self.assertEqual(response.status_code, 200)
        r = parse_json_response(response)
        self.assertEqual(
            reproducible_json_dumps(r['events']['children_election_info']),
            reproducible_json_dumps(test_data.auth_event18['children_election_info'])
        )

    def test_create_children_authevent(self):
        c = JClient()
        response = c.authenticate(self.aeid_special, self.admin_auth_data)
        self.assertEqual(response.status_code, 200)

        auth_event = copy.deepcopy(test_data.auth_event1)
        auth_event['parent_id'] = 3463453 # does not exist
        response = c.post('/api/auth-event/', auth_event)
        self.assertEqual(response.status_code, 400)

        auth_event['parent_id'] = 1 # does exist
        response = c.post('/api/auth-event/', auth_event)
        self.assertEqual(response.status_code, 200)
        r = parse_json_response(response)
        rid = r['id']

        response = c.get('/api/auth-event/%d/' % rid, {})
        self.assertEqual(response.status_code, 200)
        r = parse_json_response(response)
        self.assertEqual(r['events']['parent_id'], 1)


class ApitTestCensusManagementInElectionWithChildren(TestCase):
    def setUpTestData():
        flush_db_load_fixture()

    def setUp(self):
        self.aeid_special = 1
        u = User(
            username=test_data.admin['username'], 
            email=test_data.admin['email']
        )
        u.set_password(test_data.admin['password'])
        u.save()
        u.userdata.event = AuthEvent.objects.get(pk=1)
        u.userdata.save()
        self.user = u

        self.admin_auth_data = dict(
            email=test_data.admin['email'],
            code="ERGERG"
        )
        c = Code(
            user=self.user.userdata,
            code=self.admin_auth_data['code'],
            auth_event_id=self.aeid_special
        )
        c.save()
        
        acl = ACL(
            user=self.user.userdata, 
            object_type='AuthEvent', 
            perm='create',
            object_id=0
        )
        acl.save()

    def _add_to_census(self, auth_method):
        c = JClient()
        response = c.authenticate(self.aeid_special, self.admin_auth_data)
        self.assertEqual(response.status_code, 200)

        def change_extra_fields(event_data):
            if auth_method.startswith('sms'):
                event_data['extra_fields'] = [
                    {
                        "name": "tlf",
                        "type": "tlf", 
                        "required": True,
                        "min": 4,
                        "max": 20,
                        "required_on_authentication": True
                    }
                ]

        # create the child election1
        event_data = copy.deepcopy(test_data.auth_event19)
        event_data['auth_method'] = auth_method
        change_extra_fields(event_data)
        response = c.post('/api/auth-event/', event_data)
        self.assertEqual(response.status_code, 200)
        r = parse_json_response(response)
        child_id_1 = r['id']

        # create the child election2
        event_data = copy.deepcopy(test_data.auth_event19)
        event_data['auth_method'] = auth_method
        change_extra_fields(event_data)
        response = c.post('/api/auth-event/', event_data)
        self.assertEqual(response.status_code, 200)
        r = parse_json_response(response)
        child_id_2 = r['id']

        # create the parent election
        event_data = test_data.get_auth_event_20(child_id_1, child_id_2)
        event_data['auth_method'] = auth_method
        change_extra_fields(event_data)
        response = c.post('/api/auth-event/', event_data)
        self.assertEqual(response.status_code, 200)
        r = parse_json_response(response)
        parent_id = r['id']

        # set the parent in children. We do not set at the begining
        # because we do not know the children election ids..
        parent_election = AuthEvent.objects.get(pk=parent_id)
        
        children_1 = AuthEvent.objects.get(pk=child_id_1)
        children_1.parent = parent_election
        children_1.save()
        
        children_2 = AuthEvent.objects.get(pk=child_id_2)
        children_2.parent = parent_election
        children_2.save()
        
        # try to add otherwise "valid-looking" census to the children 
        # should fail
        response = c.census(child_id_1, test_data.get_auth_event19_census(auth_method))
        self.assertEqual(response.status_code, 400)
        
        # try to add valid census to the parent should work
        response = c.census(
            parent_id, 
            test_data.get_auth_event20_census_ok(child_id_1, child_id_2, auth_method)
        )
        self.assertEqual(response.status_code, 200)
        
        # try to add census linking to other elections should fail
        response = c.census(
            parent_id, 
            test_data.get_auth_event20_census_invalid(auth_method)
        )
        self.assertEqual(response.status_code, 400)

    def test_add_to_census_email(self):
        self._add_to_census('email')

    def test_add_to_census_email_otp(self):
        self._add_to_census('email-otp')

    def test_add_to_census_sms(self):
        self._add_to_census('sms')

    def test_add_to_census_email(self):
        self._add_to_census('sms-otp')


class ApitTestAuthenticateInElectionWithChildren(TestCase):
    def setUpTestData():
        flush_db_load_fixture()

    def setUp(self):
        self.aeid_special = 1
        u = User(
            username=test_data.admin['username'], 
            email=test_data.admin['email']
        )
        u.set_password(test_data.admin['password'])
        u.save()
        u.userdata.event = AuthEvent.objects.get(pk=1)
        u.userdata.save()
        self.user = u

        self.admin_auth_data = dict(
            email=test_data.admin['email'],
            code="ERGERG"
        )
        c = Code(
            user=self.user.userdata,
            code=self.admin_auth_data['code'],
            auth_event_id=self.aeid_special
        )
        c.save()
        
        acl = ACL(
            user=self.user.userdata, 
            object_type='AuthEvent', 
            perm='create',
            object_id=0
        )
        acl.save()

    def _auth_and_vote(self, auth_method):
        client = JClient()
        response = client.authenticate(self.aeid_special, self.admin_auth_data)
        self.assertEqual(response.status_code, 200)

        # create the child election1
        event_data = copy.deepcopy(test_data.auth_event19)
        event_data['auth_method'] = auth_method
        response = client.post('/api/auth-event/', event_data)
        self.assertEqual(response.status_code, 200)
        r = parse_json_response(response)
        child_id_1 = r['id']

        # create the child election2
        event_data = copy.deepcopy(test_data.auth_event19)
        event_data['auth_method'] = auth_method
        response = client.post('/api/auth-event/', event_data)
        self.assertEqual(response.status_code, 200)
        r = parse_json_response(response)
        child_id_2 = r['id']

        # create the parent election
        event_data = test_data.get_auth_event_20(child_id_1, child_id_2)
        event_data['auth_method'] = auth_method
        response = client.post('/api/auth-event/', event_data)
        self.assertEqual(response.status_code, 200)
        r = parse_json_response(response)
        parent_id = r['id']

        # set the parent in children. We do not set at the begining
        # because we do not know the children election ids..
        parent_election = AuthEvent.objects.get(pk=parent_id)
        
        children_1 = AuthEvent.objects.get(pk=child_id_1)
        children_1.parent = parent_election
        children_1.save()
        
        children_2 = AuthEvent.objects.get(pk=child_id_2)
        children_2.parent = parent_election
        children_2.save()
        
        # add valid census to the parent should work
        census_data = test_data.get_auth_event20_census_ok(
            child_id_1, 
            child_id_2, 
            auth_method
        )
        response = client.census(
            parent_id, 
            census_data
        )
        self.assertEqual(response.status_code, 200)

        # create authentication code for user in census
        voter = User.objects.get(
            email=census_data['census'][0]['email'],
            userdata__event=parent_election
        )
        code = Code(
            user=voter.userdata, 
            code=test_data.auth_email_default['code'], 
            auth_event_id=parent_election.pk
        )
        code.save()

        # start the election
        response = client.post(
            '/api/auth-event/%d/%s/' % (parent_election.pk, 'started'), 
            {}
        )
        self.assertEqual(response.status_code, 200)

        # authenticate in parent election
        response = client.authenticate(
            parent_election.id, 
            {
                "email": census_data['census'][0]['email'],
                "dni": census_data['census'][0]['dni'],
                "code": test_data.auth_email_default['code']
            }
        )
        self.assertEqual(response.status_code, 200)

        # verify answer data
        resp_json = parse_json_response(response)
        self.assertEqual(type(resp_json), dict)
        self.assertEqual(resp_json['status'], 'ok')
        assert 'username' in resp_json
        self.assertEqual(type(resp_json['username']), str)
        assert 'auth-token' in resp_json
        self.assertEqual(type(resp_json['auth-token']), str)
        assert 'vote-children-info' in resp_json
        self.assertEqual(type(resp_json['vote-children-info']), list)
        self.assertEqual(len(resp_json['vote-children-info']), 2)
        
        child_info_1 = resp_json['vote-children-info'][0]
        self.assertEqual(type(child_info_1), dict)
        assert 'auth-event-id' in child_info_1
        self.assertEqual(child_info_1['auth-event-id'], child_id_1)
        assert 'vote-permission-token' in child_info_1
        self.assertEqual(type(child_info_1['vote-permission-token']), str)
        self.assertTrue(re.match(
            "^khmac:\/\/\/sha-256;[a-f0-9]{64}\/[a-f0-9]+:AuthEvent:[0-9]:vote:[0-9]+$",
            child_info_1['vote-permission-token']
        ))
        self.assertEqual(child_info_1.get('num-successful-logins-allowed'), 0)
        self.assertEqual(child_info_1.get('num-successful-logins'), 0)

        # verify the second user is not allowed to authenticate in child_election_2
        voter = User.objects.get(
            email=census_data['census'][1]['email'],
            userdata__event=parent_election
        )
        code = Code(
            user=voter.userdata, 
            code=test_data.auth_email_default['code'], 
            auth_event_id=parent_election.pk
        )
        code.save()

        # authenticate in parent election
        response = client.authenticate(
            parent_election.id, 
            {
                "email": census_data['census'][1]['email'],
                "dni": census_data['census'][1]['dni'],
                "code": test_data.auth_email_default['code']
            }
        )
        self.assertEqual(response.status_code, 200)

        # verify answer data
        resp_json = parse_json_response(response)
        resp_json['vote-children-info']
        self.assertEqual(len(resp_json['vote-children-info']), 2)
        child_info_1 = resp_json['vote-children-info'][0]
        child_info_2 = resp_json['vote-children-info'][1]
        self.assertEqual(type(child_info_1), dict)
        assert 'auth-event-id' in child_info_1
        self.assertEqual(child_info_1['auth-event-id'], child_id_1)
        assert 'vote-permission-token' in child_info_1
        self.assertEqual(type(child_info_1['vote-permission-token']), str)
        self.assertTrue(re.match(
            "^khmac:\/\/\/sha-256;[a-f0-9]{64}\/[a-f0-9]+:AuthEvent:[0-9]:vote:[0-9]+$",
            child_info_1['vote-permission-token']
        ))
        self.assertEqual(type(child_info_2), dict)
        assert 'auth-event-id' in child_info_2
        self.assertEqual(child_info_2['auth-event-id'], child_id_2)
        assert 'vote-permission-token' in child_info_2
        self.assertEqual(child_info_2['vote-permission-token'], None)

    def _auth_and_vote_with_edit_children_parent(self, auth_method):
        client = JClient()
        response = client.authenticate(self.aeid_special, self.admin_auth_data)
        self.assertEqual(response.status_code, 200)

        # create the child election1
        event_data = copy.deepcopy(test_data.auth_event19)
        event_data['auth_method'] = auth_method
        response = client.post('/api/auth-event/', event_data)
        self.assertEqual(response.status_code, 200)
        r = parse_json_response(response)
        child_id_1 = r['id']
        self.assertEqual(
            AuthEvent.objects.get(pk=child_id_1).parent_id,
            None
        )

        # create the child election2
        event_data = copy.deepcopy(test_data.auth_event19)
        event_data['auth_method'] = auth_method
        response = client.post('/api/auth-event/', event_data)
        self.assertEqual(response.status_code, 200)
        r = parse_json_response(response)
        child_id_2 = r['id']
        self.assertEqual(
            AuthEvent.objects.get(pk=child_id_2).parent_id,
            None
        )

        # create the parent election, but not yet with children_election_info
        event_data = test_data.get_auth_event_20(child_id_1, child_id_2)
        children_election_info = event_data['children_election_info']
        del event_data['children_election_info']
        event_data['auth_method'] = auth_method
        response = client.post('/api/auth-event/', event_data)
        self.assertEqual(response.status_code, 200)
        r = parse_json_response(response)
        parent_id = r['id']

        # set the parent and children election info in the elections
        update_data = {
            'parent_id': parent_id
        }
        response = client.post(
            '/api/auth-event/%d/edit-children-parent/' % child_id_1, 
            update_data
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            AuthEvent.objects.get(pk=child_id_1).parent_id,
            parent_id
        )
        response = client.post(
            '/api/auth-event/%d/edit-children-parent/' % child_id_2, 
            update_data
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            AuthEvent.objects.get(pk=child_id_2).parent_id,
            parent_id
        )

        response = client.post(
            '/api/auth-event/%d/edit-children-parent/' % parent_id, 
            {
                'children_election_info': children_election_info
            }
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            reproducible_json_dumps(
                AuthEvent\
                    .objects\
                    .get(pk=parent_id)\
                    .children_election_info
            ),
            reproducible_json_dumps(children_election_info)
        )
        
        # add valid census to the parent should work
        census_data = test_data.get_auth_event20_census_ok(
            child_id_1, 
            child_id_2, 
            auth_method
        )
        response = client.census(
            parent_id, 
            census_data
        )
        self.assertEqual(response.status_code, 200)

        # create authentication code for user in census
        voter = User.objects.get(
            email=census_data['census'][0]['email'],
            userdata__event_id=parent_id
        )
        code = Code(
            user=voter.userdata, 
            code=test_data.auth_email_default['code'], 
            auth_event_id=parent_id
        )
        code.save()

        # start the election
        response = client.post(
            '/api/auth-event/%d/%s/' % (parent_id, 'started'), 
            {}
        )
        self.assertEqual(response.status_code, 200)

        # authenticate in parent election
        response = client.authenticate(
            parent_id, 
            {
                "email": census_data['census'][0]['email'],
                "dni": census_data['census'][0]['dni'],
                "code": test_data.auth_email_default['code']
            }
        )
        self.assertEqual(response.status_code, 200)

        # verify census
        response = client.authenticate(self.aeid_special, self.admin_auth_data)
        response = client.get('/api/auth-event/%d/census/' % parent_id, {})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            reproducible_json_dumps(parse_json_response(response)['object_list'][0]['voted_children_elections']),
            reproducible_json_dumps([])
        )

        successful_login = SuccessfulLogin(user=voter.userdata, auth_event_id=child_id_1)
        successful_login.save()
        response = client.get('/api/auth-event/%d/census/' % parent_id, {})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            reproducible_json_dumps(parse_json_response(response)['object_list'][0]['voted_children_elections']),
            reproducible_json_dumps([child_id_1])
        )

    """ def test_auth_and_vote_email(self):
        self._auth_and_vote('email')

    def test_auth_and_vote_email_otp(self):
        self._auth_and_vote('email-otp')

    def test_auth_and_vote_with_edit_children_parent_email(self):
        self._auth_and_vote_with_edit_children_parent('email') """

    def test_auth_and_vote_with_edit_children_parent_email_otp(self):
        self._auth_and_vote_with_edit_children_parent('email-otp')


class TestAuthEventList(TestCase):
    def setUpTestData():
        flush_db_load_fixture()

    def setUp(self):
        ae = AuthEvent(
            auth_method=test_data.auth_event4['auth_method'],
            extra_fields=test_data.auth_event4['extra_fields'],
            auth_method_config=test_data.authmethod_config_email_default
        )
        ae.save()
        ae2 = AuthEvent(
            auth_method=test_data.auth_event4['auth_method'],
            extra_fields=test_data.auth_event4['extra_fields'],
            auth_method_config=test_data.authmethod_config_email_default,
            parent_id=ae.pk
        )
        ae2.save()

        self.aeid_special = 1
        u = User(
            username=test_data.admin['username'], 
            email=test_data.admin['email']
        )
        u.set_password('smith')
        u.save()
        u.userdata.event = AuthEvent.objects.get(pk=1)
        u.userdata.save()

        self.admin_auth_data = dict(
            email=test_data.admin['email'],
            code="ERGERG"
        )
        c = Code(
            user=u.userdata,
            code=self.admin_auth_data['code'],
            auth_event_id=self.aeid_special
        )
        c.save()

        self.userid = u.pk
        self.testuser = u
        self.aeid = ae.pk
        self.ae = ae
        self.ae2 = ae2

        acl = ACL(
            user=u.userdata, 
            object_type='AuthEvent', 
            perm='view',
            object_id=self.ae.id
        )
        acl.save()
        acl2 = ACL(
            user=u.userdata, 
            object_type='AuthEvent', 
            perm='view',
            object_id=self.ae2.id
        )
        acl2.save()
    
    def test_list_and_filter(self):
        client = JClient()
        response = client.authenticate(
            self.aeid_special, 
            self.admin_auth_data
        )
        self.assertEqual(response.status_code, 200)

        # list all
        response = client.get('/api/auth-event/', {})
        self.assertEqual(response.status_code, 200)
        r = parse_json_response(response)
        self.assertEqual(len(r['events']), 3)

        # list my elections
        response = client.get('/api/auth-event/?has_perms=edit|view', {})
        self.assertEqual(response.status_code, 200)
        r = parse_json_response(response)
        self.assertEqual(len(r['events']), 2)

        # list my elections with no parents
        response = client.get('/api/auth-event/?has_perms=edit|view&only_parent_elections=true', {})
        self.assertEqual(response.status_code, 200)
        r = parse_json_response(response)
        self.assertEqual(len(r['events']), 1)

        # list my elections with no parents and archived
        response = client.get('/api/auth-event/?has_perms=unarchive|view-archived&only_parent_elections=true', {})
        self.assertEqual(response.status_code, 200)
        r = parse_json_response(response)
        self.assertEqual(len(r['events']), 0)

        # list my elections with specific ids
        response = client.get('/api/auth-event/?has_perms=edit|view&ids=%d' % self.ae2.id, {})
        self.assertEqual(response.status_code, 200)
        r = parse_json_response(response)
        self.assertEqual(len(r['events']), 1)


class TestOtl(TestCase):
    def setUpTestData():
        flush_db_load_fixture()

    def setUp(self):
        self.aeid_special = 1
        u = User(
            username=test_data.admin['username'], 
            email=test_data.admin['email']
        )
        u.set_password(test_data.admin['password'])
        u.save()
        u.userdata.event = AuthEvent.objects.get(pk=1)
        u.userdata.save()
        self.user = u

        self.admin_auth_data = dict(
            email=test_data.admin['email'],
            code="ERGERG"
        )
        c = Code(
            user=self.user.userdata,
            code=self.admin_auth_data['code'],
            auth_event_id=self.aeid_special
        )
        c.save()
        
        acl = ACL(
            user=self.user.userdata, 
            object_type='AuthEvent', 
            perm='create',
            object_id=0
        )
        acl.save()

    def test_create_otl_auth_event(self):
        '''
        Create an OTL auth event
        '''
        # authenticate as an admin
        c = JClient()
        response = c.authenticate(self.aeid_special, self.admin_auth_data)
        self.assertEqual(response.status_code, 200)

        # create otp auth-event
        response = c.post('/api/auth-event/', test_data.auth_event_otp1)
        self.assertEqual(response.status_code, 200)
        r = parse_json_response(response)
        otp_auth_event_id = r['id']

        # retrieve otp auth-event
        response = c.get(f'/api/auth-event/{otp_auth_event_id}/', {})
        self.assertEqual(response.status_code, 200)
        r = parse_json_response(response)

        # check the otp auth-event has support of otl enabled
        self.assertEqual(r['events']['support_otl_enabled'], True)
        self.assertEqual(r['events']['inside_authenticate_otl_period'], False)

    def test_toggle_otl_period_flag(self):
        '''
        Checks that the API to enable and disable the OTL period does change
        the inside_authenticate_otl_period flag
        '''
        # authenticate as an admin
        c = JClient()
        response = c.authenticate(self.aeid_special, self.admin_auth_data)
        self.assertEqual(response.status_code, 200)

        # create otp auth-event
        response = c.post('/api/auth-event/', test_data.auth_event_otp1)
        self.assertEqual(response.status_code, 200)
        r = parse_json_response(response)
        otp_auth_event_id = r['id']

        # check there's no action related yet
        self.assertEqual(
            Action.objects.filter(
                executer__id=self.user.id,
                action_name='authevent:set-authenticate-otl-period',
                event=otp_auth_event_id
            ).count(),
            0
        )

        # enable otl period
        response = c.post(
            f'/api/auth-event/{otp_auth_event_id}/set-authenticate-otl-period/',
            dict(set_authenticate_otl_period=True)
        )
        self.assertEqual(response.status_code, 200)

        # retrieve otp auth-event and check otl period
        response = c.get(f'/api/auth-event/{otp_auth_event_id}/', {})
        self.assertEqual(response.status_code, 200)
        r = parse_json_response(response)
        self.assertEqual(r['events']['inside_authenticate_otl_period'], True)

        # check a new action was registered
        self.assertEqual(
            Action.objects.filter(
                executer__id=self.user.id,
                action_name='authevent:set-authenticate-otl-period',
                event=otp_auth_event_id
            ).count(),
            1
        )

        # enable otl period again (no change)
        response = c.post(
            f'/api/auth-event/{otp_auth_event_id}/set-authenticate-otl-period/',
            dict(set_authenticate_otl_period=True)
        )
        self.assertEqual(response.status_code, 200)

        # retrieve otp auth-event and check otl period
        response = c.get(f'/api/auth-event/{otp_auth_event_id}/', {})
        self.assertEqual(response.status_code, 200)
        r = parse_json_response(response)
        self.assertEqual(r['events']['inside_authenticate_otl_period'], True)

        # check a new action was registered
        self.assertEqual(
            Action.objects.filter(
                executer__id=self.user.id,
                action_name='authevent:set-authenticate-otl-period',
                event=otp_auth_event_id
            ).count(),
            2
        )

        # disable otl period
        response = c.post(
            f'/api/auth-event/{otp_auth_event_id}/set-authenticate-otl-period/',
            dict(set_authenticate_otl_period=False)
        )
        self.assertEqual(response.status_code, 200)

        # retrieve otp auth-event and check otl period
        response = c.get(f'/api/auth-event/{otp_auth_event_id}/', {})
        self.assertEqual(response.status_code, 200)
        r = parse_json_response(response)
        self.assertEqual(r['events']['inside_authenticate_otl_period'], False)

        # check a new action was registered
        self.assertEqual(
            Action.objects.filter(
                executer__id=self.user.id,
                action_name='authevent:set-authenticate-otl-period',
                event=otp_auth_event_id
            ).count(),
            3
        )

    def test_invalid_set_otl_period(self):
        '''
        Checks multiple cases in which the setting of the OTL period should
        fail:
        - no authentication
        - invalid input data
        - invalid permissions
        '''
        # authenticate as an admin
        c = JClient()
        response = c.authenticate(self.aeid_special, self.admin_auth_data)
        self.assertEqual(response.status_code, 200)

        # create otp auth-event
        response = c.post('/api/auth-event/', test_data.auth_event_otp1)
        self.assertEqual(response.status_code, 200)
        r = parse_json_response(response)
        otp_auth_event_id = r['id']

        # invalid input data
        response = c.post(
            f'/api/auth-event/{otp_auth_event_id}/set-authenticate-otl-period/',
            dict(set_authenticate_otl_period="invalid")
        )
        self.assertEqual(response.status_code, 400)
        response = c.post(
            f'/api/auth-event/{otp_auth_event_id}/set-authenticate-otl-period/',
            dict(whatever="invalid")
        )
        self.assertEqual(response.status_code, 400)

        # log out and try to set otl period
        c.set_auth_token(None)
        response = c.post(
            f'/api/auth-event/{otp_auth_event_id}/set-authenticate-otl-period/',
            dict(set_authenticate_otl_period=True)
        )
        self.assertEqual(response.status_code, 403)

        # check there's no action related yet
        self.assertEqual(
            Action.objects.filter(
                executer__id=self.user.id,
                action_name='authevent:set-authenticate-otl-period',
                event=otp_auth_event_id
            ).count(),
            0
        )

        # retrieve otp auth-event and check otl period didn't change
        response = c.get(f'/api/auth-event/{otp_auth_event_id}/', {})
        self.assertEqual(response.status_code, 200)
        r = parse_json_response(response)
        self.assertEqual(r['events']['inside_authenticate_otl_period'], False)

    @override_settings(**override_celery_data)
    def test_otl_flow(self):
        '''
        Test the whole OTL flow, from election creation to voter authentication
        '''
        # authenticate as an admin
        c = JClient()
        response = c.authenticate(self.aeid_special, self.admin_auth_data)
        self.assertEqual(response.status_code, 200)

        # create otp auth-event
        response = c.post('/api/auth-event/', test_data.auth_event_otp1)
        self.assertEqual(response.status_code, 200)
        r = parse_json_response(response)
        otp_auth_event_id = r['id']

        # add user to the census
        response = c.census(
            otp_auth_event_id,
            {
                "field-validation": "enabled",
                "census": [
                    {
                        "email": "baaa@aaa.com",
                        "membership-id": "1234"
                    }
                ]
            }
        )
        self.assertEqual(response.status_code, 200)

        # enable otl period
        response = c.post(
            f'/api/auth-event/{otp_auth_event_id}/set-authenticate-otl-period/',
            dict(set_authenticate_otl_period=True)
        )
        self.assertEqual(response.status_code, 200)

        # enable authentication period
        response = c.post(
            f'/api/auth-event/{otp_auth_event_id}/started/',
            dict()
        )
        self.assertEqual(response.status_code, 200)

        # send authentication, which should generate an OTL
        self.assertEqual(OneTimeLink.objects.count(), 0)
        response = c.post(
            f'/api/auth-event/{otp_auth_event_id}/census/send_auth/',
            {
                "msg": "Vote in __URL__ but obtain code in __OTL__",
                "subject": "Test Vote",
                "user-ids": None,
                "auth-method": "email"
            }
        )
        self.assertEqual(response.status_code, 200)

        self.assertEqual(OneTimeLink.objects.count(), 1)
        otl = OneTimeLink.objects.filter()[0]

        # perform otp authentication
        response = c.post(
            f'/api/auth-event/{otp_auth_event_id}/authenticate-otl/',
            {
                "email": "baaa@aaa.com",
                "membership-id": "1234",
                "__otl_secret": str(otl.secret)
            }
        )
        self.assertEqual(response.status_code, 200)
        response_json = parse_json_response(response)
        self.assertTrue(
            'code' in response_json and isinstance(response_json['code'], str)
        )
        code = response_json['code']

        # perform authentication using otp
        c.authenticate(
            otp_auth_event_id,
            {
                'email': "baaa@aaa.com",
                'code': code
            }
        )
        self.assertEqual(response.status_code, 200)

        # authenticate as an admin again
        c = JClient()
        response = c.authenticate(self.aeid_special, self.admin_auth_data)
        self.assertEqual(response.status_code, 200)

        # resend the OTL, creating a new OTL and invalidating previous one
        response = c.post(
            f'/api/auth-event/{otp_auth_event_id}/census/send_auth/',
            {
                "msg": "Vote in __URL__ but obtain code in __OTL__",
                "subject": "Test Vote",
                "user-ids": None,
                "auth-method": "email",
                "force_create_otl": True
            }
        )
        self.assertEqual(response.status_code, 200)

        # sanity checks
        self.assertEqual(OneTimeLink.objects.count(), 2)
        [new_otl, old_otl] = OneTimeLink.objects.order_by("-created")
        self.assertEqual(old_otl.secret, otl.secret)
        self.assertEqual(old_otl.is_enabled, False)
        self.assertEqual(new_otl.is_enabled, True)
        self.assertTrue(new_otl.secret != old_otl.secret)

        # perform otp authentication with old code fails
        response = c.post(
            f'/api/auth-event/{otp_auth_event_id}/authenticate-otl/',
            {
                "email": "baaa@aaa.com",
                "membership-id": "1234",
                "__otl_secret": str(old_otl.secret)
            }
        )
        self.assertEqual(response.status_code, 400)

        # perform otp auth with new code works
        response = c.post(
            f'/api/auth-event/{otp_auth_event_id}/authenticate-otl/',
            {
                "email": "baaa@aaa.com",
                "membership-id": "1234",
                "__otl_secret": str(new_otl.secret)
            }
        )
        self.assertEqual(response.status_code, 200)
        response_json = parse_json_response(response)
        new_code = response_json['code']

        # the new code obtained is the same as before because this election is
        # configured to use static codes
        self.assertEqual(code, new_code)

        # the code can still be used for authentication
        c.authenticate(
            otp_auth_event_id,
            {
                'email': "baaa@aaa.com",
                'code': new_code
            }
        )
        self.assertEqual(response.status_code, 200)


class ApiTestGoToUrlAuthenticate(TestCase):
    def setUpTestData():
        flush_db_load_fixture()

    def setUp(self):
        self.auth_event = AuthEvent(
            auth_method='email',
            auth_method_config=copy.deepcopy(test_data.authmethod_config_email_go_to_url),
            extra_fields=[],
            status='started',
            census='open')
        self.auth_event.save()

        self.user = User(
            username='foo',
            email='foo@bar.com')
        self.user.set_password('qwerty')
        self.user.save()
        self.user.userdata.event = self.auth_event
        self.user.userdata.save()

        code = Code(
            user=self.user.userdata,
            code='ERGERG',
            auth_event_id=self.auth_event.id)
        code.save()

        acl = ACL(
            user=self.user.userdata,
            object_type='AuthEvent',
            perm='vote',
            object_id=self.auth_event.id)
        acl.save()

    def test_go_to_url_login(self):
        '''
        Test that the user gets a return url after successful login
        '''
        client = JClient()
        user_data = dict(
            email='foo@bar.com',
            code='ERGERG'
        )
        url_auth = '/api/auth-event/%d/authenticate/' % self.auth_event.id
        response = client.post(url_auth, user_data)
        self.assertEqual(response.status_code, 200)
        response_data = parse_json_response(response)
        redirect_url = test_data.authmethod_config_email_go_to_url['config']['authentication-action']['mode-config']['url']
        self.assertEqual(response_data['redirect-to-url'], redirect_url)

    def test_go_to_url_login_template(self):
        '''
        Test that the user gets a return url after successful login, replacing
        also __VOTE_CHILDREN_INFO__ in the url template
        '''
        self.auth_event.auth_method_config['config']['authentication-action']['mode-config']['url'] = (
            test_data.authmethod_config_email_go_to_url['config']['authentication-action']['mode-config']['url'] +
            "?children=__VOTE_CHILDREN_INFO__"
        )
        self.auth_event.save()
        client = JClient()
        user_data = dict(
            email='foo@bar.com',
            code='ERGERG'
        )
        url_auth = '/api/auth-event/%d/authenticate/' % self.auth_event.id
        response = client.post(url_auth, user_data)
        self.assertEqual(response.status_code, 200)
        response_data = parse_json_response(response)

        # Note '%5B%5D' is urlencoded for '[]', which is what is expected since
        # this is not a parent-children election
        redirect_url = (
            test_data.authmethod_config_email_go_to_url['config']['authentication-action']['mode-config']['url'] +
            "?children=%5B%5D"
        )
        self.assertEqual(response_data['redirect-to-url'], redirect_url)
