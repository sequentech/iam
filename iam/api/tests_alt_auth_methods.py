# This file is part of iam.
# Copyright (C) 2014-2023  Sequent Tech Inc <legal@sequentech.io>

# iam is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License.

# iam  is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.

# You should have received a copy of the GNU Affero General Public License
# along with iam.  If not, see <http://www.gnu.org/licenses/>.

import copy
import json
from django.test.utils import override_settings
from django.utils.text import slugify
from unittest.mock import patch
from django.test import TestCase
from django.contrib.auth.models import User

from . import test_data
from .models import ACL, AuthEvent
from authmethods.models import Code, Message
from utils import reproducible_json_dumps
from .tests import parse_json_response, flush_db_load_fixture, JClient

auth_event_1 = {
    "auth_method": "email",
    "census": "open",
    "auth_method_config": {
        "authentication-action":{
            "mode":"vote",
            "mode-config": None
        },
        "registration-action":{
            "mode":"vote",
            "mode-config":None
        },
        "subject": "Confirm your email",
        "msg": "Click __URL__ and put this code __CODE__",
        "fixed-code": True
    },
    "extra_fields": [
        {
            "name": "email",
            "type": "email",
            "required": True,
            "unique": True,
            "min": 4,
            "max": 255,
            "required_on_authentication": True
        },
        {
            "name": "tlf",
            "type": "tlf",
            "required": True,
            "unique": True,
            "min": 4,
            "max": 255,
            "required_on_authentication": False
        }
    ],
    "alternative_auth_methods": [
        {
            "id": "sms",
            "auth_method_name": "sms",
            "auth_method_config": {
                "allow_user_resend": False,
                "authentication-action": {
                    "mode": "vote",
                    "mode-config": None
                },
                "msg": "Enter in __URL__ and put this code __CODE__",
                "registration-action": {
                    "mode": "vote",
                    "mode-config": None
                }
            },
            "extra_fields": [
                {
                    "name": "email",
                    "type": "email",
                    "required": True,
                    "unique": True,
                    "min": 4,
                    "max": 255,
                    "required_on_authentication": False
                },
                {
                    "name": "tlf",
                    "type": "tlf",
                    "required": True,
                    "unique": True,
                    "min": 4,
                    "max": 255,
                    "required_on_authentication": True
                }
            ], 
            "public_name": "Phone",
            "public_name_i18n": {"es": "Teléfono"},
            "icon": "icon-name"
        }
    ]
}

def add_slugs(extra_fields):
    return [
        (
            extra_field.update({'slug': slugify(extra_field['name']).upper()})
            or extra_field
        )
        for extra_field in extra_fields
    ]

def fix_auth_event_config(auth_event_config):
    '''
    Fixes auth_event config adding slugs to extra_fields and pipelines to
    auth_method_config
    '''
    from utils import update_alt_methods_config
    ret = copy.deepcopy(auth_event_config)
    ret['extra_fields'] = add_slugs(ret['extra_fields'])
    if "alternative_auth_methods" in ret:
        ret["alternative_auth_methods"] = [
            (
                alt_auth_method.update({
                    'extra_fields': add_slugs(alt_auth_method['extra_fields'])
                })
                or alt_auth_method
            )
            for alt_auth_method in ret["alternative_auth_methods"]
        ]
        update_alt_methods_config(ret["alternative_auth_methods"])
    return ret


class ApitTestCreateAltAuthentication(TestCase):
    '''
    Creates an authentication event with support for an alternative
    authentication method
    '''
    def setUpTestData():
        flush_db_load_fixture()

    def setUp(self):
        self.aeid_special = 1
        user = User(
            username=test_data.admin['username'], 
            email=test_data.admin['email']
        )
        user.set_password(test_data.admin['password'])
        user.save()
        user.userdata.event = AuthEvent.objects.get(pk=1)
        user.userdata.save()
        self.user = user

        self.admin_auth_data = dict(
            email=test_data.admin['email'],
            code="ERGERG"
        )
        code = Code(
            user=self.user.userdata,
            code=self.admin_auth_data['code'],
            auth_event_id=self.aeid_special
        )
        code.save()
        
        acl = ACL(
            user=self.user.userdata, 
            object_type='AuthEvent', 
            perm='create',
            object_id=0
        )
        acl.save()

    def test_create_parent_authevent(self):
        client = JClient()
        response = client.authenticate(self.aeid_special, self.admin_auth_data)
        self.assertEqual(response.status_code, 200)
        response = client.post('/api/auth-event/', auth_event_1)
        self.assertEqual(response.status_code, 200)
        r = parse_json_response(response)
        rid = r['id']

        response = client.get('/api/auth-event/%d/' % rid, {})
        self.assertEqual(response.status_code, 200)
        r = parse_json_response(response)
        self.assertEqual(
            reproducible_json_dumps(r['events']['alternative_auth_methods']),
            reproducible_json_dumps(fix_auth_event_config(auth_event_1)['alternative_auth_methods'])
        )


class AuthMethodAltSmsTestCase(TestCase):
    def setUpTestData():
        flush_db_load_fixture()

    def setUp(self):
        # super-admin event
        self.aeid_special = 1
        admin_user = User(
            username=test_data.admin['username'], 
            email=test_data.admin['email']
        )
        admin_user.set_password(test_data.admin['password'])
        admin_user.save()
        admin_user.userdata.event = AuthEvent.objects.get(pk=1)
        admin_user.userdata.save()
        self.admin_user = admin_user

        self.admin_auth_data = dict(
            email=test_data.admin['email'],
            code="ERGERG"
        )
        admin_code = Code(
            user=self.admin_user.userdata,
            code=self.admin_auth_data['code'],
            auth_event_id=self.aeid_special
        )
        admin_code.save()
        
        admin_acl = ACL(
            user=self.admin_user.userdata, 
            object_type='AuthEvent', 
            perm='create',
            object_id=0
        )
        admin_acl.save()

        self.client = JClient()
        response = self.client.authenticate(
            self.aeid_special, self.admin_auth_data
        )
        self.assertEqual(response.status_code, 200)
        response = self.client.post('/api/auth-event/', auth_event_1)
        self.assertEqual(response.status_code, 200)
        response = parse_json_response(response)
        self.aeid = response['id']
        auth_event = AuthEvent.objects.get(pk=self.aeid)
        auth_event.status = AuthEvent.STARTED
        auth_event.save()
    
        user = User(username='test1', email='test@sequentech.io')
        user.save()
        user.userdata.event = auth_event
        user.userdata.tlf = '+34666666666'
        user.userdata.metadata = dict()
        user.userdata.save()
        self.user = user.userdata
        user_code = Code(
            user=user.userdata,
            code='AAAAAAAA',
            auth_event_id=auth_event.pk
        )
        user_code.save()
        user_message = Message(
            tlf=user.userdata.tlf,
            auth_event_id=auth_event.pk
        )
        user_message.save()

        user_acl = ACL(
            user=user.userdata, 
            object_type='AuthEvent', 
            perm='edit', 
            object_id=auth_event.pk)
        user_acl.save()

        user2 = User(username='test2',email='test2@sequentech.io')
        user2.is_active = False
        user2.save()
        user2.userdata.tlf = '+34766666666'
        user2.userdata.event = auth_event
        user2.userdata.metadata = dict()
        user2.userdata.save()
        user_code = Code(
            user=user2.userdata,
            code='BBAABBAA',
            auth_event_id=auth_event.pk
        )
        user_code.save()

    def test_method_email_authenticate_valid_code(self):
        data = {
            'code': 'AAAAAAAA',
            'email': 'test@sequentech.io',
        }
        response = self.client.authenticate(self.aeid, data)

        r = parse_json_response(response)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(r.get('username'), 'test1')

    def test_method_email_authenticate_invalid_code(self):
        data = {
            'code': 'AAAAAAAA2',
            'email': 'test@sequentech.io',
        }
        response = self.client.authenticate(self.aeid, data)

        r = parse_json_response(response)
        self.assertEqual(response.status_code, 400)

    def test_method_alt_sms_authenticate_valid_code(self):
        data = {
            'alt_auth_method_id': 'sms',
            'code': 'AAAAAAAA',
            'tlf': '+34666666666',
        }
        response = self.client.authenticate(self.aeid, data)

        r = parse_json_response(response)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(r.get('username'), 'test1')

    def test_method_alt_sms_authenticate_invalid_alt_method1(self):
        data = {
            'alt_auth_method_id': 'invalid',
            'code': 'AAAAAAAA',
            'tlf': '+34666666666',
        }
        response = self.client.authenticate(self.aeid, data)

        r = parse_json_response(response)
        self.assertEqual(response.status_code, 400)

    def test_method_alt_sms_authenticate_invalid_alt_method2(self):
        data = {
            'code': 'AAAAAAAA',
            'tlf': '+34666666666',
        }
        response = self.client.authenticate(self.aeid, data)

        r = parse_json_response(response)
        self.assertEqual(response.status_code, 400)

    def test_method_alt_sms_authenticate_invalid_auth(self):
        data = {
            'alt_auth_method_id': 'invalid',
            'code': 'AAAAAAAA',
            'email': 'test@sequentech.io',
        }
        response = self.client.authenticate(self.aeid, data)

        r = parse_json_response(response)
        self.assertEqual(response.status_code, 400)

class AuthMethodAltSendCodes(TestCase):
    '''
    Tests that the URL variables related to sending authentication codes for
    alternative authentication methods work fine.
    '''
    def setUpTestData():
        flush_db_load_fixture()

    def setUp(self):
        # super-admin event
        self.aeid_special = 1

        # admin user config
        admin_user = User(
            username=test_data.admin['username'], 
            email=test_data.admin['email']
        )
        admin_user.set_password(test_data.admin['password'])
        admin_user.save()
        admin_user.userdata.event = AuthEvent.objects.get(pk=1)
        admin_user.userdata.save()
        self.admin_user = admin_user

        self.admin_auth_data = dict(
            email=test_data.admin['email'],
            code="ERGERG"
        )
        admin_code = Code(
            user=self.admin_user.userdata,
            code=self.admin_auth_data['code'],
            auth_event_id=self.aeid_special
        )
        admin_code.save()
        
        admin_acl = ACL(
            user=self.admin_user.userdata, 
            object_type='AuthEvent', 
            perm='create',
            object_id=0
        )
        admin_acl.save()

        # auth event for testing
        self.client = JClient()
        response = self.client.authenticate(
            self.aeid_special, self.admin_auth_data
        )
        self.assertEqual(response.status_code, 200)
        response = self.client.post('/api/auth-event/', auth_event_1)
        self.assertEqual(response.status_code, 200)
        response = parse_json_response(response)
        self.aeid = response['id']
        auth_event = AuthEvent.objects.get(pk=self.aeid)
        auth_event.status = AuthEvent.STARTED
        auth_event.save()
    
        # election user 1
        user = User(username='test1', email='test@sequentech.io')
        user.save()
        user.userdata.event = auth_event
        user.userdata.tlf = '+34666666666'
        user.userdata.metadata = dict()
        user.userdata.save()
        self.user = user.userdata
        user_code = Code(
            user=user.userdata,
            code='AAAAAAAA',
            auth_event_id=auth_event.pk
        )
        user_code.save()
        user_message = Message(
            tlf=user.userdata.tlf,
            auth_event_id=auth_event.pk
        )
        user_message.save()

        user_acl = ACL(
            user=user.userdata, 
            object_type='AuthEvent', 
            perm='vote', 
            object_id=auth_event.pk)
        user_acl.save()
    
    @patch("utils.send_email")
    def test_send_simple_email(self, send_email):
        '''
        Check that a simple URL replacement works fine
        '''
        # authenticate as admin
        response = self.client.authenticate(
            self.aeid_special, self.admin_auth_data
        )
        self.assertEqual(response.status_code, 200)

        emails = []
        def send_email_mock(email):
            emails.append(email)

        send_email.side_effect = send_email_mock

        # send authentication codes to election users
        response = self.client.post(
            f'/api/auth-event/{self.aeid}/census/send_auth/',
            dict(
                subject='whatever',
                msg='something something __URL__ something'
            )
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(emails, 1)
        self.assertEqual(
            emails[0].body,
            'something something https://sequent.example.com/#/election/2/public/login/test@sequentech.io something\n\n -- Sequent https://sequentech.io'
        )
    
    @patch("utils.send_email")
    def test_send_simple_email(self, send_email):
        '''
        Check that a simple URL replacement works fine
        '''
        # authenticate as admin
        response = self.client.authenticate(
            self.aeid_special, self.admin_auth_data
        )
        self.assertEqual(response.status_code, 200)

        emails = []
        def send_email_mock(email):
            emails.append(email)

        send_email.side_effect = send_email_mock

        # send authentication codes to election users
        response = self.client.post(
            f'/api/auth-event/{self.aeid}/census/send_auth/',
            dict(
                subject='whatever',
                msg='something something __URL__ something'
            )
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(emails), 1)
        self.assertEqual(
            emails[0].body,
            'something something https://sequent.example.com/#/election/2/public/login/test@sequentech.io something\n\n -- Sequent https://sequentech.io'
        )
    
    @patch("utils.send_email")
    def test_send_alt_urls_email(self, send_email):
        '''
        Check that alt URLs replacement works fine
        '''
        # authenticate as admin
        response = self.client.authenticate(
            self.aeid_special, self.admin_auth_data
        )
        self.assertEqual(response.status_code, 200)

        emails = []
        def send_email_mock(email):
            emails.append(email)

        send_email.side_effect = send_email_mock

        # send authentication codes to election users
        response = self.client.post(
            f'/api/auth-event/{self.aeid}/census/send_auth/',
            dict(
                subject='whatever',
                msg='''
                Hello!
                You can authenticate in multiple ways:
                - email: __URL__
                - direct email: __URL2__
                - sms: __URL_SMS__
                - sms direct: __URL2_SMS__
                Regards,
                '''
            )
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(emails), 1)
        import pdb; pdb.set_trace()
        self.assertEqual(
            emails[0].body,
            ''''
                Hello!
                You can authenticate in multiple ways:
                - email: https://sequent.example.com/#/election/2/public/login/test@sequentech.io
                - direct email: https://sequent.example.com/#/election/2/public/login/test@sequentech.io/AAAAAAAA
                - sms: https://sequent.example.com/election/2/public/login//sms/?tlf=%2B34666666666
                - sms direct: https://sequent.example.com/election/2/public/login//sms/?tlf=%2B34666666666&code=AAAAAAAA
                Regards,
                

 -- Sequent https://sequentech.io'''
        )
