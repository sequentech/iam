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
from django.utils.text import slugify
from django.test import TestCase
from django.contrib.auth.models import User

from . import test_data
from .models import ACL, AuthEvent
from authmethods.models import Code
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
    Fixes auth_event config adding slugs to extra_fields
    '''
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
