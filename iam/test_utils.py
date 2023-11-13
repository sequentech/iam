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

from django.test import TestCase
from utils import check_alt_auth_methods

class BaseTestCase(TestCase):
    '''
    TestCase class with some fixtures
    '''
    def email_extra_fields(self):
        return [
            {
                "name": "email",
                "type": "email",
                "required": True,
                "min": 4,
                "max": 255,
                "required_on_authentication": True
            },
        ]

class CheckAltAuthMethodsTestCase(BaseTestCase):
    '''
    Checks check_alt_auth_methods() works as expected
    '''

    def test_empty(self):
        '''
        Test when empty
        '''
        # None is valid
        ret = check_alt_auth_methods(
            dict(alternative_auth_methods=None, extra_fields=[])
        )
        self.assertEqual(ret, '')

        # Empty list is valid
        ret = check_alt_auth_methods(
            dict(alternative_auth_methods=[], extra_fields=[])
        )
        self.assertEqual(ret, '')

        # None is still valid independently of the extra_fields
        ret = check_alt_auth_methods(dict(
            alternative_auth_methods=None,
            extra_fields=[
                {
                    "name": "name",
                    "help": "put the name that appear in your dni",
                    "type": "text",
                    "required": True,
                    "min": 2,
                    "max": 64,
                    "required_on_authentication": True
                },
                {
                    "name": "email",
                    "type": "email",
                    "required": True,
                    "min": 4,
                    "max": 255,
                    "required_on_authentication": True
                },
            ]
        ))
        self.assertEqual(ret, '')

    def test_basic(self):
        ret = check_alt_auth_methods(dict(
            alternative_auth_methods=[
                {
                    "id": "email",
                    "auth_method_name": "email",
                    "auth_method_config": {"msg": "Enter in __URL__ and put this code __CODE__"},
                    "extra_fields": [
                        {
                            "name": "name",
                            "help": "put the name that appear in your dni",
                            "type": "text",
                            "required": True,
                            "min": 2,
                            "max": 64,
                            "required_on_authentication": True
                        },
                        {
                            "name": "email",
                            "type": "email",
                            "required": True,
                            "min": 4,
                            "max": 255,
                            "required_on_authentication": True
                        },
                    ], 
                    "public_name": "Email",
                    "public_name_i18n": {"es": "Nombre"},
                    "icon": "icon-name"
                }
            ],
            extra_fields=[
                {
                    "name": "name",
                    "help": "put the name that appear in your dni",
                    "type": "text",
                    "required": True,
                    "min": 2,
                    "max": 64,
                    "required_on_authentication": True
                },
                {
                    "name": "email",
                    "type": "email",
                    "required": True,
                    "min": 4,
                    "max": 255,
                    "required_on_authentication": True
                },
            ]
        ))
        self.assertEqual(ret, '')

    def test_invalid_types(self):
        '''
        Test some basic sanity checks work
        '''
        # alternative_auth_methods must be a list or None, not a number
        ret = check_alt_auth_methods(
            dict(alternative_auth_methods=33, extra_fields=[])
        )
        self.assertNotEqual(ret, '')

        # alternative_auth_methods must be a list or None, not a dict
        ret = check_alt_auth_methods(
            dict(alternative_auth_methods=dict(), extra_fields=[])
        )
        self.assertNotEqual(ret, '')

        # Check the alternative auth method fails when it's not an object
        ret = check_alt_auth_methods(dict(
            alternative_auth_methods=[
                "not-an-object"
            ],
            extra_fields=[]
        ))
        self.assertNotEqual(ret, '')

        # Check the alternative auth method fails when it's not an object
        ret = check_alt_auth_methods(dict(
            alternative_auth_methods=[
                123
            ],
            extra_fields=[]
        ))
        self.assertNotEqual(ret, '')

    def test_id_field(self):
        # Check the alternative auth method fails when it's missing "id" field
        ret = check_alt_auth_methods(dict(
            alternative_auth_methods=[
                {
                    "id_": "email",
                    "auth_method_name": "email",
                    "auth_method_config": {"msg": "Enter in __URL__ and put this code __CODE__"},
                    "extra_fields": self.email_extra_fields(), 
                    "public_name": "Email",
                    "public_name_i18n": {"es": "Nombre"},
                    "icon": "icon-name"
                }
            ],
            extra_fields=self.email_extra_fields()
        ))
        self.assertNotEqual(ret, '')

        # Check the alternative auth method fails when id field is not a string
        ret = check_alt_auth_methods(dict(
            alternative_auth_methods=[
                {
                    "id": dict(email="email"),
                    "auth_method_name": "email",
                    "auth_method_config": {"msg": "Enter in __URL__ and put this code __CODE__"},
                    "extra_fields": self.email_extra_fields(), 
                    "public_name": "Email",
                    "public_name_i18n": {"es": "Nombre"},
                    "icon": "icon-name"
                }
            ],
            extra_fields=self.email_extra_fields()
        ))
        self.assertNotEqual(ret, '')

        # Check the alternative auth method works when id field is text
        ret = check_alt_auth_methods(dict(
            alternative_auth_methods=[
                {
                    "id": "email",
                    "auth_method_name": "email",
                    "auth_method_config": {"msg": "Enter in __URL__ and put this code __CODE__"},
                    "extra_fields": self.email_extra_fields(), 
                    "public_name": "Email",
                    "public_name_i18n": {"es": "Nombre"},
                    "icon": "icon-name"
                }
            ],
            extra_fields=self.email_extra_fields()
        ))
        self.assertEqual(ret, '')

    def test_id_field_duplicated(self):
        # Check the alternative auth method fails when id field is not a string
        ret = check_alt_auth_methods(dict(
            alternative_auth_methods=[
                {
                    "id": "email",
                    "auth_method_name": "email",
                    "auth_method_config": {"msg": "Enter in __URL__ and put this code __CODE__"},
                    "extra_fields": self.email_extra_fields(), 
                    "public_name": "Email",
                    "public_name_i18n": {"es": "Nombre"},
                    "icon": "icon-name"
                },
                {
                    "id": "email",
                    "auth_method_name": "email",
                    "auth_method_config": {"msg": "Enter in __URL__ and put this code __CODE__"},
                    "extra_fields": self.email_extra_fields(), 
                    "public_name": "Email",
                    "public_name_i18n": {"es": "Nombre"},
                    "icon": "icon-name"
                },
            ],
            extra_fields=self.email_extra_fields()
        ))
        self.assertNotEqual(ret, '')

        # Check the alternative auth method fails when id field is not a string
        ret = check_alt_auth_methods(dict(
            alternative_auth_methods=[
                {
                    "id": "email",
                    "auth_method_name": "email",
                    "auth_method_config": {"msg": "Enter in __URL__ and put this code __CODE__"},
                    "extra_fields": self.email_extra_fields(), 
                    "public_name": "Email",
                    "public_name_i18n": {"es": "Nombre"},
                    "icon": "icon-name"
                },
                {
                    "id": "email2",
                    "auth_method_name": "email",
                    "auth_method_config": {"msg": "Enter in __URL__ and put this code __CODE__"},
                    "extra_fields": self.email_extra_fields(), 
                    "public_name": "Email",
                    "public_name_i18n": {"es": "Nombre"},
                    "icon": "icon-name"
                },
            ],
            extra_fields=self.email_extra_fields()
        ))
        self.assertEqual(ret, '')

    def test_id_validate_other_fields(self):
        '''
        Validate other alt auth method fields
        '''
        # invalid auth_method_name type
        ret = check_alt_auth_methods(dict(
            alternative_auth_methods=[
                {
                    "id": "email",
                    "auth_method_name": 1, ## not a string
                    "auth_method_config": {"msg": "Enter in __URL__ and put this code __CODE__"},
                    "extra_fields": self.email_extra_fields(), 
                    "public_name": "Email",
                    "public_name_i18n": {"es": "Nombre"},
                    "icon": "icon-name"
                },
            ],
            extra_fields=self.email_extra_fields()
        ))
        self.assertNotEqual(ret, '')

        # inexistent auth method name
        ret = check_alt_auth_methods(dict(
            alternative_auth_methods=[
                {
                    "id": "email",
                    "auth_method_name": "email-other",
                    "auth_method_config": {"msg": "Enter in __URL__ and put this code __CODE__"},
                    "extra_fields": self.email_extra_fields(), 
                    "public_name": "Email",
                    "public_name_i18n": {"es": "Nombre"},
                    "icon": "icon-name"
                },
            ],
            extra_fields=self.email_extra_fields()
        ))
        self.assertNotEqual(ret, '')

        # invalid auth_method_config
        ret = check_alt_auth_methods(dict(
            alternative_auth_methods=[
                {
                    "id": "email",
                    "auth_method_name": "email",
                    "auth_method_config": 33,
                    "extra_fields": self.email_extra_fields(), 
                    "public_name": "Email",
                    "public_name_i18n": {"es": "Nombre"},
                    "icon": "icon-name"
                },
            ],
            extra_fields=self.email_extra_fields()
        ))
        self.assertNotEqual(ret, '')

        # invalid public_name
        ret = check_alt_auth_methods(dict(
            alternative_auth_methods=[
                {
                    "id": "email",
                    "auth_method_name": "email",
                    "auth_method_config": {"msg": "Enter in __URL__ and put this code __CODE__"},
                    "extra_fields": self.email_extra_fields(), 
                    "public_name": 1,
                    "public_name_i18n": {"es": "Nombre"},
                    "icon": "icon-name"
                },
            ],
            extra_fields=self.email_extra_fields()
        ))
        self.assertNotEqual(ret, '')

    def test_id_validate_public_name_i18n(self):
        # invalid public_name_i18n
        ret = check_alt_auth_methods(dict(
            alternative_auth_methods=[
                {
                    "id": "email",
                    "auth_method_name": "email",
                    "auth_method_config": {"msg": "Enter in __URL__ and put this code __CODE__"},
                    "extra_fields": self.email_extra_fields(), 
                    "public_name": 1,
                    "public_name_i18n": {"es": {"es": "Nombre"}},
                    "icon": "icon-name"
                },
            ],
            extra_fields=self.email_extra_fields()
        ))
        self.assertNotEqual(ret, '')

        # invalid public_name_i18n 2
        ret = check_alt_auth_methods(dict(
            alternative_auth_methods=[
                {
                    "id": "email",
                    "auth_method_name": "email",
                    "auth_method_config": {"msg": "Enter in __URL__ and put this code __CODE__"},
                    "extra_fields": self.email_extra_fields(), 
                    "public_name": 1,
                    "public_name_i18n": {"es": 11},
                    "icon": "icon-name"
                },
            ],
            extra_fields=self.email_extra_fields()
        ))
        self.assertNotEqual(ret, '')

        # valid public_name_i18n
        ret = check_alt_auth_methods(dict(
            alternative_auth_methods=[
                {
                    "id": "email",
                    "auth_method_name": "email",
                    "auth_method_config": {"msg": "Enter in __URL__ and put this code __CODE__"},
                    "extra_fields": self.email_extra_fields(), 
                    "public_name": "something",
                    "public_name_i18n": {"es": "something", "fr": "whatever"},
                    "icon": "icon-name"
                },
            ],
            extra_fields=self.email_extra_fields()
        ))
        self.assertEqual(ret, '')

    def test_id_validate_extra_fields_equal_names(self):
        '''
        extra fields should be the same name in all alt auth methods 
        '''
        # mismatched name
        ret = check_alt_auth_methods(dict(
            alternative_auth_methods=[
                {
                    "id": "email",
                    "auth_method_name": "email",
                    "auth_method_config": {"msg": "Enter in __URL__ and put this code __CODE__"},
                    "extra_fields": [
                        {
                            "name": "email-different",
                            "type": "email",
                            "required": True,
                            "min": 4,
                            "max": 255,
                            "required_on_authentication": True
                        },
                    ], 
                    "public_name": "Email",
                    "public_name_i18n": {"es": "Nombre"},
                    "icon": "icon-name"
                },
            ],
            extra_fields=[
                {
                    "name": "email",
                    "type": "email",
                    "required": True,
                    "min": 4,
                    "max": 255,
                    "required_on_authentication": True
                },
            ]
        ))
        self.assertNotEqual(ret, '')

        # extra field, called "name and surname"
        ret = check_alt_auth_methods(dict(
            alternative_auth_methods=[
                {
                    "id": "email",
                    "auth_method_name": "email",
                    "auth_method_config": {"msg": "Enter in __URL__ and put this code __CODE__"},
                    "extra_fields": [
                        {
                            "name": "email",
                            "type": "email",
                            "required": True,
                            "min": 4,
                            "max": 255,
                            "required_on_authentication": True
                        },
                        {
                            "name": "name and surname",
                            "help": "put the name that appear in your dni",
                            "type": "text",
                            "required": True,
                            "min": 2,
                            "max": 64,
                            "required_on_authentication": True
                        },
                    ], 
                    "public_name": "Email",
                    "public_name_i18n": {"es": "Nombre"},
                    "icon": "icon-name"
                },
            ],
            extra_fields=[
                {
                    "name": "email",
                    "type": "email",
                    "required": True,
                    "min": 4,
                    "max": 255,
                    "required_on_authentication": True
                },
            ]
        ))
        self.assertNotEqual(ret, '')

        # one alt auth method has different extra field name, the other is fine
        ret = check_alt_auth_methods(dict(
            alternative_auth_methods=[
                {
                    "id": "email",
                    "auth_method_name": "email",
                    "auth_method_config": {"msg": "Enter in __URL__ and put this code __CODE__"},
                    "extra_fields": [
                        {
                            "name": "email",
                            "type": "email",
                            "required": True,
                            "min": 4,
                            "max": 255,
                            "required_on_authentication": True
                        },
                        {
                            "name": "name and surname",
                            "help": "put the name that appear in your dni",
                            "type": "text",
                            "required": True,
                            "min": 2,
                            "max": 64,
                            "required_on_authentication": True
                        },
                    ], 
                    "public_name": "Email",
                    "public_name_i18n": {"es": "Nombre"},
                    "icon": "icon-name"
                },
                {
                    "id": "email-otp",
                    "auth_method_name": "email-otp",
                    "auth_method_config": {"msg": "Enter in __URL__ and put this code __CODE__"},
                    "extra_fields": [
                        {
                            "name": "email",
                            "type": "email",
                            "required": True,
                            "min": 4,
                            "max": 255,
                            "required_on_authentication": True
                        },
                    ], 
                    "public_name": "Email OTP",
                    "public_name_i18n": {"es": "Nombre"},
                    "icon": "icon-name"
                },
            ],
            extra_fields=[
                {
                    "name": "email",
                    "type": "email",
                    "required": True,
                    "min": 4,
                    "max": 255,
                    "required_on_authentication": True
                },
            ]
        ))
        self.assertNotEqual(ret, '')

    def test_id_validate_extra_fields_equal_types(self):
        '''
        extra fields should be the same type
        '''
        # mismatched type
        ret = check_alt_auth_methods(dict(
            alternative_auth_methods=[
                {
                    "id": "email",
                    "auth_method_name": "email",
                    "auth_method_config": {"msg": "Enter in __URL__ and put this code __CODE__"},
                    "extra_fields": [
                        {
                            "name": "email",
                            "type": "text",
                            "required": True,
                            "min": 4,
                            "max": 255,
                            "required_on_authentication": True
                        },
                    ], 
                    "public_name": "Email",
                    "public_name_i18n": {"es": "Nombre"},
                    "icon": "icon-name"
                },
            ],
            extra_fields=[
                {
                    "name": "email",
                    "type": "email",
                    "required": True,
                    "min": 4,
                    "max": 255,
                    "required_on_authentication": True
                },
            ]
        ))
        self.assertNotEqual(ret, '')
