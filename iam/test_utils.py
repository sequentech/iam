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

class CheckAltAuthMethodsTestCase(TestCase):
    '''
    Checks check_alt_auth_methods() works as expected
    '''

    def test_empty(self):
        '''
        Test when empty
        '''
        ret = check_alt_auth_methods(
            alternative_auth_methods=None, extra_fields=[]
        )
        self.assertEqual(ret, '')

        ret = check_alt_auth_methods(
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
        )
        self.assertEqual(ret, '')

    def test_basic(self):
        ret = check_alt_auth_methods(
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
                    "icon": "{null/name/url}"
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
        )
        self.assertEqual(ret, '')
