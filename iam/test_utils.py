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
    def test_empty_auth_method(self):
        ret = check_alt_auth_methods(None, {})
        self.assertEqual(ret, '')
