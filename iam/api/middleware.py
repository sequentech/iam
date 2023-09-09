# This file is part of iam.
# Copyright (C) 2023 Sequent Tech Inc <legal@sequentech.io>

# iam is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License.

# iam  is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.

# You should have received a copy of the GNU Affero General Public License
# along with iam.  If not, see <http://www.gnu.org/licenses/>.

from threading import local
from .decorators import get_login_user

_user = local()

class CurrentUserMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        _user.value, _, _ = get_login_user(request)
        response = self.get_response(request)
        _user.value = None  # clear the user after processing the request
        return response

    @staticmethod
    def get_current_user():
        if hasattr(_user, "value"):
            return _user.value
        else:
            return None