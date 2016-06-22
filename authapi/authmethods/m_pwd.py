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

import json
from . import register_method
from utils import genhmac
from django.conf import settings
from django.contrib.auth.models import User
from django.conf.urls import url
from django.db.models import Q

from utils import json_response


def testview(request, param):
    data = {'status': 'ok'}
    return json_response(data)


class PWD:
    DESCRIPTION = 'Register using user and password. '
    CONFIG = {}
    PIPELINES = {
        "register-pipeline": [],
        "authenticate-pipeline": []
    }

    def authenticate_error(self):
        d = {'status': 'nok'}
        return d

    def authenticate(self, ae, request):
        d = {'status': 'ok'}
        req = json.loads(request.body.decode('utf-8'))
        email = req.get('email', '')
        pwd = req.get('password', '')

        try:
            u = User.objects.get(email=email, userdata__event=ae, is_active=True)
        except:
            return self.authenticate_error()

        if not u.check_password(pwd):
            return self.authenticate_error()

        d['username'] = u.username
        d['auth-token'] = genhmac(settings.SHARED_SECRET, u.username)

        # add redirection
        auth_action = ae.auth_method_config['config']['authentication-action']
        if auth_action['mode'] == 'go-to-url':
            data['redirect-to-url'] = auth_action['mode-config']['url']
        return d

    views = [
        url(r'^test/(\w+)$', testview),
    ]


register_method('user-and-password', PWD)
