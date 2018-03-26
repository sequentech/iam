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
import logging
from . import register_method
from utils import genhmac
from django.conf import settings
from django.contrib.auth.models import User
from django.conf.urls import url
from django.db.models import Q

from utils import json_response
from utils import stack_trace_str
from authmethods.utils import *


LOGGER = logging.getLogger('authapi')


def testview(request, param):
    data = {'status': 'ok'}
    return json_response(data)


class EmailPWD:
    DESCRIPTION = 'Register using email and password. '
    CONFIG = {}
    PIPELINES = {
        "register-pipeline": [],
        "authenticate-pipeline": [],
        'give_perms': [
            {'object_type': 'UserData', 'perms': ['edit',], 'object_id': 'UserDataId' },
            {'object_type': 'AuthEvent', 'perms': ['vote',], 'object_id': 'AuthEventId' }
        ],
    }
    USED_TYPE_FIELDS = ['email', 'password']
    email_definition = { "name": "email", "type": "email", "required": True, "min": 4, "max": 255, "required_on_authentication": True }
    password_definition = { "name": "password", "type": "password", "required": True, "min": 3, "max": 200, "required_on_authentication": True }

    def check_config(self, config):
        return ''

    def resend_auth_code(self, config):
        return {'status': 'ok'}

    def census(self, ae, request):
        req = json.loads(request.body.decode('utf-8'))
        validation = req.get('field-validation', 'enabled') == 'enabled'

        msg = ''
        emails = []
        for r in req.get('census'):
            email = r.get('email')
            password = r.get('password')
            msg += check_field_type(self.email_definition, email)
            msg += check_field_type(self.password_definition, password)
            if validation:
                msg += check_field_type(self.email_definition, email)
                msg += check_field_value(self.email_definition, email)
                msg += check_field_type(self.password_definition, password)
                msg += check_field_value(self.password_definition, password)

            msg += check_fields_in_request(r, ae, 'census', validation=validation)
            if validation:
                msg += exist_user(r, ae)
                if email in emails:
                    msg += "Email %s repeat in this census." % email
                emails.append(email)
            else:
                if msg:
                    LOGGER.debug(\
                        "EmailPWD.census warning\n"\
                        "error (but validation disabled) '%r'\n"\
                        "request '%r'\n"\
                        "validation '%r'\n"\
                        "authevent '%r'\n"\
                        "Stack trace: \n%s",\
                        msg, req, validation, ae, stack_trace_str())
                    msg = ''
                    continue
                exist = exist_user(r, ae)
                if exist and not exist.count('None'):
                    continue
                # By default we creates the user as active we don't check
                # the pipeline
                u = create_user(r, ae, True, request.user, password=password)
                give_perms(u, ae)
        if msg and validation:
            LOGGER.error(\
                "EmailPWD.census error\n"\
                "error '%r'\n"\
                "request '%r'\n"\
                "validation '%r'\n"\
                "authevent '%r'\n"\
                "Stack trace: \n%s",\
                msg, req, validation, ae, stack_trace_str())
            return self.error("Incorrect data", error_codename="invalid_credentials")

        if validation:
            for r in req.get('census'):
                # By default we creates the user as active we don't check
                # the pipeline
                u = create_user(r, ae, True, request.user, password=password)
                give_perms(u, ae)
        
        ret = {'status': 'ok'}
        LOGGER.debug(\
            "EmailPWD.census\n"\
            "request '%r'\n"\
            "validation '%r'\n"\
            "authevent '%r'\n"\
            "returns '%r'\n"\
            "Stack trace: \n%s",\
            req, validation, ae, ret, stack_trace_str())
        return ret

    def authenticate_error(self):
        d = {'status': 'nok'}
        return d

    def authenticate(self, ae, request):
        d = {'status': 'ok'}
        req = json.loads(request.body.decode('utf-8'))
        email = req.get('email', '')
        pwd = req.get('password', '')

        try:
            u = User.objects.get(userdata__event=ae, is_active=True, email=email)
        except:
            return self.authenticate_error()

        if not u.check_password(pwd):
            return self.authenticate_error()

        if (ae.num_successful_logins_allowed > 0 and
            u.userdata.successful_logins.filter(is_active=True).count() >= ae.num_successful_logins_allowed):
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


register_method('email-and-password', EmailPWD)
