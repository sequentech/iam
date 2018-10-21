# This file is part of authapi.
# Copyright (C) 2018  Agora Voting SL <agora@agoravoting.com>

# authapi is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License.

# authapi  is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.

# You should have received a copy of the GNU Affero General Public License
# along with authapi.  If not, see <http://www.gnu.org/licenses/>.

from . import register_method
from utils import genhmac
from utils import json_response
from utils import stack_trace_str
from authmethods.utils import *

from django.conf import settings
from django.contrib.auth.models import User
from django.conf.urls import url
from django.db.models import Q
from django.contrib.auth.signals import user_logged_in

import requests
import json
import logging

from oic.oic import Client
from oic.oic.message import ProviderConfigurationResponse, RegistrationResponse
from oic.utils.authn.client import CLIENT_AUTHN_METHOD

LOGGER = logging.getLogger('authapi')


def testview(request, param):
    data = {'status': 'ok'}
    return json_response(data)


class OpenIdConnect(object):
    '''
    Allows authentication with OpenID Connect 1.0

    Reference standard:
    https://openid.net/specs/openid-connect-core-1_0.html
    '''

    DESCRIPTION = 'Authenticate using OpenID Connect 1.0'
    CONFIG = {}
    PIPELINES = {
        "register-pipeline": [],
        "authenticate-pipeline": [],
        'give_perms': [
            {'object_type': 'UserData', 'perms': ['edit',], 'object_id': 'UserDataId' },
            {'object_type': 'AuthEvent', 'perms': ['vote',], 'object_id': 'AuthEventId' }
        ],
    }
    USED_TYPE_FIELDS = ['sub']
    sub_definition = {
      "name": "sub",
      "type": "text",
      "required": True,
      "min": 1,
      "max": 255,
      "required_on_authentication": True
    }

    PROVIDERS = dict()

    def __init__(self):
        for conf in settings.OPENID_CONNECT_PROVIDERS_CONF:
            client = Client(client_authn_method=CLIENT_AUTHN_METHOD)

            client.provider_info = ProviderConfigurationResponse(
                version='1.0',
                **conf['public_info']
            )
            registration_data = dict(
              client_id=conf['public_info']['client_id'],
              **conf["private_config"]
            )
            registration_response = RegistrationResponse().from_dict(registration_data)
            client.store_registration_info(registration_response)

            self.PROVIDERS[conf['public_info']['id']] = dict(
                conf=conf,
                client=client
            )

    def check_config(self, config):
        return ''

    def resend_auth_code(self, config):
        return {'status': 'ok'}

    def census(self, ae, request):
        return {'status': 'ok'}

    def authenticate_error(self, error, req, ae):
        d = {'status': 'nok'}
        LOGGER.error(\
            "OpenIdConnect.authenticate error\n"\
            "error '%r'\n"\
            "request '%r'\n"\
            "authevent '%r'\n"\
            "Stack trace: \n%s",\
            error, req, ae, stack_trace_str())
        return d

    def authenticate(self, ae, request, mode='authenticate'):
        d = {'status': 'ok'}
        req = json.loads(request.body.decode('utf-8'))
        id_token = req.get('id_token', '')
        provider_id = req.get('provider', '')
        nonce = req.get('nonce', '')

        if provider_id not in self.PROVIDERS:
            return self.authenticate_error("invalid-provider", req, ae)

        #msg = ""
        #msg += check_fields_in_request(req, ae, 'authenticate')
        #if msg:
            #return self.authenticate_error("invalid-fields-check", req, ae)

        #try:
            #q = Q(userdata__event=ae, is_active=True)
            #if 'email' in req:
                #q = q & Q(email=email)
            #elif not settings.MAKE_LOGIN_KEY_PRIVATE:
                #return self.authenticate_error("no-email-provided", req, ae)

            #q = get_required_fields_on_auth(req, ae, q)
            #u = User.objects.get(q)
        #except:
            #return self.authenticate_error("user-not-found", req, ae)

        #msg = check_pipeline(request, ae, 'authenticate')
        #if msg:
            #return self.authenticate_error("invalid-pipeline", req, ae)

        #if mode == "authenticate":
            #if not u.check_password(pwd):
                #return self.authenticate_error("invalid-password", req, ae)

            #if (ae.num_successful_logins_allowed > 0 and
                #u.userdata.successful_logins.filter(is_active=True).count() >= ae.num_successful_logins_allowed):
                #return self.authenticate_error(
                    #"invalid_num_successful_logins_allowed", req, ae)

            #user_logged_in.send(sender=u.__class__, request=request, user=u)
            #u.save()

            #d['username'] = u.username
            #d['auth-token'] = genhmac(settings.SHARED_SECRET, u.username)

            ## add redirection
            #auth_action = ae.auth_method_config['config']['authentication-action']
            #if auth_action['mode'] == 'go-to-url':
                #data['redirect-to-url'] = auth_action['mode-config']['url']

        LOGGER.debug(\
            "OpenIdConnect.authenticate success\n"\
            "returns '%r'\n"\
            "authevent '%r'\n"\
            "request '%r'\n"\
            "Stack trace: \n%s",\
            d, ae, req, stack_trace_str())
        return d

    def public_census_query(self, ae, request):
        # whatever
        return self.authenticate(ae, request, "census-query")

    views = [
        url(r'^test/(\w+)$', testview),
    ]


register_method('openid-connect', OpenIdConnect)
