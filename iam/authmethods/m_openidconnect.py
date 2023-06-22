# This file is part of iam.
# Copyright (C) 2018  Sequent Tech Inc <legal@sequentech.io>

# iam is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License.

# iam  is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.

# You should have received a copy of the GNU Affero General Public License
# along with iam.  If not, see <http://www.gnu.org/licenses/>.

from . import register_method

from iam.utils import ErrorCodes
from utils import (
    verify_admin_generated_auth_code
)
from authmethods.utils import (
    create_user,
    get_base_auth_query,
    give_perms,
    check_pipeline,
    verify_num_successful_logins,
    return_auth_data,
    resend_auth_code,
    generate_auth_code,
    stack_trace_str,
    json_response,
    constant_time_compare
)

from django.conf import settings
from django.contrib.auth.models import User
from django.conf.urls import url

import json
import logging

from oic.oic import Client
from oic.oic.message import (
    ProviderConfigurationResponse,
    RegistrationResponse,
    AuthorizationResponse
)
from oic.utils.keyio import KeyJar
from oic.utils.authn.client import CLIENT_AUTHN_METHOD
from oic.utils.time_util import utc_time_sans_frac

LOGGER = logging.getLogger('iam')


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
    MANDATORY_FIELDS = dict(
        types=[],
        names=['sub']
    )
    sub_definition = {
        "name": "sub",
        "type": "text",
        "required": True,
        "min": 1,
        "max": 255,
        "unique": True,
        "required_on_authentication": True
    }

    PROVIDERS = dict()

    def __init__(self):
        for conf in settings.OPENID_CONNECT_PROVIDERS_CONF:
            keyjar = KeyJar()
            keyjar.add(
                conf['public_info']['issuer'],
                conf['public_info']['jwks_uri']
            )

            client = Client(
                client_authn_method=CLIENT_AUTHN_METHOD,
                keyjar=keyjar
            )

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

    def census(self, ae, request):
        return {'status': 'ok'}

    def authenticate_error(self, error, req, ae, message=""):
        d = {'status': 'nok'}
        LOGGER.error(\
            "OpenIdConnect.authenticate error\n"\
            "error '%r'\n"\
            "message '%r'\n"\
            "request '%r'\n"\
            "authevent '%r'\n"\
            "Stack trace: \n%s",\
            error, message, req, ae, stack_trace_str())
        return d

    def error(
            self, msg, auth_event=None, error_codename=None, internal_error=None
        ):
        data = {'status': 'nok', 'msg': msg, 'error_codename': error_codename}
        LOGGER.error(\
            "OpenIdConnect.error\n"\
            f"internal_error '{internal_error}'\n"\
            f"error_codename '{error_codename}'\n"\
            f"returning error '{data}'\n"\
            f"auth_event '{auth_event}'\n"\
            f"Stack trace: \n{stack_trace_str()}"
        )
        return data

    def authenticate(self, auth_event, request, mode='authenticate'):
        ret_data = {'status': 'ok'}
        req = json.loads(request.body.decode('utf-8'))
        if mode == 'authenticate':
            verified, user = verify_admin_generated_auth_code(
                auth_event=auth_event,
                req_data=req,
                log_prefix="OpenIdConnect"
            )
            if verified:
                if not verify_num_successful_logins(
                    auth_event,
                    'OpenIdConnect',
                    user,
                    req
                ):
                    return self.error(
                        ErrorCodes.CANT_VOTE_MORE_TIMES,
                        auth_event=auth_event,
                        error_codename=ErrorCodes.CANT_VOTE_MORE_TIMES
                    )

                return return_auth_data('OpenIdConnect', req, request, user)

        if auth_event.parent is not None:
            return self.error(
                msg,
                auth_event=auth_event,
                error_codename=ErrorCodes.CANT_AUTHENTICATE_TO_PARENT
            )

        id_token = req.get('id_token', '')
        provider_id = req.get('provider', '')
        nonce = req.get('nonce', '')

        if provider_id not in self.PROVIDERS:
            return self.authenticate_error("invalid-provider", req, auth_event)

        provider = self.PROVIDERS[provider_id]
        # parses and verifies/validates the id token
        id_token_obj = provider['client'].parse_response(
            AuthorizationResponse,
            info=id_token,
            sformat="jwt",
            keyjar=provider['client'].keyjar,
            scope="openid"
        )
        if not id_token_obj:
            return self.authenticate_error("invalid-id-token", req, auth_event,
                message="id_token_obj is empty")

        # verify nonce securely
        id_token_dict = id_token_obj.to_dict()
        if not constant_time_compare(id_token_dict['nonce'], nonce):
            return self.authenticate_error("invalid-nonce", req, auth_event,
                message="'%r' != '%r'" % (id_token_dict['nonce'], nonce))

        # verify client_id
        if not constant_time_compare(id_token_dict['aud'], provider['conf']['public_info']['client_id']):
            return self.authenticate_error("invalid-aud", req, auth_event,
                message="'%r' != '%r'" % (id_token_dict['aud'], provider['conf']['public_info']['client_id']))

        # verify expiration
        current_timestamp = utc_time_sans_frac()
        if id_token_dict['exp'] < current_timestamp:
            return self.authenticate_error("invalid-exp", req, auth_event,
                message="'%r' != '%r'" % (id_token_dict['exp'], current_timestamp))

        # get user_id and get/create user
        user_id = id_token_dict['sub']
        try:
            user_query = get_base_auth_query(auth_event)
            user_query["userdata__metadata__contains"]={"sub": user_id}
            user = User.objects.get(user_query)
        except:
            user = create_user(
                req=dict(sub=user_id),
                ae=auth_event,
                active=True,
                creator=request.user
            )
            give_perms(user, auth_event)

        msg = check_pipeline(request, auth_event, 'authenticate')
        if msg:
            return self.authenticate_error("invalid-pipeline", req, auth_event,
                message=msg)

        if mode == "authenticate":
            if not verify_num_successful_logins(auth_event, 'OpenIdConnect', user, req):
                return self.error(
                    ErrorCodes.CANT_VOTE_MORE_TIMES,
                    auth_event=auth_event,
                    error_codename=ErrorCodes.CANT_VOTE_MORE_TIMES
                )

            LOGGER.debug(\
                "OpenIdConnect.authenticate success\n"\
                "returns '%r'\n"\
                "authevent '%r'\n"\
                "id_token_dict '%r'\n"\
                "request '%r'\n"\
                "Stack trace: \n%s",\
                ret_data, auth_event, id_token_dict, req, stack_trace_str()
            )
            return return_auth_data(
                'OpenIdConnect', 
                req, 
                request, 
                user,
                auth_event, 
                extra_debug="id_token_dict '%r'\n" % id_token_dict
            )

        LOGGER.debug(\
            "OpenIdConnect.authenticate success\n"\
            "returns '%r'\n"\
            "authevent '%r'\n"\
            "id_token_dict '%r'\n"\
            "request '%r'\n"\
            "Stack trace: \n%s",\
            ret_data, auth_event, id_token_dict, req, stack_trace_str()
        )
        return ret_data

    def public_census_query(self, ae, request):
        # whatever
        return self.authenticate(ae, request, "census-query")

    def resend_auth_code(self, auth_event, request):
        return resend_auth_code(
            auth_event=auth_event,
            request=request,
            logger_name="OpenIdConnect",
            default_pipelines=OpenIdConnect.PIPELINES
        )

    def generate_auth_code(self, auth_event, request):
        return generate_auth_code(
            auth_event=auth_event,
            request=request,
            logger_name="OpenIdConnect"
        )

    views = [
        url(r'^test/(\w+)$', testview),
    ]


register_method('openid-connect', OpenIdConnect)
