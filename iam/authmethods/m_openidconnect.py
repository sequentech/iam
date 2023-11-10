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

from utils import (
    ErrorCodes,
    verify_admin_generated_auth_code
)
from authmethods.utils import (
    verify_children_election_info,
    check_fields_in_request,
    verify_valid_children_elections,
    exists_unique_user,
    exist_user,
    add_unique_user,
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

from marshmallow import (
    Schema,
    fields as marshmallow_fields,
    validate
)
from marshmallow.exceptions import ValidationError as MarshMallowValidationError

from contracts.base import JsonTypeEncoder

LOGGER = logging.getLogger('iam')


def testview(request, param):
    data = {'status': 'ok'}
    return json_response(data)



class OIDCConfigSchema(Schema):
    provider_names = marshmallow_fields.List(
        marshmallow_fields.String,
        validate=[validate.Length(min=1)]
    )

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

    providers = dict()

    def init_providers(self, auth_event):
        provider_names = OIDCConfigSchema()\
            .load(auth_event.auth_method_config['config']).provider_names
        self.providers = dict()

        for provider_name in provider_names:
            provider = next(
                (
                    provider
                    for provider in auth_event.oidc_providers
                    if provider["id"] == provider_name
                ),
                None
            )
            keyjar = KeyJar()
            keyjar.add(
                provider["issuer"],
                provider["jwks_uri"]
            )

            client = Client(
                client_authn_method=CLIENT_AUTHN_METHOD,
                keyjar=keyjar
            )

            client.provider_info = ProviderConfigurationResponse(
                version='1.0',
                **provider["public_info"]
            )
            registration_data = dict(
              client_id=provider.client_id,
                **provider["private_info"]
            )
            registration_response = RegistrationResponse().from_dict(registration_data)
            client.store_registration_info(registration_response)

            self.providers[provider["id"]] = dict(
                provider=provider,
                client=client
            )

    def check_config(self, config):
        """
        Check config when creating the auth-event.
        """
        if config is None:
            return ''
        try:
            OIDCConfigSchema.validate(config)
            ret_value = ''
            LOGGER.debug(
                "OpenId.check_config success\n"
                f"config '{config}'\n"
                f"returns '{ret_value}'"
                f"Stack trace: \n{stack_trace_str()}"
            )
            return ret_value
        except MarshMallowValidationError as error:
            ret_value = json.dumps(error.messages, cls=JsonTypeEncoder)
            LOGGER.error(
                "OpenId.check_config error\n"
                f"config '{config}'\n"
                f"returns '{ret_value}'"
                f"Stack trace: \n{stack_trace_str()}"
            )
            return ret_value

    def census(self, auth_event, request):
        req = json.loads(request.body.decode('utf-8'))
        validation = req.get('field-validation', 'enabled') == 'enabled'

        msg = ''
        unique_users = dict()
        
        # cannot add voters to an election with invalid children election info
        if auth_event.children_election_info is not None:
            try:
                verify_children_election_info(
                    auth_event, request.user, ['edit', 'census-add']
                )
            except:
                return self.error(
                    "Incorrect data",
                    error_codename="invalid_data",
                    internal_error=(
                        f"request '{req}'\n"
                        f"error in verify_children_election_info '{msg}'"
                    ),
                    auth_event=auth_event,
                    method_name="census",
                )

        for census_element in req.get('census'):
            msg += check_fields_in_request(
              census_element, 
              auth_event, 
              'census', 
              validation=validation
            )

            if auth_event.children_election_info is not None:
                try:
                    verify_valid_children_elections(auth_event, census_element)
                except:
                    return self.error(
                        "Incorrect data",
                        error_codename="invalid_data",
                        internal_error=(
                            f"request '{req}'\n"
                            f"error in verify_valid_children_elections '{msg}'"
                        ),
                        auth_event=auth_event,
                        method_name="census",
                    )

            if validation:
                exists, extra_msg = exists_unique_user(
                    unique_users,
                    census_element,
                    auth_event
                )
                msg += extra_msg
                if not exists:
                    add_unique_user(
                        unique_users,
                        census_element,
                        auth_event
                    )
                    msg += exist_user(census_element, auth_event)
            else:
                if msg:
                    LOGGER.debug(
                        "OpenIdConnect.census warning\n"
                        f"error (but validation disabled) '{msg}'\n"
                        f"request '{req}'\n"
                        f"validation '{validation}'\n"
                        f"authevent '{auth_event}'\n"
                        f"returns '{ret}'\n"
                        f"Stack trace: \n{stack_trace_str()}"
                    )
                    msg = ''
                    continue
                exist = exist_user(census_element, auth_event)
                if exist and not exist.count('None'):
                    continue
                # By default we creates the user as active we don't check
                # the pipeline
                u = create_user(census_element, auth_event, True, request.user)
                give_perms(u, auth_event)
        if msg and validation:
            return self.error(
                "Incorrect data",
                error_codename="invalid_credentials",
                internal_error=f"request '{req}'\n msg=`{msg}`",
                auth_event=auth_event,
                method_name="census"
            )

        if validation:
            for census_element in req.get('census'):
                # By default we creates the user as active we don't check
                # the pipeline
                u = create_user(census_element, auth_event, True, request.user)
                give_perms(u, auth_event)
        
        ret = {'status': 'ok'}
        LOGGER.debug(
            "OpenIdConnect.census\n"
            f"request '{req}'\n"
            f"validation '{validation}'\n"
            f"authevent '{auth_event}'\n"
            f"returns '{ret}'\n"
            f"Stack trace: \n{stack_trace_str()}"
        )
        return ret

    def error(
            self, 
            msg, 
            auth_event=None,
            error_codename=None,
            internal_error=None,
            method_name="error",
        ):
        data = {'status': 'nok', 'msg': msg, 'error_codename': error_codename}
        LOGGER.error(
            f"OpenIdConnect.{method_name}\n"
            f"internal_error '{internal_error}'\n"
            f"error_codename '{error_codename}'\n"
            f"returning error '{data}'\n"
            f"auth_event '{auth_event}'\n"
            f"Stack trace: \n{stack_trace_str()}"
        )
        return data

    def authenticate(self, auth_event, request, mode='authenticate'):
        try:
            self.init_providers(self.auth_event)
        except MarshMallowValidationError as error:
            return self.error(
                ErrorCodes.INTERNAL_SERVER_ERROR,
                error_codename=ErrorCodes.INTERNAL_SERVER_ERROR,
                internal_error=(
                    f"request '{req}'\n"
                    f"error parsing config '{error}'"
                ),
                auth_event=auth_event,
                method_name="authenticate",
            )

        ret_data = {'status': 'ok'}
        req = json.loads(request.body.decode('utf-8'))
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
                    error_codename=ErrorCodes.CANT_VOTE_MORE_TIMES,
                    internal_error=(
                        f"request '{req}'\n"
                        f"error in verify_num_successful_logins"
                    ),
                    auth_event=auth_event,
                    method_name="authenticate",
                )

            return return_auth_data('OpenIdConnect', req, request, user)

        if auth_event.parent is not None:
            return self.error(
                msg,
                error_codename=ErrorCodes.CANT_AUTHENTICATE_TO_PARENT,
                internal_error=(
                    f"request '{req}'\n"
                    f"auth_event.parent is not None"
                ),
                auth_event=auth_event,
                method_name="authenticate",
            )

        id_token = req.get('id_token', '')
        provider_id = req.get('provider', '')
        nonce = req.get('nonce', '')

        if provider_id not in self.providers:
            return self.error(
                ErrorCodes.INVALID_FIELD_VALIDATION,
                error_codename=ErrorCodes.INVALID_FIELD_VALIDATION,
                internal_error=(
                    f"request '{req}'\n"
                    f"provider-id '{provider_id}' not found"
                ),
                auth_event=auth_event,
                method_name="authenticate",
            )

        provider = self.providers[provider_id]
        # parses and verifies/validates the id token
        id_token_obj = provider['client'].parse_response(
            AuthorizationResponse,
            info=id_token,
            sformat="jwt",
            keyjar=provider['client'].keyjar,
            scope="openid"
        )
        if not id_token_obj:
            return self.error(
                ErrorCodes.INVALID_REQUEST,
                error_codename=ErrorCodes.INVALID_REQUEST,
                internal_error=(
                    f"request '{req}'\n"
                    f"invalid-id-token, id_token_obj is empty"
                ),
                auth_event=auth_event,
                method_name="authenticate",
            )

        # verify nonce securely
        id_token_dict = id_token_obj.to_dict()
        if not constant_time_compare(id_token_dict['nonce'], nonce):
            return self.error(
                ErrorCodes.INVALID_REQUEST,
                error_codename=ErrorCodes.INVALID_REQUEST,
                internal_error=(
                    f"request '{req}'\n"
                    f"invalid-nonce, {id_token_dict['nonce']} != {nonce}"
                ),
                auth_event=auth_event,
                method_name="authenticate",
            )

        # verify client_id
        if not constant_time_compare(
            id_token_dict['aud'], 
            provider['conf']['public_info']['client_id']
        ):
            return self.error(
                ErrorCodes.INVALID_REQUEST,
                error_codename=ErrorCodes.INVALID_REQUEST,
                internal_error=(
                    f"request '{req}'\n"
                    f"invalid-aud, {id_token_dict['aud']} != {provider['conf']['public_info']['client_id']}"
                ),
                auth_event=auth_event,
                method_name="authenticate",
            )

        # verify expiration
        current_timestamp = utc_time_sans_frac()
        if id_token_dict['exp'] < current_timestamp:
            return self.error(
                ErrorCodes.INVALID_REQUEST,
                error_codename=ErrorCodes.INVALID_REQUEST,
                internal_error=(
                    f"request '{req}'\n"
                    f"invalid-exp, {id_token_dict['exp']} >= {current_timestamp}"
                ),
                auth_event=auth_event,
                method_name="authenticate",
            )

        msg = check_pipeline(request, auth_event, 'authenticate')
        if msg:
            return self.error(
                ErrorCodes.PIPELINE_INVALID_CREDENTIALS,
                internal_error=(
                    f"request '{req}'\n"
                    f"msg '{msg}'"
                ),
                auth_event=auth_event,
                error_codename=ErrorCodes.PIPELINE_INVALID_CREDENTIALS
            )

        # get user_id and get/create user
        user_id = id_token_dict['sub']
        try:
            user_query = get_base_auth_query(auth_event)
            user_query["userdata__metadata__contains"]={"sub": user_id}
            user = User.objects.get(user_query)
        except Exception as error:
            msg += f"can't find user with query: `{str(q)}`\nexception: `{error}`\n"
            if auth_event.census == 'close':
                return self.error(
                    msg=ErrorCodes.USER_NOT_FOUND,
                    internal_error=(
                        f"request '{req}'\n"
                        f"msg '{msg}'"
                    ),
                    auth_event=auth_event,
                    error_codename=ErrorCodes.USER_NOT_FOUND
                )
            else:
                user = create_user(
                    req=dict(sub=user_id),
                    ae=auth_event,
                    active=True,
                    creator=request.user
                )
                give_perms(user, auth_event)

        if not verify_num_successful_logins(
            auth_event, 'OpenIdConnect', user, req
        ):
            return self.error(
                ErrorCodes.CANT_VOTE_MORE_TIMES,
                internal_error=(
                    f"request '{req}'\n"
                    f"error in verify_num_successful_logins"
                ),
                auth_event=auth_event,
                error_codename=ErrorCodes.CANT_VOTE_MORE_TIMES
            )

        LOGGER.debug(
            "OpenIdConnect.authenticate success\n"
            "OpenIdConnect.census\n"
            f"request '{req}'\n"
            f"id_token_dict '{id_token_dict}'\n"
            f"authevent '{auth_event}'\n"
            f"returns '{ret_data}'\n"
            f"Stack trace: \n{stack_trace_str()}"
        )
        return return_auth_data(
            'OpenIdConnect', 
            req, 
            request, 
            user,
            auth_event, 
            extra_debug="id_token_dict '%r'\n" % id_token_dict
        )

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
