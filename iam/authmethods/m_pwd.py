# This file is part of iam.
# Copyright (C) 2014-2020  Sequent Tech Inc <legal@sequentech.io>

# iam is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License.

# iam  is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.

# You should have received a copy of the GNU Affero General Public License
# along with iam.  If not, see <http://www.gnu.org/licenses/>.

import json
import logging
from . import register_method
from django.contrib.auth.models import User
from django.conf.urls import url

from utils import (
    ErrorCodes,
    verify_admin_generated_auth_code
)
from authmethods.utils import (
    check_fields_in_request,
    exists_unique_user,
    add_unique_user,
    exist_user,
    create_user,
    give_perms,
    check_pipeline,
    verify_num_successful_logins,
    return_auth_data,
    check_field_type,
    check_field_value,
    get_base_auth_query,
    get_required_fields_on_auth,
    post_verify_fields_on_auth,
    resend_auth_code,
    generate_auth_code,
    stack_trace_str,
    json_response,
    authenticate_otl
)

from contracts.base import check_contract, JsonTypeEncoder
from contracts import CheckException

LOGGER = logging.getLogger('iam')


def testview(request, param):
    data = {'status': 'ok'}
    return json_response(data)


class Password:
    DESCRIPTION = 'Register using user and password. '
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
        types=['password'],
        names=['username']
    )
    username_definition = {
        "name": "username",
        "type": "text",
        "unique": True,
        "required": True,
        "min": 3, 
        "max": 200,
        "required_on_authentication": True
    }
    password_definition = {
        "name": "password",
        "type": "password",
        "required": True,
        "min": 3,
        "max": 200,
        "required_on_authentication": True
    }

    CONFIG_CONTRACT = [
      {
        'check': 'isinstance',
        'type': dict
      },
      {
          'check': 'index-check-list',
          'index': 'msg_i18n',
          'optional': True,
          'check-list': [
              {
                  'check': 'isinstance',
                  'type': dict
              },
              {   # keys are strings
                  'check': 'lambda',
                  'lambda': lambda d: all([isinstance(k, str) for k in d.keys()])
              },
              {   # values are strings
                  'check': 'lambda',
                  'lambda': lambda d: all([isinstance(k, str) for k in d.values()])
              },
          ]
      },
      {
          'check': 'index-check-list',
          'index': 'subject_i18n',
          'optional': True,
          'check-list': [
              {
                  'check': 'isinstance',
                  'type': dict
              },
              {   # keys are strings
                  'check': 'lambda',
                  'lambda': lambda d: all([isinstance(k, str) for k in d.keys()])
              },
              {   # values are strings
                  'check': 'lambda',
                  'lambda': lambda d: all([isinstance(k, str) for k in d.values()])
              },
          ]
      }
    ]

    def check_config(self, config):
        """ Check config when create auth-event. """
        if config is None:
            return ''
        try:
            check_contract(self.CONFIG_CONTRACT, config)
            LOGGER.debug(\
                "OpenId.check_config success\n"\
                "config '%r'\n"\
                "returns ''\n"\
                "Stack trace: \n%s",\
                config, stack_trace_str())
            return ''
        except CheckException as e:
            LOGGER.error(\
                "OpenId.check_config error\n"\
                "error '%r'\n"\
                "config '%r'\n"\
                "Stack trace: \n%s",\
                e.data, config, stack_trace_str())
            return json.dumps(e.data, cls=JsonTypeEncoder)


    def census(self, auth_event, request):
        req = json.loads(request.body.decode('utf-8'))
        validation = req.get('field-validation', 'enabled') == 'enabled'

        msg = ''
        unique_users = dict()
        for census_element in req.get('census'):
            username = census_element.get('username')
            password = census_element.get('password')
            msg += check_field_type(self.username_definition, username)
            msg += check_field_type(self.password_definition, password)
            if validation:
                msg += check_field_type(self.username_definition, username)
                msg += check_field_value(self.username_definition, username)
                msg += check_field_type(self.password_definition, password)
                msg += check_field_value(self.password_definition, password)

            msg += check_fields_in_request(
                census_element,
                auth_event,
                'census',
                validation=validation
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
                    LOGGER.debug(\
                        "UserPassword.census warning\n"\
                        "error (but validation disabled) '%r'\n"\
                        "request '%r'\n"\
                        "validation '%r'\n"\
                        "authevent '%r'\n"\
                        "Stack trace: \n%s",\
                        msg, req, validation, auth_event, stack_trace_str())
                    msg = ''
                    continue
                exist = exist_user(census_element, auth_event)
                if exist and not exist.count('None'):
                    continue
                # By default we creates the user as active we don't check
                # the pipeline
                u = create_user(
                    census_element,
                    auth_event,
                    True,
                    request.user, 
                    user=username, 
                    password=password
                )
                give_perms(u, auth_event)
        if msg and validation:
            LOGGER.error(\
                "UserPassword.census error\n"\
                "error '%r'\n"\
                "request '%r'\n"\
                "validation '%r'\n"\
                "authevent '%r'\n"\
                "Stack trace: \n%s",\
                msg, req, validation, auth_event, stack_trace_str())
            return self.error(
                "Incorrect data", 
                error_codename="invalid_credentials"
            )

        if validation:
            for census_element in req.get('census'):
                # By default we creates the user as active we don't check
                # the pipeline
                u = create_user(
                    census_element,
                    auth_event,
                    True,
                    request.user,
                    user=username,
                    password=password
                )
                give_perms(u, auth_event)
        
        ret = {'status': 'ok'}
        LOGGER.debug(\
            "UserPassword.census\n"\
            "request '%r'\n"\
            "validation '%r'\n"\
            "authevent '%r'\n"\
            "returns '%r'\n"\
            "Stack trace: \n%s",\
            req, validation, auth_event, ret, stack_trace_str())
        return ret

    def authenticate_error(self, error, req, ae):
        d = {'status': 'nok'}
        LOGGER.error(\
            "UserPassword.census error\n"\
            "error '%r'\n"\
            "request '%r'\n"\
            "authevent '%r'\n"\
            "Stack trace: \n%s",\
            error, req, ae, stack_trace_str())
        return d

    def error(
            self, msg, auth_event=None, error_codename=None, internal_error=None
        ):
        data = {'status': 'nok', 'msg': msg, 'error_codename': error_codename}
        LOGGER.error(\
            "UserPassword.error\n"\
            f"internal_error '{internal_error}'\n"\
            f"error_codename '{error_codename}'\n"\
            f"returning error '{data}'\n"\
            f"auth_event '{auth_event}'\n"\
            f"Stack trace: \n{stack_trace_str()}"
        )
        return data

    def authenticate(self, auth_event, request, mode="authenticate"):
        ret_data = {'status': 'ok'}
        req = json.loads(request.body.decode('utf-8'))
        if mode == 'authenticate':
            verified, user = verify_admin_generated_auth_code(
                auth_event=auth_event,
                req_data=req,
                log_prefix="UserPassword"
            )
            if verified:
                if not verify_num_successful_logins(
                    auth_event,
                    'UserPassword',
                    user,
                    req
                ):
                    return self.error(
                        ErrorCodes.CANT_VOTE_MORE_TIMES,
                        auth_event=auth_event,
                        error_codename=ErrorCodes.CANT_VOTE_MORE_TIMES
                    )

                return return_auth_data('UserPassword', req, request, user)

        msg = ""
        if auth_event.parent is not None:
            msg += 'you can only authenticate to parent elections'
            return self.error(
                msg,
                auth_event=auth_event,
                error_codename=ErrorCodes.CANT_AUTHENTICATE_TO_PARENT
            )

        msg += check_fields_in_request(req, auth_event, mode)
        if msg:
            return self.error(
                msg="",
                internal_error=msg,
                auth_event=auth_event,
                error_codename=ErrorCodes.INVALID_FIELD_VALIDATION
            )

        msg = check_pipeline(request, auth_event, 'authenticate')
        if msg:
            return self.error(
                msg="",
                internal_error=msg,
                auth_event=auth_event,
                error_codename=ErrorCodes.PIPELINE_INVALID_CREDENTIALS
            )
        msg = ""

        try:
            q = get_base_auth_query(auth_event)
            q = get_required_fields_on_auth(req, auth_event, q)
            user = User.objects.get(q)
        except Exception as error:
            msg += f"can't find user with query: `{str(q)}`\nexception: `{error}`\n"
            return self.error(
                msg="",
                internal_error=msg,
                auth_event=auth_event,
                error_codename=ErrorCodes.USER_NOT_FOUND
            )
        try:
            if mode == 'authenticate':
                post_verify_fields_on_auth(user, req, auth_event)
        except Exception as error:
            msg += f"exception: `{error}`\n"
            return self.error(
                msg="",
                internal_error=msg,
                auth_event=auth_event,
                error_codename=ErrorCodes.INVALID_PASSWORD_OR_CODE
            )

        if mode == "authenticate":
            if not verify_num_successful_logins(auth_event, 'UserPassword', user, req):
                return self.error(
                    ErrorCodes.CANT_VOTE_MORE_TIMES,
                    auth_event=auth_event,
                    error_codename=ErrorCodes.CANT_VOTE_MORE_TIMES
                )

            LOGGER.debug(\
                f"UserPassword.authenticate success\n"\
                "returns '%r'\n"\
                "authevent '%r'\n"\
                "request '%r'\n"\
                "Stack trace: \n%s",\
                ret_data, auth_event, req, stack_trace_str()
            )
            return return_auth_data('UserPassword', req, request, user, auth_event)

        LOGGER.debug(\
            f"UserPassword.authenticate success\n"\
            "returns '%r'\n"\
            "authevent '%r'\n"\
            "request '%r'\n"\
            "Stack trace: \n%s",\
            ret_data, auth_event, req, stack_trace_str()
        )
        return ret_data

    def public_census_query(self, ae, request):
        # whatever
        return self.authenticate(ae, request, "census-query")

    def resend_auth_code(self, auth_event, request):
        return resend_auth_code(
            auth_event=auth_event,
            request=request,
            logger_name="Password",
            default_pipelines=Password.PIPELINES
        )

    def authenticate_otl(self, auth_event, request):
        return authenticate_otl(
            auth_event=auth_event,
            request=request,
            logger_name="Password"
        )


    def generate_auth_code(self, auth_event, request):
        return generate_auth_code(
            auth_event=auth_event,
            request=request,
            logger_name="Password"
        )

    views = [
        url(r'^test/(\w+)$', testview),
    ]


register_method('user-and-password', Password)
