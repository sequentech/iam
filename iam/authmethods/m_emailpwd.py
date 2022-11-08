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

from django.conf.urls import url
import json
import logging
from django.contrib.auth.models import User
from . import register_method

from utils import (
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
    authenticate_otl
)

LOGGER = logging.getLogger('iam')


def testview(request, param):
    data = {'status': 'ok'}
    return json_response(data)


class EmailPassword:
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
    MANDATORY_FIELDS = dict(
        types=['email', 'password'],
        names=[]
    )
    email_definition = {
        "name": "email",
        "type": "email",
        "required": True,
        "min": 4,
        "max": 255,
        "unique": True,
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

    def check_config(self, config):
        return ''

    def census(self, auth_event, request):
        req = json.loads(request.body.decode('utf-8'))
        validation = req.get('field-validation', 'enabled') == 'enabled'

        msg = ''
        unique_users = dict()
        for census_element in req.get('census'):
            email = census_element.get('email')
            password = census_element.get('password')
            msg += check_field_type(self.email_definition, email)
            msg += check_field_type(self.password_definition, password)
            if validation:
                msg += check_field_type(self.email_definition, email)
                msg += check_field_value(self.email_definition, email)
                msg += check_field_type(self.password_definition, password)
                msg += check_field_value(self.password_definition, password)

            msg += check_fields_in_request(census_element, auth_event, 'census', validation=validation)
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
                        "EmailPassword.census warning\n"\
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
                u = create_user(census_element, auth_event, True, request.user, password=password)
                give_perms(u, auth_event)
        if msg and validation:
            LOGGER.error(\
                "EmailPassword.census error\n"\
                "error '%r'\n"\
                "request '%r'\n"\
                "validation '%r'\n"\
                "authevent '%r'\n"\
                "Stack trace: \n%s",\
                msg, req, validation, auth_event, stack_trace_str())
            return self.error("Incorrect data", error_codename="invalid_credentials")

        if validation:
            for census_element in req.get('census'):
                # By default we creates the user as active we don't check
                # the pipeline
                u = create_user(census_element, auth_event, True, request.user, password=password)
                give_perms(u, auth_event)
        
        ret = {'status': 'ok'}
        LOGGER.debug(\
            "EmailPassword.census\n"\
            "request '%r'\n"\
            "validation '%r'\n"\
            "authevent '%r'\n"\
            "returns '%r'\n"\
            "Stack trace: \n%s",\
            req, validation, auth_event, ret, stack_trace_str())
        return ret

    def authenticate_error(self, error, req, ae):
        d = {'status': 'nok'}
        LOGGER.error(
            "EmailPassword.census error\n"\
            "error '%r'\n"\
            "request '%r'\n"\
            "authevent '%r'\n"\
            "Stack trace: \n%s",
            error, req, ae, stack_trace_str()
        )
        return d

    def authenticate(self, auth_event, request, mode='authenticate'):
        return_data = {'status': 'ok'}
        req = json.loads(request.body.decode('utf-8'))
        if mode == 'authenticate':
            verified, user = verify_admin_generated_auth_code(
                auth_event=auth_event,
                req_data=req,
                log_prefix="EmailPassword"
            )
            if verified:
                if not verify_num_successful_logins(
                    auth_event,
                    'EmailPassword',
                    user,
                    req
                ):
                    return self.authenticate_error(
                        "invalid_num_successful_logins_allowed", req, auth_event
                    )

                return return_auth_data('EmailPassword', req, request, user)

        msg = ""
        msg += check_fields_in_request(req, auth_event, 'authenticate')
        if msg:
            return self.authenticate_error("invalid-fields-check", req, auth_event)

        try:
            q = get_base_auth_query(auth_event)

            q = get_required_fields_on_auth(req, auth_event, q)
            user = User.objects.get(q)
            if mode == 'authenticate':
                post_verify_fields_on_auth(user, req, auth_event)
        except:
            return self.authenticate_error("user-not-found", req, auth_event)

        msg = check_pipeline(request, auth_event, 'authenticate')
        if msg:
            return self.authenticate_error("invalid-pipeline", req, auth_event)

        if mode == "authenticate":
            if not verify_num_successful_logins(
                auth_event,
                'EmailPassword',
                user,
                req
            ):
                return self.authenticate_error(
                    "invalid_num_successful_logins_allowed", req, auth_event
                )

            LOGGER.debug(
                "EmailPassword.authenticate success\n"\
                "returns '%r'\n"\
                "authevent '%r'\n"\
                "request '%r'\n"\
                "Stack trace: \n%s",
                return_data, auth_event, req, stack_trace_str()
            )
            return return_auth_data(
                'EmailPassword', 
                req, 
                request, 
                user,
                auth_event
            )
    
        LOGGER.debug(
            "EmailPassword.authenticate success\n"\
            "returns '%r'\n"\
            "authevent '%r'\n"\
            "request '%r'\n"\
            "Stack trace: \n%s",
            return_data, auth_event, req, stack_trace_str())
        return return_data

    def public_census_query(self, ae, request):
        # whatever
        return self.authenticate(ae, request, "census-query")

    def resend_auth_code(self, auth_event, request):
        return resend_auth_code(
            auth_event=auth_event,
            request=request,
            logger_name="EmailPassword",
            default_pipelines=EmailPassword.PIPELINES
        )

    def authenticate_otl(self, auth_event, request):
        return authenticate_otl(
            auth_event=auth_event,
            request=request,
            logger_name="EmailPassword"
        )


    def generate_auth_code(self, auth_event, request):
        return generate_auth_code(
            auth_event=auth_event,
            request=request,
            logger_name="EmailPassword"
        )

    views = [
        url(r'^test/(\w+)$', testview),
    ]


register_method('email-and-password', EmailPassword)
