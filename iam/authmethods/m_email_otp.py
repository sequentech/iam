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
from django.conf import settings
from django.db.models import Q
from django.contrib.auth.models import User
from utils import (
    ErrorCodes,
    constant_time_compare,
    send_codes,
    get_client_ip,
    is_valid_url,
    verify_admin_generated_auth_code,
)
from . import register_method
from authmethods.utils import (
    verify_children_election_info,
    check_fields_in_request,
    verify_valid_children_elections,
    exists_unique_user,
    add_unique_user,
    exist_user,
    create_user,
    give_perms,
    check_pipeline,
    get_user_match_query,
    get_fill_if_empty_query,
    MissingFieldError,
    fill_empty_fields,
    edit_user,
    verify_num_successful_logins,
    return_auth_data,
    check_field_type,
    check_field_value,
    get_base_auth_query,
    get_required_fields_on_auth,
    post_verify_fields_on_auth,
    resend_auth_code,
    generate_auth_code,
    authenticate_otl,
    stack_trace_str,
    get_user_code,
    disable_previous_user_codes
)
from contracts.base import check_contract, JsonTypeEncoder
from contracts import CheckException

LOGGER = logging.getLogger('iam')

class EmailOtp:
    DESCRIPTION = 'Register by email. You need to confirm your email.'
    CONFIG = {
        'subject': 'Confirm your email',
        'msg': 'Click __URL__ and put this code __CODE__',
        'registration-action': {
            'mode': 'vote',
            'mode-config': None,
        },
        'authentication-action': {
            'mode': 'vote',
            'mode-config': None,
        },
        'allow_user_resend': False
    }
    PIPELINES = {
        'give_perms': [
            {'object_type': 'UserData', 'perms': ['edit',], 'object_id': 'UserDataId' },
            {'object_type': 'AuthEvent', 'perms': ['vote',], 'object_id': 'AuthEventId' }
        ],
        "register-pipeline": [
            ["check_whitelisted", {"field": "ip"}],
            ["check_blacklisted", {"field": "ip"}],
            ["check_total_max", {"field": "ip", "period": 3600, "max": 10}],
            ["check_total_max", {"field": "ip", "period": 3600*24, "max": 50}],
        ],
        "authenticate-pipeline": [
            #['check_total_connection', {'times': 5 }],
        ],
        "resend-auth-pipeline": [
            ["check_whitelisted", {"field": "ip"}],
            ["check_blacklisted", {"field": "ip"}],
            ["check_total_max", {"field": "ip", "period": 1, "max": 1}],
            ["check_total_max", {"field": "ip", "period": 5, "max": 2}],
            ["check_total_max", {"field": "ip", "period": 3600, "max": 10}],
            ["check_total_max", {"field": "ip", "period": 3600*24, "max": 20}],
        ]
    }

    MANDATORY_FIELDS = dict(
        types=['email'],
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
    code_definition = {
        "name": "code",
        "type": "text",
        "required": True,
        "min": 6,
        "max": 255,
        "unique": True,
        "required_on_authentication": True
    }

    CONFIG_CONTRACT = [
      {
        'check': 'isinstance',
        'type': dict
      },
      {
        'check': 'dict-keys-exist',
        'keys': ['msg', 'subject', 'registration-action', 'authentication-action']
      },
      {
        'check': 'index-check-list',
        'index': 'msg',
        'check-list': [
          {
            'check': 'isinstance',
            'type': str
          },
          {
            'check': 'length',
            'range': [1, 5000]
          }
        ]
      },
      {
        'check': 'index-check-list',
        'index': 'html_message',
        'optional': True,
        'check-list': [
          {
            'check': 'isinstance',
            'type': str
          },
          {
            'check': 'length',
            'range': [1, 5000]
          }
        ]
      },
      {
        'check': 'index-check-list',
        'index': 'subject',
        'check-list': [
          {
            'check': 'isinstance',
            'type': str
          },
          {
            'check': 'length',
            'range': [1, 1024]
          }
        ]
      },
      {
        'check': 'index-check-list',
        'index': 'registration-action',
        'check-list': [
          {
            'check': 'isinstance',
            'type': dict
          },
          {
            'check': 'dict-keys-exact',
            'keys': ['mode', 'mode-config']
          },
          {
            'check': 'index-check-list',
            'index': 'mode',
            'check-list': [
              {
                'check': 'isinstance',
                'type': str
              },
              {
                'check': 'lambda',
                'lambda': lambda d: d in ['vote', 'go-to-url']
              }
            ]
          },
          {
            'check': 'switch-contract-by-dict-key',
            'switch-key': 'mode',
            'contract-key': 'mode-config',
            'contracts': {
              'vote': [
                {
                  'check': 'lambda',
                  'lambda': lambda d: d is None
                }
              ],
              'go-to-url': [
                {
                  'check': 'isinstance',
                  'type': dict
                },
                {
                  'check': 'dict-keys-exact',
                  'keys': ['url']
                },
                {
                  'check': 'index-check-list',
                  'index': 'url',
                  'check-list': [
                    {
                      'check': 'isinstance',
                      'type': str
                    },
                    {
                      'check': 'length',
                      'range': [1, 400]
                    },
                    {
                      'check': 'lambda',
                      'lambda': lambda d: is_valid_url(d, schemes=['https'])
                    }
                  ]
                }
              ]
            }
          }
        ]
      },
      {
        'check': 'index-check-list',
        'index': 'authentication-action',
        'check-list': [
          {
            'check': 'isinstance',
            'type': dict
          },
          {
            'check': 'dict-keys-exact',
            'keys': ['mode', 'mode-config']
          },
          {
            'check': 'index-check-list',
            'index': 'mode',
            'check-list': [
              {
                'check': 'isinstance',
                'type': str
              },
              {
                'check': 'lambda',
                'lambda': lambda d: d in ['vote', 'go-to-url']
              }
            ]
          },
          {
            'check': 'switch-contract-by-dict-key',
            'switch-key': 'mode',
            'contract-key': 'mode-config',
            'contracts': {
              'vote': [
                {
                  'check': 'lambda',
                  'lambda': lambda d: d is None
                }
              ],
              'go-to-url': [
                {
                  'check': 'isinstance',
                  'type': dict
                },
                {
                  'check': 'dict-keys-exact',
                  'keys': ['url']
                },
                {
                  'check': 'index-check-list',
                  'index': 'url',
                  'check-list': [
                    {
                      'check': 'isinstance',
                      'type': str
                    },
                    {
                      'check': 'length',
                      'range': [1, 400]
                    },
                    {
                      'check': 'lambda',
                      'lambda': lambda d: is_valid_url(d, schemes=['https'])
                    }
                  ]
                }
              ]
            }
          }
        ]
      }
    ]

    def check_config(self, config):
        """ Check config when create auth-event. """
        msg = ''
        try:
            check_contract(self.CONFIG_CONTRACT, config)
            LOGGER.debug(\
                "EmailOtp.check_config success\n"\
                "config '%r'\n"\
                "returns ''\n"\
                "Stack trace: \n%s",\
                config, stack_trace_str())
            return ''
        except CheckException as e:
            LOGGER.error(\
                "EmailOtp.check_config error\n"\
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
        
        # cannot add voters to an election with invalid children election info
        if auth_event.children_election_info is not None:
            try:
                verify_children_election_info(auth_event, request.user, ['edit', 'census-add'])
            except:
                LOGGER.error(
                    "EmailOtp.census error in verify_children_election_info"\
                    "error '%r'\n"\
                    "request '%r'\n"\
                    "validation '%r'\n"\
                    "authevent '%r'\n"\
                    "Stack trace: \n%s",\
                    msg, req, validation, auth_event, stack_trace_str())
                return self.error("Incorrect data", error_codename="invalid_data")

        for census_element in req.get('census'):
            msg += check_fields_in_request(
                census_element, 
                auth_event, 
                'census',
                validation=validation)

            if auth_event.children_election_info is not None:
                try:
                    verify_valid_children_elections(auth_event, census_element)
                except:
                    LOGGER.error(
                        "EmailOtp.census error in verify_valid_children_elections"\
                        "error '%r'\n"\
                        "request '%r'\n"\
                        "validation '%r'\n"\
                        "authevent '%r'\n"\
                        "Stack trace: \n%s",\
                        msg, req, validation, auth_event, stack_trace_str())
                    return self.error("Incorrect data", error_codename="invalid_data")

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
                        "EmailOtp.census warning\n"\
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
                u = create_user(census_element, auth_event, True, request.user)
                give_perms(u, auth_event)
        if msg and validation:
            LOGGER.error(\
                "EmailOtp.census error\n"\
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
                u = create_user(census_element, auth_event, True, request.user)
                give_perms(u, auth_event)
        
        ret = {'status': 'ok'}
        LOGGER.debug(\
            "EmailOtp.census\n"\
            "request '%r'\n"\
            "validation '%r'\n"\
            "authevent '%r'\n"\
            "returns '%r'\n"\
            "Stack trace: \n%s",\
            req, validation, auth_event, ret, stack_trace_str())
        return ret

    def error(
            self, msg, auth_event=None, error_codename=None, internal_error=None
        ):
        data = {'status': 'nok', 'msg': msg, 'error_codename': error_codename}
        LOGGER.error(\
            "EmailOtp.error\n"\
            f"internal_error '{internal_error}'\n"\
            f"error_codename '{error_codename}'\n"\
            f"returning error '{data}'\n"\
            f"auth_event '{auth_event}'\n"\
            f"Stack trace: \n{stack_trace_str()}"
        )
        return data

    def register(self, auth_event, request):
        req = json.loads(request.body.decode('utf-8'))

        user_exists_codename = (
            "user_exists"
            if True == settings.SHOW_ALREADY_REGISTERED
            else "invalid_credentials"
        )

        msg = check_pipeline(request, auth_event)
        if msg:
            LOGGER.error(\
                "EmailOtp.register error\n"\
                "pipeline check error'%r'\n"\
                "authevent '%r'\n"\
                "request '%r'\n"\
                "Stack trace: \n%s",\
                msg, auth_event, req, stack_trace_str())
            return msg

        # create the user as active? Usually yes, but the execute_pipeline call
        # inside check_fields_in_request might modify this
        req['active'] = True

        msg = check_fields_in_request(req, auth_event)
        if msg:
            LOGGER.error(\
                "EmailOtp.register error\n"\
                "Fields check error '%r'"\
                "authevent '%r'\n"\
                "request '%r'\n"\
                "Stack trace: \n%s",\
                msg, auth_event, req, stack_trace_str())
            return self.error(
                "Incorrect data", 
                error_codename="invalid_credentials"
            )
        # get active from req, this value might have changed in
        # check_fields_in_requests
        active = req.pop('active')

        # lookup in the database if there's any user with the match fields
        # NOTE: we assume reg_match_fields are unique in the DB and required
        base_query = Q(
            userdata__event=auth_event,
            is_active=True
        )
        query = None
        fill_if_empty_fields = None
        try:
            match_query, use_matching = get_user_match_query(
                auth_event,
                req,
                base_query
            )
            query, fill_if_empty_fields = get_fill_if_empty_query(
                auth_event,
                req, 
                match_query
            )
        except MissingFieldError as error:
            LOGGER.error(
                "EmailOtp.register error\n"\
                "match field '%r' missing in request '%r'\n"\
                "authevent '%r'\n"\
                "Stack trace: \n%s",\
                error.field_name, req, auth_event, stack_trace_str()
            )
            return self.error(
                "Incorrect data",
                error_codename="invalid_credentials"
            )

        # if there are any matching fields, this is an election with 
        # pre-registration data so no new user can be created, it has to match
        # a pre-registered user
        if use_matching:
            user_found = None
            user_list = User.objects.filter(query)
            if 1 == user_list.count():
                user_found = user_list[0]

                # check that the unique:True extra fields are actually unique
                unique_error_msg = exist_user(
                    req,
                    auth_event,
                    ignore_user=user_found
                )
                if unique_error_msg != '':
                    LOGGER.error(
                        "EmailOtp.register error\n"\
                        "unique field error '%r'\n"\
                        "authevent '%r'\n"\
                        "request '%r'\n"\
                        "Stack trace: \n%s",\
                        unique_error_msg,
                        auth_event, req, stack_trace_str()
                    )
                    return self.error(
                        "Incorrect data",
                        error_codename="invalid_credentials"
                    )
            # user needs to exist
            else:
                LOGGER.error(\
                    "EmailOtp.register error\n"\
                    "user not found for query '%r'\n"\
                    "authevent '%r'\n"\
                    "request '%r'\n"\
                    "Stack trace: \n%s",\
                    query, auth_event, req, stack_trace_str()
                )
                return self.error(
                    "Incorrect data", 
                    error_codename="invalid_credentials"
                )
            fill_empty_fields(fill_if_empty_fields, user_found, req)
            register_user = user_found
        # pre-registration not enabled
        else:
            # check if the user exists, with the unique fields given
            msg_exist = exist_user(req, auth_event, get_repeated=True)
            if msg_exist:
                ret_error = True
                try:
                    register_user = User.objects.get(
                        email=req.get('email'),
                        userdata__event=auth_event
                    )
                    # user is  admin and is disabled (deregistered)
                    # allow him to re-register with new parameters
                    if (
                        settings.ADMIN_AUTH_ID == auth_event.pk and
                        False == register_user.is_active and
                        True == settings.ALLOW_DEREGISTER
                    ):
                        edit_user(register_user, req, auth_event)
                        register_user.is_active = True
                        register_user.save()
                        ret_error = False
                except:
                    pass
                if ret_error:
                    LOGGER.error(
                        "EmailOtp.register error\n"\
                        "User already exists '%r'\n"\
                        "authevent '%r'\n"\
                        "request '%r'\n"\
                        "Stack trace: \n%s",\
                        msg_exist, auth_event, req, stack_trace_str()
                    )
                    return self.error(
                        "Incorrect data", 
                        error_codename=user_exists_codename
                    )
            else:
                # user is really new, doesn't exist. So let's create it and
                # add the appropiate permissions to this user
                register_user = create_user(
                    req, 
                    auth_event, 
                    active, 
                    request.user
                )
                msg += give_perms(register_user, auth_event)

        if msg:
            LOGGER.error(
                "EmailOtp.register error\n"\
                "Probably a permissions error\n"\
                "Error '%r'\n"\
                "authevent '%r'\n"\
                "request '%r'\n"\
                "Stack trace: \n%s",
                msg, auth_event, req, stack_trace_str()
            )
            return self.error("Incorrect data", error_codename="invalid_credentials")
        elif not active:
            LOGGER.debug(
                "EmailOtp.register.\n"\
                "user id '%r' is not active, message NOT sent\n"\
                "authevent '%r'\n"\
                "request '%r'\n"\
                "Stack trace: \n%s",\
                register_user.id, auth_event, req, stack_trace_str()
            )
            # Note, we are not calling to extend_send_sms because we are not
            # sending the code in here
            return {'status': 'ok', 'user': register_user}

        response = {'status': 'ok', 'user': register_user}
        send_codes.apply_async(
            args=[
                [register_user.id,],
                get_client_ip(request)
            ]
        )
        LOGGER.info(
            "EmailOtp.register.\n"\
            "Sending (email) codes to user id '%r'"\
            "client ip '%r'\n"\
            "authevent '%r'\n"\
            "request '%r'\n"\
            "Stack trace: \n%s",
            register_user.id, get_client_ip(request), auth_event, req, 
            stack_trace_str()
        )
        return response

    def authenticate_error(self):
        d = {'status': 'nok'}
        LOGGER.error(\
            "EmailOtp.authenticate_error\n"\
            "returning '%r'"\
            "Stack trace: \n%s",\
            d, stack_trace_str())
        return d

    def authenticate(self, auth_event, request):
        req = json.loads(request.body.decode('utf-8'))
        verified, user = verify_admin_generated_auth_code(
            auth_event=auth_event,
            req_data=req,
            log_prefix="EmailOtp"
        )
        if verified:
            if not verify_num_successful_logins(auth_event, 'EmailOtp', user, req):
                return self.error(
                    ErrorCodes.CANT_VOTE_MORE_TIMES,
                    auth_event=auth_event,
                    error_codename=ErrorCodes.CANT_VOTE_MORE_TIMES
                )

            return return_auth_data('EmailOtp', req, request, user)

        msg = ''
        email = req.get('email')

        if isinstance(email, str):
            email = email.strip()
            email = email.replace(" ", "")

        if auth_event.parent is not None:
            msg += 'you can only authenticate to parent elections'
            return self.error(
                msg,
                auth_event=auth_event,
                error_codename=ErrorCodes.CANT_AUTHENTICATE_TO_PARENT
            )

        msg += check_field_type(self.code_definition, req.get('code'), 'authenticate')
        msg += check_field_value(self.code_definition, req.get('code'), 'authenticate')
        msg += check_fields_in_request(req, auth_event, 'authenticate')
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
            otp_field_code = post_verify_fields_on_auth(user, req, auth_event)
        except Exception as error:
            msg += f"exception: `{error}`\n"
            return self.error(
                msg="",
                internal_error=msg,
                auth_event=auth_event,
                error_codename=ErrorCodes.INVALID_PASSWORD_OR_CODE
            )

        if not verify_num_successful_logins(auth_event, 'EmailOtp', user, req):
            return self.error(
                ErrorCodes.CANT_VOTE_MORE_TIMES,
                auth_event=auth_event,
                error_codename=ErrorCodes.CANT_VOTE_MORE_TIMES
            )

        if otp_field_code is not None:
            code = otp_field_code
        else:
            code = get_user_code(
                user,
                timeout_seconds=settings.SMS_OTP_EXPIRE_SECONDS
            )
        if not code:
            msg += f"code not found in the database for user `{user.userdata}` and requested code `{req.get('code').upper()}` with expiration less than `{settings.SMS_OTP_EXPIRE_SECONDS}`\n"
            return self.error(
                msg="",
                internal_error=msg,
                auth_event=auth_event,
                error_codename=ErrorCodes.INVALID_CODE
            )

        # if otp_field_code is not None then post_verify_fields_on_auth already
        # disabled the user code
        if otp_field_code is None:
            disable_previous_user_codes(user)

        if not constant_time_compare(req.get('code').upper(), code.code):
            msg += f"code mismatch for user `{user.userdata}`: [dbcode = `{code.code}`] != [requested code = `{req.get('code').upper()}`]\n"
            return self.error(
                msg="",
                internal_error=msg,
                auth_event=auth_event,
                error_codename=ErrorCodes.INVALID_CODE
            )
            
        return return_auth_data('EmailOtp', req, request, user)

    def authenticate_otl(self, auth_event, request):
        return authenticate_otl(
            auth_event=auth_event,
            request=request,
            logger_name="EmailOtp"
        )

    def resend_auth_code(self, auth_event, request):
        return resend_auth_code(
            auth_event=auth_event,
            request=request,
            logger_name="EmailOtp",
            default_pipelines=EmailOtp.PIPELINES
        )

    def generate_auth_code(self, auth_event, request):
        return generate_auth_code(
            auth_event=auth_event,
            request=request,
            logger_name="EmailOtp"
        )

register_method('email-otp', EmailOtp)
