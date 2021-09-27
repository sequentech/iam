# This file is part of authapi.
# Copyright (C) 2014-2020  Agora Voting SL <contact@nvotes.com>

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
from django.conf import settings
from django.conf.urls import url
from django.contrib.auth.models import User
from utils import genhmac, constant_time_compare, send_codes, get_client_ip, is_valid_url

from . import register_method
from authmethods.utils import *
from api.models import AuthEvent
from contracts.base import check_contract, JsonTypeEncoder
from contracts import CheckException
from authmethods.models import Code
from utils import stack_trace_str

LOGGER = logging.getLogger('authapi')

class Email:
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
            ["check_total_max", {"field": "ip", "period": 3600, "max": 10}],
            ["check_total_max", {"field": "ip", "period": 3600*24, "max": 50}],
        ]
    }
    USED_TYPE_FIELDS = ['email']

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
                "Email.check_config success\n"\
                "config '%r'\n"\
                "returns ''\n"\
                "Stack trace: \n%s",\
                config, stack_trace_str())
            return ''
        except CheckException as e:
            LOGGER.error(\
                "Email.check_config error\n"\
                "error '%r'\n"\
                "config '%r'\n"\
                "Stack trace: \n%s",\
                e, config, stack_trace_str())
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
                    "Email.census error in verify_children_election_info"\
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
              validation=validation
            )

            if auth_event.children_election_info is not None:
                try:
                    verify_valid_children_elections(auth_event, census_element)
                except:
                    LOGGER.error(
                        "Email.census error in verify_valid_children_elections"\
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
                        "Email.census warning\n"\
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
                "Email.census error\n"\
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
            "Email.census\n"\
            "request '%r'\n"\
            "validation '%r'\n"\
            "authevent '%r'\n"\
            "returns '%r'\n"\
            "Stack trace: \n%s",\
            req, validation, auth_event, ret, stack_trace_str())
        return ret

    def error(self, msg, error_codename):
        d = {'status': 'nok', 'msg': msg, 'error_codename': error_codename}
        LOGGER.error(\
            "Email.error\n"\
            "error '%r'\n"\
            "Stack trace: \n%s",\
            d, stack_trace_str())
        return d

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
                "Email.register error\n"\
                "pipeline check error'%r'\n"\
                "authevent '%r'\n"\
                "request '%r'\n"\
                "Stack trace: \n%s",\
                msg, auth_event, req, stack_trace_str())
            return msg

        # create the user as active? Usually yes, but the execute_pipeline call 
        # inside check_fields_in_request might modify this
        req['active'] = True

        reg_match_fields = get_match_fields(auth_event)

        # NOTE the fields of type "fill_if_empty_on_registration" need
        # to be empty, otherwise the user is already registered.
        reg_fill_empty_fields = get_fill_empty_fields(auth_event)

        msg = ''
        email = req.get('email')
        if isinstance(email, str):
            email = email.strip()
            email = email.replace(" ", "")
        msg += check_fields_in_request(req, auth_event)
        if msg:
            LOGGER.error(\
                "Email.register error\n"\
                "Fields check error '%r'"\
                "authevent '%r'\n"\
                "request '%r'\n"\
                "Stack trace: \n%s",\
                msg, auth_event, req, stack_trace_str()
            )
            return self.error("Incorrect data", error_codename="invalid_credentials")
        # get active from req, this value might have changed in check_fields_in_requests
        active = req.pop('active')

        if len(reg_match_fields) > 0 or len(reg_fill_empty_fields) > 0:
            # is the email a match field?
            match_email = False
            match_email_element = None
            for extra in auth_event.extra_fields:
                if (
                    'name' in extra and
                    'email' == extra['name'] and
                    "match_census_on_registration" in extra and
                    extra['match_census_on_registration']
                ):
                    match_email = True
                    match_email_element = extra
                    break
            # if the email is not a match field, and there already is a user
            # with that email, reject the registration request
            if not match_email and User.objects.filter(email=email, userdata__event=auth_event, is_active=True).count() > 0:
                LOGGER.error(\
                    "Email.register error\n"\
                    "email is not a match field, and there already is a user with email '%r'\n"\
                    "authevent '%r'\n"\
                    "request '%r'\n"\
                    "Stack trace: \n%s",\
                    email,\
                    User.objects.filter(email=email, userdata__event=auth_event, is_active=True)[0],\
                    auth_event,\
                    req,\
                    stack_trace_str())
                return self.error("Incorrect data", error_codename=user_exists_codename)

            # lookup in the database if there's any user with the match fields
            # NOTE: we assume reg_match_fields are unique in the DB and required
            search_email = email if match_email else ""
            if match_email:
                reg_match_fields.remove(match_email_element)
            q = Q(userdata__event=auth_event,
                  is_active=False,
                  email=search_email)
            # Check the reg_match_fields
            for reg_match_field in reg_match_fields:
                 # Filter with Django's JSONfield
                 reg_name = reg_match_field.get('name')
                 if not reg_name:
                     LOGGER.error(\
                         "Email.register error\n"\
                         "'name' not in match field '%r'\n"\
                         "authevent '%r'\n"\
                         "request '%r'\n"\
                         "Stack trace: \n%s",\
                         reg_match_field, auth_event, req, stack_trace_str())
                     return self.error("Incorrect data", error_codename="invalid_credentials")
                 req_field_data = req.get(reg_name)
                 if reg_name and req_field_data:
                    if reg_name == 'email':
                        continue
                    q = q & Q(userdata__metadata__contains={reg_name: req_field_data})
                 else:
                     LOGGER.error(\
                         "Email.register error\n"\
                         "match field '%r' missing in request '%r'\n"\
                         "authevent '%r'\n"\
                         "Stack trace: \n%s",\
                         reg_name, req, auth_event, stack_trace_str())
                     return self.error("Incorrect data", error_codename="invalid_credentials")

            # Check that the reg_fill_empty_fields are empty, otherwise the user
            # is already registered
            for reg_empty_field in reg_fill_empty_fields:
                 # Filter with Django's JSONfield
                 reg_name = reg_empty_field.get('name')
                 if not reg_name:
                     LOGGER.error(\
                         "Email.register error\n"\
                         "'name' not in empty field '%r'\n"\
                         "authevent '%r'\n"\
                         "request '%r'\n"\
                         "Stack trace: \n%s",\
                         reg_empty_field, auth_event, req, stack_trace_str())
                     return self.error("Incorrect data", error_codename="invalid_credentials")
                 # Note: the register query _must_ contain a value for these fields
                 if reg_name and reg_name in req and req[reg_name]:
                     q = q & Q(userdata__metadata__contains={reg_name: ""})
                 else:
                     LOGGER.error(\
                         "Email.register error\n"\
                         "the register query _must_ contain a value for these fields\n"\
                         "reg_name '%r'\n"\
                         "reg_name in req '%r'\n"\
                         "req[reg_name] '%r'\n"\
                         "authevent '%r'\n"\
                         "request '%r'\n"\
                         "Stack trace: \n%s",\
                         reg_name, (reg_name in req), req[reg_name], auth_event,\
                         req, stack_trace_str())
                     return self.error("Incorrect data", error_codename="invalid_credentials")


            user_found = None
            user_list = User.objects.filter(q)
            if 1 == user_list.count():
                user_found = user_list[0]

                # check that the unique:True extra fields are actually unique
                uniques = []
                for extra in auth_event.extra_fields:
                    if 'unique' in extra.keys() and extra.get('unique'):
                        uniques.append(extra['name'])
                if len(uniques) > 0:
                    base_q = Q(userdata__event=auth_event, is_active=True)
                    base_list = User.objects.exclude(id = user_found.id)
                    for reg_name in uniques:
                        req_field_data = req.get(reg_name)
                        if reg_name and req_field_data:
                            uq = base_q & Q(userdata__metadata__contains={reg_name: req_field_data})
                            repeated_list = base_list.filter(uq)
                            if repeated_list.count() > 0:
                                LOGGER.error(\
                                    "Email.register error\n"\
                                    "unique field named '%r'\n"\
                                    "with content '%r'\n"\
                                    "is repeated on '%r'\n"\
                                    "authevent '%r'\n"\
                                    "request '%r'\n"\
                                    "Stack trace: \n%s",\
                                    reg_name, req_field_data, repeated_list[0],\
                                    auth_event, req, stack_trace_str())
                                return self.error("Incorrect data", error_codename="invalid_credentials")

            # user needs to exist
            if user_found is None:
                LOGGER.error(\
                    "Email.register error\n"\
                    "user not found for query '%r'\n"\
                    "authevent '%r'\n"\
                    "request '%r'\n"\
                    "Stack trace: \n%s",\
                    q, auth_event, req, stack_trace_str())
                return self.error("Incorrect data", error_codename="invalid_credentials")

            for reg_empty_field in reg_fill_empty_fields:
                reg_name = reg_empty_field['name']
                if reg_name in req:
                    user_found.userdata.metadata[reg_name] = req.get(reg_name)
            user_found.userdata.save()
            if not match_email:
               user_found.email = email
            user_found.save()
            u = user_found
        else:
            msg_exist = exist_user(req, auth_event, get_repeated=True)
            if msg_exist:
                ret_error = True
                try:
                    u = User.objects.get(email=req.get('email'), userdata__event=auth_event)
                    # user is  admin and is disabled (deregistered)
                    # allow him to re-register with new parameters
                    if settings.ADMIN_AUTH_ID == auth_event.pk and \
                        False == u.is_active and \
                        True == settings.ALLOW_DEREGISTER:
                        edit_user(u, req, auth_event)
                        u.is_active = True
                        u.save()
                        ret_error = False
                except:
                    pass
                if ret_error:
                    LOGGER.error(\
                        "Email.register error\n"\
                        "User already exists '%r'\n"\
                        "authevent '%r'\n"\
                        "request '%r'\n"\
                        "Stack trace: \n%s",\
                        msg_exist, auth_event, req, stack_trace_str())
                    return self.error("Incorrect data", error_codename=user_exists_codename)
            else:
                u = create_user(req, auth_event, active, request.user)
                msg += give_perms(u, auth_event)

        if msg:
            LOGGER.error(\
                "Email.register error\n"\
                "Probably a permissions error\n"\
                "Error '%r'\n"\
                "authevent '%r'\n"\
                "request '%r'\n"\
                "Stack trace: \n%s",\
                msg, auth_event, req, stack_trace_str())
            return self.error("Incorrect data", error_codename="invalid_credentials")
        elif not active:
            LOGGER.debug(\
                "Email.register.\n"\
                "user id '%r' is not active, message NOT sent\n"\
                "authevent '%r'\n"\
                "request '%r'\n"\
                "Stack trace: \n%s",\
                u.id, auth_event, req, stack_trace_str())
            # Note, we are not calling to extend_send_sms because we are not
            # sending the code in here
            return {'status': 'ok', 'user': u}

        response = {'status': 'ok', 'user': u}
        send_codes.apply_async(args=[[u.id,], get_client_ip(request),'email'])
        LOGGER.info(\
            "Email.register.\n"\
            "Sending (email) codes to user id '%r'"\
            "client ip '%r'\n"\
            "authevent '%r'\n"\
            "request '%r'\n"\
            "Stack trace: \n%s",\
            u.id, get_client_ip(request), auth_event, req, stack_trace_str())
        return response

    def authenticate_error(self):
        d = {'status': 'nok'}
        LOGGER.error(\
            "Email.authenticate_error\n"\
            "returning '%r'"\
            "Stack trace: \n%s",\
            d, stack_trace_str())
        return d

    def authenticate(self, auth_event, request):
        req = json.loads(request.body.decode('utf-8'))
        msg = ''
        if auth_event.parent is not None:
            msg += 'you can only authenticate to parent elections'
            LOGGER.error(\
                "Email.authenticate error\n"\
                "error '%r'"\
                "authevent '%r'\n"\
                "request '%r'\n"\
                "Stack trace: \n%s",\
                msg, auth_event, req, stack_trace_str())
            return self.error("Incorrect data", error_codename="invalid_credentials")

        msg += check_field_type(self.code_definition, req.get('code'), 'authenticate')
        msg += check_field_value(self.code_definition, req.get('code'), 'authenticate')
        msg += check_fields_in_request(req, auth_event, 'authenticate')
        if msg:
            LOGGER.error(\
                "Email.authenticate error\n"\
                "error '%r'"\
                "authevent '%r'\n"\
                "request '%r'\n"\
                "Stack trace: \n%s",\
                msg, auth_event, req, stack_trace_str())
            return self.error("Incorrect data", error_codename="invalid_credentials")

        msg = check_pipeline(request, auth_event, 'authenticate')
        if msg:
            LOGGER.error(\
                "Email.authenticate error\n"\
                "error '%r'\n"\
                "authevent '%r'\n"\
                "request '%r'\n"\
                "Stack trace: \n%s",\
                msg, auth_event, req, stack_trace_str())
            return self.error("Incorrect data", error_codename="invalid_credentials")

        try:
            q = get_base_auth_query(auth_event)
            q = get_required_fields_on_auth(req, auth_event, q)
            user = User.objects.get(q)
            post_verify_fields_on_auth(user, req, auth_event)
        except:
            LOGGER.error(\
                "Email.authenticate error\n"\
                "user not found with these characteristics: email '%r'\n"\
                "authevent '%r'\n"\
                "is_active True\n"\
                "request '%r'\n"\
                "Stack trace: \n%s",\
                email, auth_event, req, stack_trace_str())
            return self.error("Incorrect data", error_codename="invalid_credentials")

        user_auth_event = user.userdata.event

        if not verify_num_successful_logins(user_auth_event, 'Email', user, req):
            return self.error("Incorrect data", error_codename="invalid_credentials")

        code = Code.objects\
            .filter(
                user=user.userdata,
                code=req.get('code').upper()
            )\
            .order_by('-created')\
            .first()
        if not code:
            LOGGER.error(\
                "Email.authenticate error\n"\
                "Code not found on db for user '%r'\n"\
                "and code '%r'\n"\
                "authevent '%r'\n"\
                "request '%r'\n"\
                "Stack trace: \n%s",\
                user.userdata,\
                req.get('code').upper(),\
                auth_event, req, stack_trace_str())
            return self.error("Incorrect data", error_codename="invalid_credentials")

        return return_auth_data('Email', req, request, user)

    def resend_auth_code(self, auth_event, request):
        req = json.loads(request.body.decode('utf-8'))

        msg = ''
        email = req.get('email')

        if isinstance(email, str):
            email = email.strip()
            email = email.replace(" ", "")

        if auth_event.parent is not None:
            msg += 'you can only authenticate to parent elections'
            LOGGER.error(\
                "Email.authenticate error\n"\
                "error '%r'"\
                "authevent '%r'\n"\
                "request '%r'\n"\
                "Stack trace: \n%s",\
                msg, auth_event, req, stack_trace_str())
            return self.error("Incorrect data", error_codename="invalid_credentials")

        msg += check_fields_in_request(req, auth_event, 'resend-auth')
        if msg:
            LOGGER.error(\
                "Email.resend_auth_code error\n"\
                "error '%r'"\
                "authevent '%r'\n"\
                "request '%r'\n"\
                "Stack trace: \n%s",\
                msg, auth_event, req, stack_trace_str())
            return self.error("Incorrect data", error_codename="invalid_credentials")

        try:
            q = get_base_auth_query(auth_event)
            q = get_required_fields_on_auth(req, auth_event, q)
            u = User.objects.get(q)
        except:
            LOGGER.error(\
                "Email.resend_auth_code error\n"\
                "user not found with these characteristics: email '%r'\n"\
                "authevent '%r'\n"\
                "request '%r'\n"\
                "Stack trace: \n%s",\
                email, auth_event, req, stack_trace_str())
            return self.error("Incorrect data", error_codename="invalid_credentials")

        msg = check_pipeline(
          request,
          auth_event,
          'resend-auth-pipeline',
          Email.PIPELINES['resend-auth-pipeline'])

        if msg:
            LOGGER.error(\
                "Email.resend_auth_code error\n"\
                "check_pipeline error '%r'\n"\
                "authevent '%r'\n"\
                "request '%r'\n"\
                "Stack trace: \n%s",\
                msg, auth_event, req, stack_trace_str())
            return self.error("Incorrect data", error_codename="invalid_credentials")

        send_codes.apply_async(args=[[u.id,], get_client_ip(request),'email'])
        LOGGER.info(\
            "Email.resend_auth_code.\n"\
            "Sending (email) codes to user id '%r'\n"\
            "client ip '%r'\n"\
            "authevent '%r'\n"\
            "request '%r'\n"\
            "Stack trace: \n%s",\
            u.id, get_client_ip(request), auth_event, req, stack_trace_str())
        return {'status': 'ok', 'user': u}
        

register_method('email', Email)
