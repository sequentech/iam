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
from django.db.models import Q
from django.contrib.auth.models import User
from django.shortcuts import get_object_or_404
from datetime import datetime, timedelta
from utils import (
  genhmac, send_codes, get_client_ip, is_valid_url, constant_time_compare
)

import plugins
from . import register_method
from contracts.base import check_contract, JsonTypeEncoder
from contracts import CheckException
from authmethods.utils import *
from utils import stack_trace_str
from django.contrib.auth.signals import user_logged_in

LOGGER = logging.getLogger('authapi')

class SmsOtp:
    DESCRIPTION = 'Provides authentication using an SMS code.'
    CONFIG = {
        'msg': 'Enter in __URL__ and put this code __CODE__',
        'registration-action': {
            'mode': 'vote',
            'mode-config': None,
        },
        'authentication-action': {
            'mode': 'vote',
            'mode-config': None,
        },
        'allow_user_resend': True
    }
    PIPELINES = {
        'give_perms': [
            {'object_type': 'UserData', 'perms': ['edit',], 'object_id': 'UserDataId' },
            {'object_type': 'AuthEvent', 'perms': ['vote',], 'object_id': 'AuthEventId' }
        ],
        "register-pipeline": [
            ["check_whitelisted", {"field": "tlf"}],
            ["check_whitelisted", {"field": "ip"}],
            ["check_blacklisted", {"field": "ip"}],
            ["check_blacklisted", {"field": "tlf"}],
            ["check_total_max", {"field": "ip", "period": 3600, "max": 10}],
            ["check_total_max", {"field": "tlf", "period": 3600, "max": 10}],
            ["check_total_max", {"field": "ip", "period": 3600*24, "max": 50}],
            ["check_total_max", {"field": "tlf", "period": 3600*24, "max": 50}],
        ],
        "authenticate-pipeline": [
            #['check_total_connection', {'times': 5 }],
            #['check_sms_code', {'timestamp': 5 }]
        ],
        "resend-auth-pipeline": [
            ["check_whitelisted", {"field": "tlf"}],
            ["check_whitelisted", {"field": "ip"}],
            ["check_blacklisted", {"field": "ip"}],
            ["check_blacklisted", {"field": "tlf"}],
            ["check_total_max", {"field": "tlf", "period": 3600, "max": 25}],
            ["check_total_max", {"field": "tlf", "period": 3600*24, "max": 100}],
            ["check_total_max", {"field": "ip", "period": 3600, "max": 25}],
            ["check_total_max", {"field": "ip", "period": 3600*24, "max": 100}],
        ]
    }
    USED_TYPE_FIELDS = ['tlf']

    tlf_definition = { "name": "tlf", "type": "text", "required": True, "min": 4, "max": 20, "required_on_authentication": True }
    tlf_opt_definition = { "name": "tlf", "type": "text", "required": False, "min": 0, "max": 20, "required_on_authentication": False }
    code_definition = { "name": "code", "type": "text", "required": True, "min": 6, "max": 255, "required_on_authentication": True }

    CONFIG_CONTRACT = [
      {
        'check': 'isinstance',
        'type': dict
      },
      {
        'check': 'dict-keys-exist',
        'keys': ['msg', 'registration-action', 'authentication-action']
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
            'range': [1, 200]
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

    def error(self, msg, error_codename):
        d = {'status': 'nok', 'msg': msg, 'error_codename': error_codename}
        LOGGER.error(\
            "SmsOtp.error\n"\
            "error '%r'\n"\
            "Stack trace: \n%s",\
            d, stack_trace_str())
        return d

    def check_config(self, config):
        """ Check config when create auth-event. """
        msg = ''
        try:
            check_contract(self.CONFIG_CONTRACT, config)
            LOGGER.debug(\
                "SmsOtp.check_config success\n"\
                "config '%r'\n"\
                "returns ''\n"\
                "Stack trace: \n%s",\
                config, stack_trace_str())
            return ''
        except CheckException as e:
            LOGGER.error(\
                "SmsOtp.check_config error\n"\
                "error '%r'\n"\
                "config '%r'"\
                "Stack trace: \n%s",\
                e, config, stack_trace_str())
            return json.dumps(e.data, cls=JsonTypeEncoder)

    def census(self, ae, request):
        req = json.loads(request.body.decode('utf-8'))
        validation = req.get('field-validation', 'enabled') == 'enabled'
        data = {'status': 'ok'}

        msg = ''
        current_tlfs = []
        for r in req.get('census'):
            if r.get('tlf'):
                r['tlf'] = get_cannonical_tlf(r.get('tlf'))
            tlf = r.get('tlf')
            if isinstance(tlf, str):
                tlf = tlf.strip()
            msg += check_field_type(self.tlf_definition, tlf)
            if validation:
                msg += check_field_value(self.tlf_definition, tlf)
            msg += check_fields_in_request(r, ae, 'census', validation=validation)
            if validation:
                msg += exist_user(r, ae)
                if tlf in current_tlfs:
                    msg += "Tlf %s repeat." % tlf
                current_tlfs.append(tlf)
            else:
                if msg:
                    msg = ''
                    continue
                exist = exist_user(r, ae)
                if exist and not exist.count('None'):
                    continue
                # By default we creates the user as active we don't check
                # the pipeline
                u = create_user(r, ae, True, request.user)
                give_perms(u, ae)
        if msg and validation:
            SmsOtp.error(\
                "Sms.census error\n"\
                "error '%r'\n"\
                "validation '%r'\n"\
                "request '%r'\n"\
                "authevent '%r'\n"\
                "Stack trace: \n%s",\
                msg, validation, req, ae, stack_trace_str())
            return self.error("Incorrect data", error_codename="invalid_credentials")

        if validation:
            for r in req.get('census'):
                # By default we creates the user as active we don't check
                # the pipeline
                u = create_user(r, ae, True, request.user)
                give_perms(u, ae)
        LOGGER.debug(\
            "SmsOtp.census success\n"\
            "response '%r'\n"\
            "validation '%r'\n"\
            "msg '%r'"\
            "request '%r'\n"\
            "authevent '%r'\n"\
            "Stack trace: \n%s",\
            data, validation, msg, req, ae, stack_trace_str())
        return data

    def register(self, ae, request):
        req = json.loads(request.body.decode('utf-8'))

        user_exists_codename = ("user_exists" \
                                if True == settings.SHOW_ALREADY_REGISTERED \
                                else "invalid_credentials")

        msg = check_pipeline(request, ae)
        if msg:
            LOGGER.error(\
                "SmsOtp.register error\n"\
                "error '%r'\n"\
                "authevent '%r'\n"\
                "request '%r'\n"\
                "Stack trace: \n%s",\
                msg, ae, req, stack_trace_str())
            return self.error("Incorrect data", error_codename="invalid_credentials")

        # create the user as active? Usually yes, but the execute_pipeline call inside
        # check_fields_in_request might modify this
        req['active'] = True

        reg_match_fields = []
        if ae.extra_fields is not None:
            reg_match_fields = [
                f for f in ae.extra_fields
                if "match_census_on_registration" in f and f['match_census_on_registration']
            ]

        # NOTE the fields of type "fill_if_empty_on_registration" need
        # to be empty, otherwise the user is already registered.
        reg_fill_empty_fields = []
        if ae.extra_fields is not None:
            reg_fill_empty_fields = [
                f for f in ae.extra_fields
                if "fill_if_empty_on_registration" in f and f['fill_if_empty_on_registration']
            ]

        msg = ''
        if req.get('tlf'):
            req['tlf'] = get_cannonical_tlf(req.get('tlf'))
        tlf = req.get('tlf')
        if isinstance(tlf, str):
            tlf = tlf.strip()
        msg += check_field_type(self.tlf_definition, tlf)
        msg += check_field_value(self.tlf_definition, tlf)
        msg += check_fields_in_request(req, ae)
        if msg:
            LOGGER.error(\
                "SmsOtp.register error\n"\
                "error '%r'\n"\
                "authevent '%r'\n"\
                "request '%r'\n"\
                "Stack trace: \n%s",\
                msg, ae, req, stack_trace_str())
            return self.error("Incorrect data", error_codename="invalid_credentials")
        # get active from req, this value might have changed in check_fields_in_requests
        active = req.pop('active')

        if len(reg_match_fields) > 0 or len(reg_fill_empty_fields) > 0:
            # is the tlf a match field?
            match_tlf = False
            match_tlf_element = None
            for extra in ae.extra_fields:
                if 'name' in extra and 'tlf' == extra['name'] and "match_census_on_registration" in extra and extra['match_census_on_registration']:
                    match_tlf = True
                    match_tlf_element = extra
                    break
            # if the tlf is not a match field, and there already is a user
            # with that tlf, reject the registration request
            if not match_tlf and User.objects.filter(userdata__tlf=tlf, userdata__event=ae, is_active=True).count() > 0:
                LOGGER.error(\
                    "SmsOtp.register error\n"\
                    "tlf is not a match field and  there already is a user with that tlf\n"\
                    "error '%r'\n"\
                    "user '%r'\n"\
                    "authevent '%r'\n"\
                    "request '%r'"\
                    "Stack trace: \n%s",\
                    msg,\
                    User.objects.filter(userdata__tlf=tlf, userdata__event=ae, is_active=True)[0],\
                    ae, req, stack_trace_str())
                return self.error("Incorrect data", error_codename=user_exists_codename)

            # lookup in the database if there's any user with the match fields
            # NOTE: we assume reg_match_fields are unique in the DB and required
            search_tlf = tlf if match_tlf else ""
            if match_tlf:
                reg_match_fields.remove(match_tlf_element)
            q = Q(userdata__event=ae,
                  is_active=False,
                  userdata__tlf=search_tlf)
            # Check the reg_match_fields
            for reg_match_field in reg_match_fields:
                 # Filter with Django's JSONfield
                 reg_name = reg_match_field.get('name')
                 if not reg_name:
                     LOGGER.error(\
                         "SmsOtp.register error\n"\
                         "'name' not in match field '%r'\n"\
                         "authevent '%r'\n"\
                         "request '%r'\n"\
                         "Stack trace: \n%s",\
                         reg_match_field, ae, req, stack_trace_str())
                     return self.error("Incorrect data", error_codename="invalid_credentials")
                 req_field_data = req.get(reg_name)
                 if reg_name and req_field_data:
                     q = q & Q(userdata__metadata__contains={reg_name: req_field_data})
                 else:
                     LOGGER.error(\
                         "SmsOtp.register error\n"\
                         "match field '%r' missing in request '%r'\n"\
                         "authevent '%r'\n"\
                         "Stack trace: \n%s",\
                         reg_name, req, ae, stack_trace_str())
                     return self.error("Incorrect data", error_codename="invalid_credentials")

            # Check that the reg_fill_empty_fields are empty, otherwise the user
            # is already registered
            for reg_empty_field in reg_fill_empty_fields:
                 # Filter with Django's JSONfield
                 reg_name = reg_empty_field.get('name')
                 if not reg_name:
                     LOGGER.error(\
                         "SmsOtp.register error\n"\
                         "'name' not in empty field '%r'\n"\
                         "authevent '%r'\n"\
                         "request '%r'\n"\
                         "Stack trace: \n%s",\
                         reg_empty_field, ae, req, stack_trace_str())
                     return self.error("Incorrect data", error_codename="invalid_credentials")
                 # Note: the register query _must_ contain a value for these fields
                 if reg_name and reg_name in req and req[reg_name]:
                     q = q & Q(userdata__metadata__contains={reg_name: ""})
                 else:
                     LOGGER.error(\
                         "SmsOtp.register error\n"\
                         "the register query _must_ contain a value for these fields\n"\
                         "reg_name '%r'\n"\
                         "reg_name in req '%r'\n"\
                         "req[reg_name] '%r'\n"\
                         "authevent '%r'\n"\
                         "request '%r'\n"\
                         "Stack trace: \n%s",\
                         reg_name, (reg_name in req), req[reg_name], ae,\
                         req, stack_trace_str())
                     return self.error("Incorrect data", error_codename="invalid_credentials")

            user_found = None
            user_list = User.objects.filter(q)
            if 1 == len(user_list):
                user_found = user_list[0]

                # check that the unique:True extra fields are actually unique
                uniques = []
                for extra in ae.extra_fields:
                    if 'unique' in extra.keys() and extra.get('unique'):
                        uniques.append(extra['name'])
                if len(uniques) > 0:
                    base_uq = Q(userdata__event=ae, is_active=True)
                    base_list = User.objects.exclude(id = user_found.id)
                    for reg_name in uniques:
                        req_field_data = req.get(reg_name)
                        if reg_name and req_field_data:
                            uq = base_q & Q(userdata__metadata__contains={reg_name: req_field_data})
                            repeated_list = base_list.filter(uq)
                            if repeated_list.count() > 0:
                                LOGGER.error(\
                                    "SmsOtp.register error\n"\
                                    "unique field named '%r'\n"\
                                    "with content '%r'\n"\
                                    "is repeated on '%r'\n"\
                                    "authevent '%r'\n"\
                                    "request '%r'\n"\
                                    "Stack trace: \n%s",\
                                    reg_name, req_field_data, repeated_list[0],\
                                    ae, req, stack_trace_str())
                                return self.error("Incorrect data", error_codename="invalid_credentials")

            # user needs to exist
            if user_found is None:
                LOGGER.error(\
                    "SmsOtp.register error\n"\
                    "user not found for query '%r'\n"\
                    "authevent '%r'\n"\
                    "request '%r'\n"\
                    "Stack trace: \n%s",\
                    q, ae, req, stack_trace_str())
                return self.error("Incorrect data", error_codename="invalid_credentials")

            for reg_empty_field in reg_fill_empty_fields:
                reg_name = reg_empty_field['name']
                if reg_name in req:
                    user_found.userdata.metadata[reg_name] = req.get(reg_name)
            user_found.userdata.save()
            if not match_tlf:
                user_found.userdata.tlf = tlf
            user_found.userdata.save()
            u = user_found
        else:
            msg_exist = exist_user(req, ae, get_repeated=True)
            if msg_exist:
                ret_error = True
                try:
                    tlf = get_cannonical_tlf(req['tlf'])
                    u = User.objects.get(userdata__tlf=tlf, userdata__event=ae)
                    # user is  admin and is disabled (deregistered)
                    # allow him to re-register with new parameters
                    if settings.ADMIN_AUTH_ID == ae.pk and \
                        False == u.is_active and \
                        True == settings.ALLOW_DEREGISTER:
                        edit_user(u, req, ae)
                        u.is_active = True
                        u.save()
                        ret_error = False
                except:
                    pass
                if ret_error:
                    LOGGER.error(\
                        "SmsOtp.register error\n"\
                        "User already exists '%r'\n"\
                        "authevent '%r'\n"\
                        "request '%r'\n"\
                        "Stack trace: \n%s",\
                        msg_exist, ae, req, stack_trace_str())
                    return self.error("Incorrect data", error_codename=user_exists_codename)
            else:
                u = create_user(req, ae, active, request.user)
                msg += give_perms(u, ae)
                u.userdata.tlf = tlf
                u.userdata.save()

        if msg:
            LOGGER.error(\
                "SmsOtp.register error\n"\
                "Probably a permissions error\n"\
                "Error '%r'\n"\
                "authevent '%r'\n"\
                "request '%r'\n"\
                "Stack trace: \n%s",\
                msg, ae, req, stack_trace_str())
            return self.error("Incorrect data", error_codename="invalid_credentials")
        elif not active:
            # Note, we are not calling to extend_send_sms because we are not
            # sending the code in here
            LOGGER.debug(\
                "SmsOtp.register.\n"\
                "user id '%r' is not active, message NOT sent\n"\
                "authevent '%r'\n"\
                "request '%r'\n"\
                "Stack trace: \n%s",\
                u.id, ae, req, stack_trace_str())
            return {'status': 'ok', 'user': u}

        result = plugins.call("extend_send_sms", ae, 1)
        if result:
            LOGGER.error(\
                "SmsOtp.register error\n"\
                "extend_send_sms plugin error\n"\
                "Error '%r'\n"\
                "authevent '%r'\n"\
                "request '%r'\n"\
                "Stack trace: \n%s",\
                result, ae, req, stack_trace_str())
            return self.error("Incorrect data", error_codename="invalid_credentials")
        send_codes.apply_async(args=[[u.id,], get_client_ip(request),'sms'])
        LOGGER.info(\
            "SmsOtp.register.\n"\
            "Sending (sms) codes to user id '%r'"\
            "client ip '%r'\n"\
            "authevent '%r'\n"\
            "request '%r'\n"\
            "Stack trace: \n%s",\
            u.id, get_client_ip(request), ae, req, stack_trace_str())
        return {'status': 'ok', 'user': u}

    def authenticate(self, ae, request):
        req = json.loads(request.body.decode('utf-8'))

        msg = ''
        if req.get('tlf'):
            req['tlf'] = get_cannonical_tlf(req.get('tlf'))
        tlf = req.get('tlf')
        if isinstance(tlf, str):
            tlf = tlf.strip()

        tlf_def = self.tlf_definition if not settings.MAKE_LOGIN_KEY_PRIVATE else self.tlf_opt_definition
        msg += check_field_type(tlf_def, tlf, 'authenticate')
        msg += check_field_value(tlf_def, tlf, 'authenticate')
        msg += check_field_type(self.code_definition, req.get('code'), 'authenticate')
        msg += check_field_value(self.code_definition, req.get('code'), 'authenticate')
        msg += check_fields_in_request(req, ae, 'authenticate')
        if msg:
            LOGGER.error(\
                "SmsOtp.authenticate error\n"\
                "error '%r'"\
                "authevent '%r'\n"\
                "request '%r'\n"\
                "Stack trace: \n%s",\
                msg, ae, req, stack_trace_str())
            return self.error("Incorrect data", error_codename="invalid_credentials")

        try:
            q = Q(userdata__event=ae, is_active=True)
            if 'tlf' in req:
                q = q & Q(userdata__tlf=tlf)
            elif not settings.MAKE_LOGIN_KEY_PRIVATE:
                return self.error("Incorrect data", error_codename="invalid_credentials")

            q = get_required_fields_on_auth(req, ae, q)
            u = User.objects.get(q)
        except:
            LOGGER.error(\
                "SmsOtp.authenticate error\n"\
                "user not found with these characteristics: tlf '%r'\n"\
                "authevent '%r'\n"\
                "is_active True\n"\
                "request '%r'\n"\
                "Stack trace: \n%s",\
                tlf, ae, req, stack_trace_str())
            return self.error("Incorrect data", error_codename="invalid_credentials")

        successful_logins_count = u.userdata.successful_logins.filter(is_active=True).count()
        if (ae.num_successful_logins_allowed > 0 and
            successful_logins_count >= ae.num_successful_logins_allowed):
            LOGGER.error(\
                "SmsOtp.authenticate error\n"\
                "Maximum number of revotes already reached for user '%r'\n"\
                "revotes for user '%r'\n"\
                "maximum allowed '%r'\n"\
                "authevent '%r'\n"\
                "request '%r'\n"\
                "Stack trace: \n%s",\
                u.userdata,\
                successful_logins_count,\
                ae.num_successful_logins_allowed,\
                ae, req, stack_trace_str())
            return self.error("Incorrect data", error_codename="invalid_credentials")

        code = Code.objects.filter(
            user=u.userdata,
            created__gt=datetime.now() - timedelta(seconds=settings.SMS_OTP_EXPIRE_SECONDS)
            ).order_by('-created').first()
        if not code:       
            LOGGER.error(\
                "SmsOtp.authenticate error\n"\
                "Code not found on db for user '%r'\n"\
                "and time between now and '%r' seconds earlier\n"\
                "authevent '%r'\n"\
                "request '%r'\n"\
                "Stack trace: \n%s",\
                u.userdata,\
                settings.SMS_OTP_EXPIRE_SECONDS,\
                ae, req, stack_trace_str())
            return self.error("Incorrect data", error_codename="invalid_credentials")
          
        if not constant_time_compare(req.get('code').upper(), code.code):  
            LOGGER.error(\
                "SmsOtp.authenticate error\n"\
                "Code mismatch for user '%r'\n"\
                "Code received '%r'\n"\
                "and latest code in the db for the user '%r'\n"\
                "authevent '%r'\n"\
                "request '%r'\n"\
                "Stack trace: \n%s",\
                u.userdata, req.get('code').upper(), code.code, ae, req,\
                stack_trace_str())
            return self.error("Incorrect data", error_codename="invalid_credentials")

        msg = check_metadata(req, u)
        if msg:
            LOGGER.error(\
                "SmsOtp.authenticate error\n"\
                "Metadata error '%r'\n"\
                "authevent '%r'\n"\
                "request '%r'\n"\
                "Stack trace: \n%s",\
                msg, ae, req, stack_trace_str())
            return self.error("Incorrect data", error_codename="invalid_credentials")

        user_logged_in.send(sender=u.__class__, request=request, user=u)
        u.save()

        data = {'status': 'ok'}
        data['username'] = u.username
        data['auth-token'] = genhmac(settings.SHARED_SECRET, u.username)

        # add redirection
        auth_action = ae.auth_method_config['config']['authentication-action']
        if auth_action['mode'] == 'go-to-url':
            data['redirect-to-url'] = auth_action['mode-config']['url']

        LOGGER.debug(\
            "SmsOtp.authenticate success\n"\
            "returns '%r'\n"\
            "authevent '%r'\n"\
            "request '%r'\n"\
            "Stack trace: \n%s",\
            data, ae, req, stack_trace_str())
        return data

    def resend_auth_code(self, ae, request):
        req = json.loads(request.body.decode('utf-8'))

        msg = ''
        if req.get('tlf'):
            req['tlf'] = get_cannonical_tlf(req.get('tlf'))
        tlf = req.get('tlf')
        if isinstance(tlf, str):
            tlf = tlf.strip()
        msg += check_field_type(self.tlf_definition, tlf, 'authenticate')
        msg += check_field_value(self.tlf_definition, tlf, 'authenticate')
        if msg:
            LOGGER.error(\
                "SmsOtp.resend_auth_code error\n"\
                "error '%r'\n"\
                "authevent '%r'\n"\
                "request '%r'\n"\
                "Stack trace: \n%s",\
                msg, ae, req, stack_trace_str())
            return self.error("Incorrect data", error_codename="invalid_credentials")

        try:
            u = User.objects.get(userdata__tlf=tlf, userdata__event=ae, is_active=True)
        except:
            LOGGER.error(\
                "SmsOtp.resend_auth_code error\n"\
                "user not found with these characteristics: tlf '%r'\n"\
                "authevent '%r'\n"\
                "is_active True"\
                "request '%r'\n"\
                "Stack trace: \n%s",\
                tlf, ae, req, stack_trace_str())
            return self.error("Incorrect data", error_codename="invalid_credentials")

        msg = check_pipeline(
          request,
          ae,
          'resend-auth-pipeline',
          SmsOtp.PIPELINES['resend-auth-pipeline'])

        if msg:
            LOGGER.error(\
                "SmsOtp.resend_auth_code error\n"\
                "check_pipeline error '%r'\n"\
                "authevent '%r'\n"\
                "request '%r'\n"\
                "Stack trace: \n%s",\
                msg, ae, req, stack_trace_str())
            return self.error("Incorrect data", error_codename="invalid_credentials")

        result = plugins.call("extend_send_sms", ae, 1)
        if result:
            LOGGER.error(\
                "SmsOtp.resend_auth_code error\n"\
                "extend_send_sms plugin error\n"\
                "Error '%r'\n"\
                "authevent '%r'\n"\
                "request '%r'\n"\
                "Stack trace: \n%s",\
                result, ae, req, stack_trace_str())
            return self.error("Incorrect data", error_codename="invalid_credentials")
        send_codes.apply_async(args=[[u.id,], get_client_ip(request),'sms'])
        LOGGER.info(\
            "SmsOtp.resend_auth_code.\n"\
            "Sending (sms) codes to user id '%r'\n"\
            "client ip '%r'\n"\
            "authevent '%r'\n"\
            "request '%r'\n"\
            "Stack trace: \n%s",\
            u.id, get_client_ip(request), ae, req, stack_trace_str())
        return {'status': 'ok', 'user': u}

register_method('sms-otp', SmsOtp)
