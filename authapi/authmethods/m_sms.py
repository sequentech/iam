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
from django.conf import settings
from django.conf.urls import url
from django.db.models import Q
from django.contrib.auth.models import User
from django.shortcuts import get_object_or_404
from utils import (
  genhmac, send_codes, get_client_ip, is_valid_url, constant_time_compare
)

import plugins
from . import register_method
from contracts.base import check_contract, JsonTypeEncoder
from contracts import CheckException
from authmethods.utils import *


class Sms:
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
        }
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
            ["check_total_max", {"field": "ip", "max": 8}],
            ["check_total_max", {"field": "tlf", "max": 7}],
            ["check_total_max", {"field": "tlf", "period": 1440, "max": 5}],
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
            ["check_total_max", {"field": "tlf", "period": 3600, "max": 5}],
            ["check_total_max", {"field": "tlf", "period": 3600*24, "max": 15}],
            ["check_total_max", {"field": "ip", "period": 3600, "max": 10}],
            ["check_total_max", {"field": "ip", "period": 3600*24, "max": 20}],
        ]
    }
    USED_TYPE_FIELDS = ['tlf']

    tlf_definition = { "name": "tlf", "type": "text", "required": True, "min": 4, "max": 20, "required_on_authentication": True }
    code_definition = { "name": "code", "type": "text", "required": True, "min": 6, "max": 255, "required_on_authentication": True }

    CONFIG_CONTRACT = [
      {
        'check': 'isinstance',
        'type': dict
      },
      {
        'check': 'dict-keys-exact',
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
        return d

    def check_config(self, config):
        """ Check config when create auth-event. """
        msg = ''
        try:
            check_contract(self.CONFIG_CONTRACT, config)
            return ''
        except CheckException as e:
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
                u = create_user(r, ae, True)
                give_perms(u, ae)
        if msg and validation:
            return self.error("Incorrect data", error_codename="invalid_credentials")

        if validation:
            for r in req.get('census'):
                # By default we creates the user as active we don't check
                # the pipeline
                u = create_user(r, ae, True)
                give_perms(u, ae)
        return data

    def register(self, ae, request):
        req = json.loads(request.body.decode('utf-8'))

        msg = check_pipeline(request, ae)
        if msg:
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

        # TODO: FIXME: use this
        # NOTE now, the fields of type "fill_if_empty_on_registration" need
        # to be empty, otherwise user is already registered.
        # TODO: NOTE that we assume it's only one field, the tlf field
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
            return self.error("Incorrect data", error_codename="invalid_credentials")
        # get active from req, this value might have changed in check_fields_in_requests
        active = req.pop('active')

        if len(reg_match_fields) > 0 or len(reg_fill_empty_fields) > 0:
            # check that there isn't any user registered with the user provided
            # unique reg_fill_empty_fields (i.e. the tlf), because tlf should
            # be unique and we are about to set the tlf to an existing user
            # with an empty tlf
            match_tlf = False
            match_tlf_element = None
            for extra in ae.extra_fields:
                if 'name' in extra and 'tlf' == extra['name'] and "match_census_on_registration" in extra and extra['match_census_on_registration']:
                    match_tlf = True
                    match_tlf_element = extra
                    break
            if not match_tlf and User.objects.filter(userdata__tlf=tlf, userdata__event=ae, is_active=True).count() > 0:
                return self.error("Incorrect data", error_codename="invalid_credentials")

            # lookup in the database if there's any user with those fields
            # NOTE: we assume reg_match_fields are unique in the DB and
            # required, and only one match_field
            search_tlf = tlf if match_tlf else ""
            if match_tlf:
                reg_match_fields.remove(match_tlf_element)
            q = Q(userdata__event=ae,
                  is_active=False,
                  userdata__tlf=search_tlf)
            # Check the reg_match_fields
            for reg_match_field in reg_match_fields:
                 # Filter with Django's JSONfield
                 reg_name = reg_match_field['name']
                 req_field_data = req.get(reg_name)
                 if reg_name and req_field_data:
                     q = q & Q(userdata__metadata__contains={reg_name: req_field_data})
                 else:
                     return self.error("Incorrect data", error_codename="invalid_credentials")

            # Check that the reg_fill_empty_fields are empty, otherwise the user
            # is already registered
            for reg_empty_field in reg_fill_empty_fields:
                 # Filter with Django's JSONfield
                 reg_name = reg_empty_field['name']
                 # Note: the register query _must_ contain a value for these fields
                 if reg_name and reg_name in req and req[reg_name]:
                     q = q & Q(userdata__metadata__contains={reg_name: ""})
                 else:
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
                                return self.error("Incorrect data", error_codename="invalid_credentials")

            # user needs to exist
            if user_found is None:
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
                return self.error("Incorrect data", error_codename="invalid_credentials")
            else:
                u = create_user(req, ae, active)
                msg += give_perms(u, ae)

        if msg:
            return self.error("Incorrect data", error_codename="invalid_credentials")
        elif not active:
            # Note, we are not calling to extend_send_sms because we are not
            # sending the code in here
            return {'status': 'ok'}

        result = plugins.call("extend_send_sms", ae, 1)
        if result:
            return self.error("Incorrect data", error_codename="invalid_credentials")
        send_codes.apply_async(args=[[u.id,], get_client_ip(request),'sms'])
        return {'status': 'ok'}

    def authenticate(self, ae, request):
        req = json.loads(request.body.decode('utf-8'))

        msg = ''
        if req.get('tlf'):
            req['tlf'] = get_cannonical_tlf(req.get('tlf'))
        tlf = req.get('tlf')
        if isinstance(tlf, str):
            tlf = tlf.strip()
        msg += check_field_type(self.tlf_definition, tlf, 'authenticate')
        msg += check_field_value(self.tlf_definition, tlf, 'authenticate')
        msg += check_field_type(self.code_definition, req.get('code'), 'authenticate')
        msg += check_field_value(self.code_definition, req.get('code'), 'authenticate')
        msg += check_fields_in_request(req, ae, 'authenticate')
        if msg:
            return self.error("Incorrect data" + msg, error_codename="invalid_credentials")

        try:
            u = User.objects.get(userdata__tlf=tlf, userdata__event=ae, is_active=True)
        except:
            return self.error("Incorrect data", error_codename="invalid_credentials")

        code = Code.objects.filter(user=u.userdata,
                code=req.get('code').upper()).order_by('-created').first()
        if not code:
            return self.error("Incorrect data", error_codename="invalid_credentials")

        msg = check_pipeline(request, ae, 'authenticate')
        if msg:
            return self.error("Incorrect data" + msg, error_codename="invalid_credentials")

        msg = check_metadata(req, u)
        if msg:
            return self.error("Incorrect data" + msg, error_codename="invalid_credentials")

        u.save()

        data = {'status': 'ok'}
        data['username'] = u.username
        data['auth-token'] = genhmac(settings.SHARED_SECRET, u.username)

        # add redirection
        auth_action = ae.auth_method_config['config']['authentication-action']
        if auth_action['mode'] == 'go-to-url':
            data['redirect-to-url'] = auth_action['mode-config']['url']

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
            return self.error("Incorrect data" + msg, error_codename="invalid_credentials")

        try:
            u = User.objects.get(userdata__tlf=tlf, userdata__event=ae, is_active=True)
        except:
            return self.error("Incorrect data", error_codename="invalid_credentials")

        msg = check_pipeline(
          request,
          ae,
          'resend-auth-pipeline',
          Sms.PIPELINES['resend-auth-pipeline'])

        if msg:
            return self.error("Incorrect data" + msg, error_codename="invalid_credentials")

        result = plugins.call("extend_send_sms", ae, 1)
        if result:
            return self.error("Incorrect data", error_codename="invalid_credentials")
        send_codes.apply_async(args=[[u.id,], get_client_ip(request),'sms'])
        return {'status': 'ok'}

register_method('sms', Sms)
