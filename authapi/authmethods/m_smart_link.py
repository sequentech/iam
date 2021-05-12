# This file is part of authapi.
# Copyright (C) 2014-2021  Agora Voting SL <contact@nvotes.com>

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
from utils import verifyhmac, HMACToken
from django.conf import settings
from django.contrib.auth.models import User
from django.conf.urls import url
from django.db.models import Q

from utils import json_response
from utils import stack_trace_str
from authmethods.utils import *
from django.contrib.auth.signals import user_logged_in


LOGGER = logging.getLogger('authapi')

class SmartLink:
  DESCRIPTION = 'Authenticate using a SmartLink.'
  CONFIG = {}
  PIPELINES = {
    "register-pipeline": [],
    "authenticate-pipeline": [],
    'give_perms': [
      {
        'object_type': 'UserData', 
        'perms': ['edit',], 
        'object_id': 'UserDataId'
      },
      {
        'object_type': 'AuthEvent',
        'perms': ['vote',],
        'object_id': 'AuthEventId'
      }
    ]
  }
  USED_TYPE_FIELDS = ['user_id']

  user_id_definition = dict(
    name="user_id",
    type="text",
    required=True,
    min=1,
    max=255,
    required_on_authentication=True
  )

  def check_config(self, config):
    return ''

  def resend_auth_code(self, config):
    return {'status': 'ok'}

  def census(self, auth_event, request):
    req = json.loads(request.body.decode('utf-8'))
    validation = req.get('field-validation', 'enabled') == 'enabled'

    msg = ''
    current_user_ids = []
    
    # cannot add voters to an election with invalid children election info
    if auth_event.children_election_info is not None:
      try:
        verify_children_election_info(
            auth_event, request.user, ['edit', 'census-add'])
      except:
        LOGGER.error(
          "SmartLink.census error in verify_children_election_info"\
          "error '%r'\n"\
          "request '%r'\n"\
          "validation '%r'\n"\
          "authevent '%r'\n"\
          "Stack trace: \n%s",\
          msg, req, validation, auth_event, stack_trace_str()
        )
        return self.error("Incorrect data", error_codename="invalid_data")

    for census_element in req.get('census'):
        user_id = census_element.get('user_id')
        
        if isinstance(user_id, str):
          user_id = user_id.strip()
          user_id = user_id.replace(" ", "")
        
        msg += check_field_type(self.user_id_definition, user_id)
        
        if validation:
          msg += check_field_type(self.user_id_definition, user_id)
          msg += check_field_value(self.user_id_definition, user_id)

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
              "SmartLink.census error in verify_valid_children_elections"\
              "error '%r'\n"\
              "request '%r'\n"\
              "validation '%r'\n"\
              "authevent '%r'\n"\
              "Stack trace: \n%s",\
              msg, req, validation, auth_event, stack_trace_str()
            )
            return self.error("Incorrect data", error_codename="invalid_data")

        if validation:
          msg += exist_user(census_element, auth_event)
          if user_id in current_user_id:
            msg += "user_id %s is repeated in this census." % user_id
          current_user_id.append(user_id)
        else:
          if msg:
            LOGGER.debug(\
              "SmartLink.census warning\n"\
              "error (but validation disabled) '%r'\n"\
              "request '%r'\n"\
              "validation '%r'\n"\
              "authevent '%r'\n"\
              "Stack trace: \n%s",\
              msg, req, validation, auth_event, stack_trace_str()
            )
            msg = ''
            continue
          exist = exist_user(census_element, auth_event)
          if exist:
            continue
          # By default we create the user as active we don't check
          # the pipeline
          u = create_user(census_element, auth_event, True, request.user)
          give_perms(u, auth_event)

    if msg and validation:
      LOGGER.error(\
        "SmartLink.census error\n"\
        "error '%r'\n"\
        "request '%r'\n"\
        "validation '%r'\n"\
        "authevent '%r'\n"\
        "Stack trace: \n%s",\
        msg, req, validation, auth_event, stack_trace_str()
      )
      return self.error("Incorrect data", error_codename="invalid_credentials")

    if validation:
      for census_element in req.get('census'):
        # By default we create the user as active we don't check
        # the pipeline
        u = create_user(census_element, auth_event, True, request.user)
        give_perms(u, auth_event)
    
    ret = {'status': 'ok'}
    LOGGER.debug(\
      "SmartLink.census\n"\
      "request '%r'\n"\
      "validation '%r'\n"\
      "authevent '%r'\n"\
      "returns '%r'\n"\
      "Stack trace: \n%s",\
      req, validation, auth_event, ret, stack_trace_str()
    )
    return ret

  def error(self, msg, error_codename):
    data = {'status': 'nok', 'msg': msg, 'error_codename': error_codename}
    LOGGER.error(\
      "SmartLink.error\n"\
      "error '%r'\n"\
      "Stack trace: \n%s",\
      internal_error, data, stack_trace_str()
    )
    return data

  def authenticate(self, auth_event, request):
    req = json.loads(request.body.decode('utf-8'))
    msg = ''
    auth_token = req.get('auth-token')
    if not auth_token or not isinstance(auth_token, str):
      LOGGER.error(\
        "SmartLink.authenticate auth-token not found or not a string\n"\
        "authevent '%r'\n"\
        "request '%r'\n"\
        "Stack trace: \n%s",\
        auth_event, req, stack_trace_str()
      )
      return self.error(
        msg="Incorrect data",
        error_codename="invalid_credentials"
      )
    
    # we will obtain it from auth_token
    user_id = None
    try:
      hmac_token = HMACToken(auth_token)
      user_id, perm_obj, auth_event_id, perm_action, timestamp = hmac_token.msg.split(':')
      if len(user_id) == 0:
        LOGGER.error(\
          "SmartLink.authenticate auth-token: invalid user_id\n"\
          "authevent '%r'\n"\
          "request '%r'\n"\
          "Stack trace: \n%s",\
          auth_event, req, stack_trace_str()
        )
        return self.error(
          msg="Incorrect data",
          error_codename="invalid_credentials"
        )
      if auth_event_id != str(auth_event.id):
        LOGGER.error(\
          "SmartLink.authenticate auth-token: mismatched auth_event_id\n"\
          "authevent '%r'\n"\
          "request '%r'\n"\
          "Stack trace: \n%s",\
          auth_event, req, stack_trace_str()
        )
        return self.error(
          msg="Incorrect data",
          error_codename="invalid_credentials"
        )
      if perm_obj != 'AuthEvent' or perm_action != 'vote':
        LOGGER.error(\
          "SmartLink.authenticate auth-token: invalid permission\n"\
          "authevent '%r'\n"\
          "request '%r'\n"\
          "Stack trace: \n%s",\
          auth_event, req, stack_trace_str()
        )
        return self.error(
          msg="Incorrect data",
          error_codename="invalid_credentials"
        )

      if not hmac_token.check_expiration(settings.TIMEOUT):
        LOGGER.error(\
          "SmartLink.authenticate auth-token: expired\n"\
          "authevent '%r'\n"\
          "request '%r'\n"\
          "Stack trace: \n%s",\
          auth_event, req, stack_trace_str()
        )
        return self.error(
          msg="Incorrect data",
          error_codename="invalid_credentials"
        )

      verified = verifyhmac(
        key=settings.SHARED_SECRET,
        msg=hmac_token.msg,
        seconds=settings.TIMEOUT,
        at=hmac_token
      )

      if not verified:
        LOGGER.error(\
          "SmartLink.authenticate auth-token: invalid verification\n"\
          "authevent '%r'\n"\
          "request '%r'\n"\
          "Stack trace: \n%s",\
          auth_event, req, stack_trace_str()
        )
        return self.error(
          msg="Incorrect data",
          error_codename="invalid_credentials"
        )
    except Exception as e:
      LOGGER.error(\
        "SmartLink.authenticate auth-token: invalid exception\n"\
        "error: '%r'\n"\
        "authevent '%r'\n"\
        "request '%r'\n"\
        "Stack trace: \n%s",\
        e, auth_event, req, stack_trace_str()
      )
      return self.error(
        msg="Incorrect data",
        error_codename="invalid_credentials"
      )

    if auth_event.parent is not None:
      msg += 'you can only authenticate to parent elections'
      LOGGER.error(\
        "SmartLink.authenticate error\n"\
        "error '%r'"\
        "authevent '%r'\n"\
        "request '%r'\n"\
        "Stack trace: \n%s",\
        msg, auth_event, req, stack_trace_str()
      )
      return self.error("Incorrect data", error_codename="invalid_credentials")

    msg = check_pipeline(request, auth_event, 'authenticate')
    if msg:
      LOGGER.error(\
        "SmartLink.authenticate error\n"\
        "error '%r'\n"\
        "authevent '%r'\n"\
        "request '%r'\n"\
        "Stack trace: \n%s",\
        msg, auth_event, req, stack_trace_str()
      )
      return self.error("Incorrect data", error_codename="invalid_credentials")

    try:
      user_query = get_base_auth_query(auth_event)
      user_query = (
        user_query & Q(userdata__metadata__contains=dict(user_id=user_id))
      )
      user = User.objects.get(user_query)
    except:
      LOGGER.error(\
        "SmartLink.authenticate error\n"\
        "user not found with these characteristics: user-id '%r'\n"\
        "authevent '%r'\n"\
        "is_active True\n"\
        "request '%r'\n"\
        "Stack trace: \n%s",\
        user_id, auth_event, req, stack_trace_str()
      )
      return self.error("Incorrect data", error_codename="invalid_credentials")

    if not verify_num_successful_logins(auth_event, 'SmartLink', user, req):
      LOGGER.error(\
        "SmartLink.authenticate error too many logins\n"\
        "authevent '%r'\n"\
        "is_active True\n"\
        "request '%r'\n"\
        "Stack trace: \n%s",\
        auth_event, req, stack_trace_str()
      )
      return self.error("Incorrect data", error_codename="invalid_credentials")

    return return_auth_data('SmartLink', req, request, user)

  def resend_auth_code(self, auth_event, request):
    return {'status': 'ok'}

register_method('smart-link', SmartLink)
