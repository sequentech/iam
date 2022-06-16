# This file is part of iam.
# Copyright (C) 2014-2021  Sequent Tech Inc <legal@sequentech.io>

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
from utils import (
  verifyhmac,
  HMACToken,
  verify_admin_generated_auth_code
)
from django.conf import settings
from django.contrib.auth.models import User
from utils import (
    verify_admin_generated_auth_code
)
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
)

from contracts.base import check_contract
from contracts import CheckException



LOGGER = logging.getLogger('iam')

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
  MANDATORY_FIELDS = dict(
    types=[],
    names=['user_id']
  )
  CONFIG_CONTRACT = [
    {
      'check': 'isinstance',
      'type': dict
    },
    {
      'check': 'lambda',
      'lambda': lambda data: (
        'shared_secret' not in data or
        (
          isinstance(data['shared_secret'], str) and
          len(data['shared_secret']) > 0 and
          len(data['shared_secret']) < 1000
        )
      )
    }
  ]


  user_id_definition = dict(
    name="user_id",
    type="text",
    required=True,
    min=1,
    max=255,
    unique=True,
    required_on_authentication=True
  )

  def check_config(self, config):
    if config is not None:
      try:
        check_contract(self.CONFIG_CONTRACT, config)
      except CheckException as e:
        return str(e.data)
    return ''

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
      data, stack_trace_str()
    )
    return data

  def authenticate(self, auth_event, request):
    req = json.loads(request.body.decode('utf-8'))
    verified, user = verify_admin_generated_auth_code(
        auth_event=auth_event,
        req_data=req,
        log_prefix="Email"
    )
    if verified:
        if not verify_num_successful_logins(auth_event, 'Email', user, req):
            return self.error(
                "Incorrect data",
                error_codename="invalid_credentials"
            )

        return return_auth_data('Email', req, request, user)

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
      
      shared_secret = settings.SHARED_SECRET
      if (
        isinstance(auth_event.auth_method_config, dict) and 
        'shared_secret' in auth_event.auth_method_config
      ):
        shared_secret = auth_event.auth_method_config['shared_secret']

      shared_secret = auth_event\
        .auth_method_config\
        .get('config', dict())\
        .get('shared_secret', settings.SHARED_SECRET.decode('utf-8'))\
        .encode('utf-8')

      verified = verifyhmac(
        key=shared_secret,
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
      # enforce user_id to match the token user_id in the request
      req['user_id'] = user_id
      user_query = get_base_auth_query(auth_event)
      user_query = get_required_fields_on_auth(req, auth_event, user_query)
      user = User.objects.get(user_query)
      post_verify_fields_on_auth(user, req, auth_event)
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
    return resend_auth_code(
      auth_event=auth_event,
      request=request,
      logger_name="SmartLink",
      default_pipelines=SmartLink.PIPELINES
    )

  def generate_auth_code(self, auth_event, request):
    return generate_auth_code(
      auth_event=auth_event,
      request=request,
      logger_name="SmartLink"
    )

register_method('smart-link', SmartLink)
