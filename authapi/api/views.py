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

# This file contains all the API views
import os
import json
import requests
import mimetypes
from datetime import datetime
from django import forms
from django.conf import settings
from django.http import Http404
from django.db.models import Q, IntegerField
from django.db.models.functions import TruncHour, Cast
from django.contrib.auth.models import User
from django.views.generic import View
from django.shortcuts import get_object_or_404
from django.http import HttpResponse
from base64 import encodestring
from django.utils.text import slugify
from django.db.models import Count, OuterRef, Subquery

import plugins
from authmethods import (
    auth_authenticate,
    auth_census,
    auth_register,
    auth_resend_auth_code,
    auth_public_census_query,
    auth_generate_auth_code,
    check_config,
    METHODS,
)
from authmethods.utils import reset_voter_to_preregistration
from utils import (
    check_authmethod,
    check_extra_fields,
    check_admin_fields,
    check_pipeline,
    genhmac,
    HMACToken,
    json_response,
    paginate,
    permission_required,
    random_code,
    send_mail,
    ErrorCodes,
    VALID_FIELDS,
    VALID_PIPELINES,
    filter_query,
    stack_trace_str,
    reproducible_json_dumps
)
from .decorators import login_required, get_login_user
from .models import (
    Action,
    ACL,
    AuthEvent,
    SuccessfulLogin,
    ALLOWED_ACTIONS,
    User,
    UserData,
    BallotBox,
    TallySheet,
    children_election_info_validator
)
from .tasks import (
    census_send_auth_task,
    update_ballot_boxes_config,
    publish_results_task,
    unpublish_results_task,
    allow_tally_task,
    calculate_results_task
)
from captcha.views import generate_captcha
from utils import send_codes, get_client_ip, parse_json_request

# import fields checks
from pipelines.field_register import *
from pipelines.field_authenticate import *
from contracts.base import check_contract
from contracts import CheckException
import logging

LOGGER = logging.getLogger('authapi')

CONTRACTS = dict(
    list_of_ints=[
      {
        'check': 'isinstance',
        'type': list
      },
      {
        'check': "iterate-list",
        'check-list': [
          {
            'check': 'isinstance',
            'type': int
          }
        ]
      }
    ],
    tally_sheet=[
      {
        'check': 'isinstance',
        'type': dict
      },
      {
        'check': 'dict-keys-exist',
        'keys': ['num_votes', 'questions', 'observations']
      },
      {
        'check': 'index-check-list',
        'index': 'num_votes',
        'check-list': [
          {
            'check': 'isinstance',
            'type': int
          },
          {
            'check': 'lambda',
            'lambda': lambda d: d >= 0
          }
        ]
      },
      {
        'check': 'index-check-list',
        'index': 'observations',
        'check-list': [
          {
            'check': 'isinstance',
            'type': str
          },
          {
            'check': 'length',
            'range': [0,2048]
          }
        ]
      },
      {
        'check': 'index-check-list',
        'index': 'questions',
        'check-list': [
          {
            'check': 'isinstance',
            'type': list
          },
          {
            'check': 'length',
            'range': [1,255]
          },
          {
            'check': "iterate-list",
            'check-list': [
              {
                'check': 'isinstance',
                'type': dict
              },
              {
                'check': 'dict-keys-exist',
                'keys': [
                    'title', 'blank_votes', 'null_votes', 'tally_type',
                    'answers'
                ]
              },
              {
                'check': 'index-check-list',
                'index': 'title',
                'check-list': [
                  {
                    'check': 'isinstance',
                    'type': str
                  },
                  {
                    'check': 'length',
                    'range': [1, 255]
                  }
                ]
              },
              {
                'check': 'index-check-list',
                'index': 'blank_votes',
                'check-list': [
                  {
                    'check': 'isinstance',
                    'type': int
                  },
                  {
                    'check': 'lambda',
                    'lambda': lambda d: d >= 0
                  }
                ]
              },
              {
                'check': 'index-check-list',
                'index': 'tally_type',
                'check-list': [
                  {
                    'check': 'isinstance',
                    'type': str
                  },
                  {
                    'check': 'lambda',
                    'lambda': lambda d: d in ['plurality-at-large']
                  }
                ]
              },
              {
                'check': 'index-check-list',
                'index': 'answers',
                'check-list': [
                  {
                    'check': 'isinstance',
                    'type': list
                  },
                  {
                    'check': 'length',
                    'range': [1,1024]
                  },
                  {
                    'check': "iterate-list",
                    'check-list': [
                      {
                        'check': 'isinstance',
                        'type': dict
                      },
                      {
                        'check': 'dict-keys-exist',
                        'keys': ['text', 'num_votes']
                      },
                      {
                        'check': 'index-check-list',
                        'index': 'text',
                        'check-list': [
                          {
                            'check': 'isinstance',
                            'type': str
                          },
                          {
                            'check': 'length',
                            'range': [1,1024]
                          }
                        ]
                      },
                      {
                        'check': 'index-check-list',
                        'index': 'num_votes',
                        'check-list': [
                          {
                            'check': 'isinstance',
                            'type': int
                          },
                          {
                            'check': 'lambda',
                            'lambda': lambda d: d >= 0
                          }
                        ]
                      }
                    ]
                  }
                ]
              }
            ]
          }
        ]
      },
      {
        'check': 'lambda',
        'lambda': lambda d: all([
          (
            sum([
              d['num_votes'],
              -q['blank_votes'],
              -q['null_votes']
            ]) * q['max']
          ) >= sum(
            [i['num_votes']  for i in q['answers']]
          )
          for q in d['questions']
        ])
      },
    ]
)

class CensusDelete(View):
    '''
    Delete census in the auth-event.

    It requires different permissions ('census-delete' or 'census-delete' and
    'census-delete-voted') depending on if the voter has already voted or not.

    The following input parameters are in the data section in json format:
    - user-ids: Required, list of ints. It's the list of ids of the affected
                users.
    - comment: Optional, string. Maximum 255 characters. It's a comment related
               to the action that will be logged in the activity.

    A single action will be created per deleted user in the activity log.
    '''
    def post(self, request, pk):
        permission_required(
            request.user, 
            'AuthEvent',
            ['edit', 'census-delete'], 
            pk
        )
        auth_event = get_object_or_404(AuthEvent, pk=pk)
        req = parse_json_request(request)
        user_ids = req.get('user-ids', [])
        comment = req.get('comment', None)
        
        # parse input
        try:
          check_contract(CONTRACTS['list_of_ints'], user_ids)
          if comment is not None:
              assert(isinstance(comment, str))
              assert(len(comment) <= 255)
        except:
            return json_response(
                status=400,
                error_codename=ErrorCodes.BAD_REQUEST
            )
        
        users = [
            get_object_or_404(
                User,
                pk=user_id, 
                userdata__event=auth_event
            )
            for user_id in user_ids
        ]

        # check if any of the users have voted, and if so require the extra
        # census-delete-voted permission for the auth_event
        action_name = 'user:deleted-from-census'
        for user in users:
            if len(
                user.userdata.serialize_children_voted_elections(auth_event)
            ) > 0:
                permission_required(
                    request.user, 
                    'AuthEvent',
                    ['edit', 'census-delete-voted'], 
                    pk
                )
                action_name = 'user:deleted-voted-from-census'
                break

        # delete user and log the delete action
        from authmethods.utils import get_trimmed_user
        for user in users:
            action = Action(
                executer=request.user,
                receiver=None,
                action_name=action_name,
                event=auth_event,
                metadata={
                    **get_trimmed_user(user, auth_event),
                    **dict(comment=comment)
                }
            )
            action.save()

            for acl in user.userdata.acls.all():
                acl.delete()
            
            user.delete()
        return json_response()

census_delete = login_required(CensusDelete.as_view())


class CensusActivate(View):
    '''
    Activates/deactivates an user in the auth-event census.

    The following input parameters are in the data section in json format:
    - user-ids: Required, list of ints. It's the list of ids of the affected
                users.
    - comment: Optional, string. Maximum 255 characters. It's a comment related
               to the action that will be logged in the activity.

    A single action will be created per user activated in the activity log.
    '''

    activate = True

    def post(self, request, pk):
        # check permissions
        permission_required(request.user, 'AuthEvent', ['edit', 'census-activation'], pk)

        # get input
        ae = get_object_or_404(AuthEvent, pk=pk)
        req = parse_json_request(request)
        user_ids = req.get('user-ids', [])
        comment = req.get('comment', None)

        # parse input
        try:
          check_contract(CONTRACTS['list_of_ints'], user_ids)
          if comment is not None:
              assert(isinstance(comment, str))
              assert(len(comment) <= 255)
        except:
            return json_response(
                status=400,
                error_codename=ErrorCodes.BAD_REQUEST)

        # activate users
        for uid in user_ids:
            u = get_object_or_404(User, pk=uid, userdata__event=ae)
            u.is_active = self.activate
            u.save()
            # autofilling autofill fields with admin data
            ae.autofill_fields(from_user=request.user, to_user=u)

            # register activity, one action per user
            action_name = 'user:activate' if self.activate else 'user:deactivate'
            action = Action(
                executer=request.user,
                receiver=u,
                action_name=action_name,
                event=ae,
                metadata=dict(comment=comment))
            action.save()

        # send codes on activation
        if self.activate:
            send_codes.apply_async(
                args=[
                  [u for u in user_ids],
                  get_client_ip(request),
                  ae.auth_method
                ])

        return json_response()
census_activate = login_required(CensusActivate.as_view())


class CensusDeactivate(CensusActivate):
    '''
    Deactivates an user in the auth-event census
    '''
    activate = False
census_deactivate = login_required(CensusDeactivate.as_view())


class Census(View):
    '''
    Add census in the auth-event
    '''

    def post(self, request, pk):
        permission_required(request.user, 'AuthEvent', ['edit', 'census-add'], pk)
        e = get_object_or_404(AuthEvent, pk=pk)
        error_kwargs = plugins.call("extend_add_census", e, request)

        if e.parent is not None:
            # Child authevents can't have census
            return json_response(status=400, error_codename=ErrorCodes.BAD_REQUEST)

        if error_kwargs:
            return json_response(**error_kwargs[0])
        try:
            data = auth_census(e, request)
        except:
            return json_response(status=400, error_codename=ErrorCodes.BAD_REQUEST)
        if data['status'] == 'ok':
            return json_response(data)
        else:
            return json_response(
                status=400,
                error_codename=data.get('error_codename'))

    def get(self, request, pk):
        permission_required(request.user, 'AuthEvent', ['edit', 'view-census'], pk)
        auth_event = get_object_or_404(AuthEvent, pk=pk)

        filter_str = request.GET.get('filter', None)
        query = auth_event.get_census_query()

        if filter_str is not None:
            if len(auth_event.extra_fields):
                filter_str = "%" + filter_str + "%"
                where_params = [filter_str, filter_str, filter_str]
                where_clause = '''
                    UPPER("auth_user"."username"::text) LIKE UPPER(%s)
                    OR UPPER("auth_user"."email"::text) LIKE UPPER(%s)
                    OR UPPER("api_userdata"."tlf"::text) LIKE UPPER(%s)
                '''
                
                for field in auth_event.extra_fields:
                    where_clause += '''
                        OR UPPER(api_userdata.metadata::jsonb->>%s) LIKE UPPER(%s)
                    '''
                    where_params += [field['name'], filter_str]
                
                query = query\
                    .select_related('user', 'user__user')\
                    .extra(
                        where=[where_clause],
                        params=where_params
                    )

            else:
                q = (
                    Q(user__user__username__icontains=filter_str) |
                    Q(user__user__email__icontains=filter_str) |
                    Q(user__tlf__icontains=filter_str)
                )
                query = query.filter(q)

        has_voted_str = request.GET.get('has_voted__equals', None)
        if has_voted_str is not None:
            if 'false' == has_voted_str:
                query = query\
                    .annotate(
                        logins=Count('user__successful_logins')
                    )\
                    .filter(logins__exact=0)
            elif 'true' == has_voted_str:
                query = query\
                    .annotate(
                        logins=Count('user__successful_logins')
                    )\
                    .filter(logins__gt=0)

        has_activity = request.GET.get('has_activity__equals', None)
        query = query.annotate(
            actions_count=Count("user__user__executed_actions")
        )
        if has_activity is not None:
            if 'false' == has_activity:
                query = query.filter(actions_count__exact=0)
            elif 'true' == has_activity:
                query = query.filter(actions_count__gt=0)

        # filter, with constraints
        query = filter_query(
            filters=request.GET,
            query=query,
            constraints=dict(
                filters=dict(
                    user__user__id=dict(
                        lt=int,
                        gt=int,
                    ),
                    user__user__is_active=dict(
                        equals=bool
                    ),
                    user__user__date_joined=dict(
                        lt=datetime,
                        gt=datetime
                    )
                ),
                order_by=[
                    'user__user__id',
                    'user__user__is_active',
                    'user__user__date_joined'
                ]
            ),
            prefix='census__',
            contraints_policy='ignore_invalid')

        def serializer(acl):
          return {
            "id": acl.user.user.pk,
            "username": acl.user.user.username,
            "active": acl.user.user.is_active,
            "has_activity": acl.actions_count > 0,
            "date_joined": acl.user.user.date_joined.isoformat(),
            "metadata": acl.user.serialize_data(),
            "voted_children_elections": acl.user.serialize_children_voted_elections(auth_event)
          }

        acls = paginate(
          request,
          query,
          serialize_method=serializer,
          elements_name='object_list')
        return json_response(acls)
census = login_required(Census.as_view())


class Authenticate(View):
    ''' Authenticate into the authapi '''

    def post(self, request, pk):
        try:
            e = get_object_or_404(AuthEvent, pk=pk, status="started")
        except:
            return json_response(status=400, error_codename=ErrorCodes.BAD_REQUEST)

        if not hasattr(request.user, 'account'):
            error_kwargs = plugins.call("extend_auth", e)
            if error_kwargs:
                return json_response(**error_kwargs[0])
        try:
            data = auth_authenticate(e, request)
        except:
            return json_response(status=400, error_codename=ErrorCodes.BAD_REQUEST)

        if data and 'status' in data and data['status'] == 'ok':
            user = User.objects.get(username=data['username'])
            action = Action(
                executer=user,
                receiver=user,
                action_name='user:authenticate',
                event=user.userdata.event,
                metadata=dict())
            action.save()

            return json_response(data)
        else:
            return json_response(
              status=400,
              error_codename=data.get('error_codename'),
              message=data.get('msg', '-'))
authenticate = Authenticate.as_view()


class GenerateAuthCode(View):
    ''' Admin generates auth code for an user'''

    def post(self, request, pk):
        permission_required(
            request.user, 
            'AuthEvent', 
            ['edit', 'generate-auth-code'],
            pk
        )
        auth_event = get_object_or_404(AuthEvent, pk=pk)
        try:
            out_data, user = auth_generate_auth_code(auth_event, request)
        except:
            return json_response(
                status=400,
                error_codename=ErrorCodes.BAD_REQUEST
            )

        action = Action(
            executer=request.user,
            receiver=user,
            action_name='user:generate-auth-code',
            event=user.userdata.event,
            metadata=dict()
        )
        action.save()

        return json_response(out_data)

generate_auth_code = login_required(GenerateAuthCode.as_view())


class PublicCensusQueryView(View):
    ''' Allow users to publicly query the census'''

    def post(self, request, pk):
        if int(pk) == 0:
            e = 0
        else:
            e = get_object_or_404(
                AuthEvent,
                pk=pk,
                status__in=['notstarted', 'started'],
                allow_public_census_query=True)

        try:
            data = auth_public_census_query(e, request)
        except:
            return json_response(
                status=400,
                error_codename=ErrorCodes.BAD_REQUEST)

        if data and 'status' in data and data['status'] == 'ok':
            return json_response(data)
        else:
            return json_response(
              status=400,
              error_codename=data.get('error_codename'),
              message=data.get('msg', '-'))

public_census_query = PublicCensusQueryView.as_view()


class Ping(View):
    ''' Returns true if the user is authenticated, else returns false.
        If the user is authenticated a new authtoken is sent
    '''

    def get(self, request, pk):
        u, error, _ = get_login_user(request)
        status = None
        data = {}

        if u and error is None:
            data = {
              'auth-token': genhmac(settings.SHARED_SECRET, u.username)
            }
            status = 200
        else:
            data = error
            status = 403

        return json_response(data, status=status)
ping = Ping.as_view()


class SuccessfulLoginView(View):
    '''
    Records a successful login
    '''
    def post(self, request, pk, uid):
        # userid is not used, but recorded in the log
        user, error, khmac_obj = get_login_user(request)

        valid_data = ["AuthEvent", pk, "RegisterSuccessfulLogin"]

        auth_event = get_object_or_404(AuthEvent, pk=pk)

        # check everything is ok
        if (not user or
            error is not None or
            (
                (
                    auth_event.parent is None and 
                    str(user.userdata.event.id) != pk
                ) or (
                    auth_event.parent is not None and 
                    (
                        int(pk) not in user.userdata.event.children_election_info.get('natural_order', []) or
                        auth_event.parent_id != user.userdata.event.id
                    )
                )
            ) or
            type(khmac_obj) != HMACToken or
            khmac_obj.get_other_values() != valid_data):
            return json_response({}, status=403)

        sl = SuccessfulLogin(
            user=user.userdata, 
            is_active=user.is_active,
            auth_event=auth_event
        )
        sl.save()

        action = Action(
            executer=user,
            receiver=user,
            action_name='user:successful-login',
            event=user.userdata.event,
            metadata=dict(auth_event=pk))
        action.save()

        return json_response({}, status=200)

successful_login = SuccessfulLoginView.as_view()

class CallbackView(View):
    '''
    Records a callback
    '''
    def post(self, request, pk):
        # userid is not used, but recorded in the log
        user, error, khmac_obj = get_login_user(request)

        valid_data = ["AuthEvent", pk, "Callback"]

        # check everything is ok
        if (not user or
            error is not None or
            type(khmac_obj) != HMACToken or
            khmac_obj.get_other_values() != valid_data):
            return json_response({}, status=403)
        ae = get_object_or_404(AuthEvent, pk=pk)

        action = Action(
            executer=user,
            receiver=user,
            action_name="authevent:callback",
            event=ae)
        action.save()

        action = Action(
            receiver=user,
            action_name="authevent:callback",
            event=ae)
        action.save()

        plugins.call("extend_callback", request, ae, get_client_ip(request))

        return json_response({}, status=200)

callback = CallbackView.as_view()


class Archive(View):
    '''
    Archives an auth-event
    '''
    def post(self, request, pk):
        permission_required(request.user, 'AuthEvent', ['edit', 'archive'], pk)
        auth_event = get_object_or_404(AuthEvent, pk=pk)

        # Get all edit and view perms and convert edit into unarchive and view
        # into view-archived permissions
        acls = ACL.objects.filter(
            perm__in=['edit', 'view'],
            object_type='AuthEvent',
            object_id=pk
        )
        converter_map = dict(edit='unarchive', view='view-archived')
        for acl in acls:
            acl.perm = converter_map[acl.perm]
            acl.save()

        # register the action
        action = Action(
            executer=request.user,
            receiver=None,
            action_name='authevent:archive',
            event=auth_event,
            metadata=dict())
        action.save()

        return json_response()
archive = login_required(Archive.as_view())


class Unarchive(View):
    '''
    Unarchives an auth-event
    '''
    def post(self, request, pk):
        permission_required(request.user, 'AuthEvent', ['unarchive'], pk)
        auth_event = get_object_or_404(AuthEvent, pk=pk)

        # Reverts the archiving of an auth-event
        acls = ACL.objects.filter(
            perm__in=['unarchive', 'view-archived'],
            object_type='AuthEvent',
            object_id=pk
        )
        converter_map = {
            'unarchive': 'edit',
            'view-archived': 'view'
        }
        for acl in acls:
            acl.perm = converter_map[acl.perm]
            acl.save()
        
        # register the action
        action = Action(
            executer=request.user,
            receiver=None,
            action_name='authevent:unarchive',
            event=auth_event,
            metadata=dict())
        action.save()

        return json_response()
unarchive = login_required(Unarchive.as_view())

class VoteStatsView(View):
    '''
    Returns statistical data about votes

    This code is dependent on a postgresql backend
    '''
    def get(self, request, pk):
        permission_required(request.user, 'AuthEvent', ['view-stats', 'edit'], pk)

        auth_event = AuthEvent.objects.get(pk=pk)
        if auth_event.children_election_info:
            parents2 = auth_event.children_election_info['natural_order']
        else:
            parents2 = []

        q_base = SuccessfulLogin.objects\
            .filter(
                Q(auth_event_id=pk) |
                Q(auth_event__parent_id=pk) |
                Q(auth_event__parent_id__in=parents2)
            )
        subquery_distinct = q_base\
            .order_by('user_id', '-created')\
            .distinct('user_id')

        q = q_base\
            .annotate(hour=TruncHour('created'))\
            .values('hour')\
            .annotate(votes=Count('user_id'))\
            .order_by('hour')\
            .filter(id__in=subquery_distinct)
        
        data = dict(
            total_votes=subquery_distinct.count(),
            votes_per_hour = [
                dict(
                    hour=str(obj['hour']),
                    votes=obj['votes']
                )
                for obj in q
            ]
        )

        return json_response(data)

vote_stats = login_required(VoteStatsView.as_view())


class Register(View):
    ''' Register into the authapi '''

    def post(self, request, pk):
        e = get_object_or_404(AuthEvent, pk=pk)

        if e.pk == settings.ADMIN_AUTH_ID and settings.ALLOW_ADMIN_AUTH_REGISTRATION:
            return json_response(
                status=400,
                error_codename="REGISTER_IS_DISABLED")

        # find if there's any extra field of type
        match_census_on_registration  = []
        if e.extra_fields is not None:
            match_census_on_registration = [
                f for f in e.extra_fields
                if "match_census_on_registration" in f and f['match_census_on_registration']
            ]

        if (e.census == 'close') and (len(match_census_on_registration) == 0 or e.status != 'started'):
            return json_response(
                status=400,
                error_codename="REGISTER_IS_DISABLED")
        # registration is closed
        if e.census == 'open' and e.status != 'started':
            return json_response(
                status=400,
                error_codename="AUTH_EVENT_NOT_STARTED")

        data = auth_register(e, request)
        if data['status'] == 'ok':

            if "user" in data:
                action = Action(
                    executer=data['user'],
                    receiver=data['user'],
                    action_name='user:register',
                    event=e,
                    metadata=dict())
                action.save()
                del data['user']

            return json_response(data)
        else:
            return json_response(
                status=400,
                error_codename=data.get('error_codename'))
register = Register.as_view()


class ResendAuthCode(View):
    ''' Register into the authapi '''

    def post(self, request, pk):
        auth_event = get_object_or_404(AuthEvent, pk=pk)
        if (auth_event.census == 'close' and not auth_event.check_allow_user_resend()):
            return json_response(
                status=400,
                error_codename="AUTH_EVENT_NOT_STARTED")
        # registration is closed
        if (auth_event.census == 'open' or auth_event.check_allow_user_resend()) and auth_event.status != 'started':
            return json_response(
                status=400,
                error_codename="AUTH_EVENT_NOT_STARTED")

        data = auth_resend_auth_code(auth_event, request)
        if data['status'] == 'ok':
            if 'user' in data:
                action = Action(
                    executer=data['user'],
                    receiver=data['user'],
                    action_name='user:resend-authcode',
                    event=data['user'].userdata.event,
                    metadata=dict())
                action.save()
                del data['user']

            return json_response(data)
        else:
            return json_response(
                status=400,
                message=data.get('msg', '-'),
                error_codename=data.get('error_codename'))
resend_auth_code = ResendAuthCode.as_view()


class AuthEventStatus(View):
    '''
    Change the status of auth-event, its children and also calls to agora-elections
    to reflect it.
    '''

    def post(self, request, pk, status):
        alt = dict(
            notstarted="notstarted",
            started='start',
            stopped='stop'
        )[status]
        permission_required(request.user, 'AuthEvent', ['edit', alt], pk)
        
        main_auth_event = get_object_or_404(AuthEvent, pk=pk)
        
        if main_auth_event.children_election_info is not None:
            children_ids = main_auth_event.children_election_info['natural_order']
        else:
            children_ids = []
        
        auth_events = AuthEvent.objects.filter(
            Q(pk=pk) |
            Q(parent_id=pk) |
            Q(parent_id__in=children_ids)
        )
        
        for auth_event in auth_events:
            # update AuthEvent

            if auth_event.status != status:
                auth_event.status = status
                auth_event.save()

                # trace the event
                if auth_event.id != pk:
                    metadata = dict(auth_event=auth_event.id)
                else:
                    metadata = dict()
                action = Action(
                    executer=request.user,
                    receiver=None,
                    action_name='authevent:' + alt,
                    event=main_auth_event,
                    metadata=metadata
                )
                action.save()
            
            # update in agora-elections
            if alt in ['start', 'stop']:
                for callback_base in settings.AGORA_ELECTIONS_BASE:
                    callback_url = "%s/api/election/%s/%s" % (
                        callback_base,
                        auth_event.id,
                        alt
                    )
                    data = "[]"

                    agora_elections_request = requests.post(
                        callback_url,
                        json=data,
                        headers={
                            'Authorization': genhmac(
                                settings.SHARED_SECRET,
                                "1:AuthEvent:%s:%s" % (auth_event.id, alt)
                            ),
                            'Content-type': 'application/json'
                        }
                    )
                    if agora_elections_request.status_code != 200:
                        LOGGER.error(\
                            "AuthEventStatus.post\n"\
                            "agora_elections.callback_url '%r'\n"\
                            "agora_elections.data '%r'\n"\
                            "agora_elections.status_code '%r'\n"\
                            "agora_elections.text '%r'\n",\
                            callback_url, 
                            data, 
                            agora_elections_request.status_code, 
                            agora_elections_request.text
                        )

                        return json_response(
                            status=500,
                            error_codename=ErrorCodes.GENERAL_ERROR
                        )

                    LOGGER.info(\
                        "AuthEventStatus.post\n"\
                        "agora_elections.callback_url '%r'\n"\
                        "agora_elections.data '%r'\n"\
                        "agora_elections.status_code '%r'\n"\
                        "agora_elections.text '%r'\n",\
                        callback_url, 
                        data, 
                        agora_elections_request.status_code, 
                        agora_elections_request.text
                    )

        return json_response(
            status=200, 
            message='Authevent status: %s' % status
        )
ae_status = login_required(AuthEventStatus.as_view())


class GetPerms(View):
    ''' Returns the permission token if the user has this perm '''

    def post(self, request):
        data = {'status': 'ok'}

        try:
            req = parse_json_request(request)
        except:
            return json_response(
                status=400,
                error_codename=ErrorCodes.BAD_REQUEST)

        if 'permission' not in req or 'object_type' not in req:
            return json_response(
                status=400,
                error_codename=ErrorCodes.BAD_REQUEST)

        object_type = req['object_type']
        perms = req['permission'].split("|")
        obj_id = req.get('object_id', 0)

        filtered_perms = "|".join([
            perm
            for perm in perms
            if (
                request.user.is_superuser or
                request.user.userdata.has_perms(object_type, perm, obj_id)
            )
        ])

        if len(filtered_perms) == 0:
            return json_response(
                status=400,
                error_codename=ErrorCodes.BAD_REQUEST)

        msg = ':'.join((request.user.username, object_type, str(obj_id), filtered_perms))

        data['permission-token'] = genhmac(settings.SHARED_SECRET, msg)
        return json_response(data)
getperms = login_required(GetPerms.as_view())


class ACLView(View):
    ''' Returns the permission token if the user has this perm '''

    def delete(self, request, username, object_type, perm, object_id=0):
        permission_required(request.user, 'ACL', 'delete')
        u = get_object_or_404(User, username=username)
        for acl in u.userdata.get_perms(object_type, perm, object_id):
            acl.delete()
        data = {'status': 'ok'}
        return json_response(data)

    def get(self, request, username, object_type, perm, object_id=0):
        permission_required(request.user, 'ACL', 'view')
        data = {'status': 'ok'}
        u = get_object_or_404(User, username=username)
        if u.userdata.has_perms(object_type, perm, object_id):
            data['perm'] = True
        else:
            data['perm'] = False
        return json_response(data)

    def post(self, request):
        permission_required(request.user, 'ACL', 'create')
        data = {'status': 'ok'}

        try:
            req = parse_json_request(request)

            user_id = req.get('userid', None)
            assert(isinstance(user_id, int))

            perms = req.get('perms', [])
            assert(isinstance(perms, list))
        except:
            return json_response(
                status=400,
                error_codename=ErrorCodes.BAD_REQUEST)

        u = User.objects.get(pk=req.get('userid', None))
        for perm in perms:
            user = get_object_or_404(UserData, user__username=perm['user'])
            acl = ACL(user=user, perm=perm['perm'], object_type=perm['object_type'],
                    object_id=perm.get('object_id', 0))
            acl.save()
        return json_response(data)
acl = login_required(ACLView.as_view())

class ACLMine(View):
    ''' Returns the user ACL perms '''

    def get(self, request):
        object_type = request.GET.get('object_type', None)
        object_id = request.GET.get('object_id', None)
        perm = request.GET.get('perm', None)

        data = {'status': 'ok', 'perms': []}
        q = Q()
        if object_type:
            q = Q(object_type=object_type)
        if object_id:
            q &= Q(object_id=object_id)
        if perm:
            perms = perm.split('|')
            q &= Q(perm__in=perms)

        query = request.user.userdata.acls.filter(q)

        acls = paginate(request, query,
                       serialize_method='serialize',
                       elements_name='perms')
        data.update(acls)
        return json_response(data)
aclmine = login_required(ACLMine.as_view())


class Activity(View):
    '''
    Returns the list of actions related to an election or filtered by
    receiver_id, executer_id or a list of actions.

    Returns  the data ordered by creation date, first the most recent.

    Allowed GET params:
    - executer_id: Int, optional. Number of the executer of the action to filter
      by. Example: "56".

    - receiver_id: Int, optional. Number of the receiver of the action to filter
      by. Example: "56".

    - actions: List, optional. Actions to filter by. The list is pipe ('|')
      separated. Example: "election:create|voter:deactivate".

    - filter: String, optional. A string to filter in some of the fields of the
      model.
    '''
    @login_required
    def get(request, pk=None):
        # get allowed filters
        executer_id = request.GET.get('executer_id', None)
        receiver_id = request.GET.get('receiver_id', None)
        actions = request.GET.get('actions', None)
        filter_str = request.GET.get('filter', None)

        # the global event activity list requires a different permission
        if receiver_id is None:
            permission_required(
                request.user,
                'AuthEvent',
                ['event-view-activity', 'edit'],
                pk)
        else:
            permission_required(
                request.user,
                'AuthEvent',
                ['event-view-activity', 'event-receiver-view-activity', 'edit'],
                pk)

        # validate input
        try:
            executer_id = int(executer_id) if executer_id is not None else None
            receiver_id = int(receiver_id) if receiver_id is not None else None
            if actions is not None:
                actions = actions.split('|')
                for action in actions:
                    assert((action, action) in ALLOWED_ACTIONS)
        except Exception as e:
            return json_response(
                status=400,
                error_codename=ErrorCodes.BAD_REQUEST)

        # apply filters
        q = Q()
        if receiver_id:
            q = Q(receiver__pk=receiver_id)
        if executer_id:
            q &= Q(executer__pk=executer_id)
        if actions:
            q &= Q(action_name__in=actions)
        event = get_object_or_404(AuthEvent, pk=pk)
        query = event.related_actions.filter(q)

        if filter_str is not None:
            q2 = (
              Q(executer__username__icontains=filter_str) |
              Q(executer__email__icontains=filter_str) |
              Q(executer__userdata__tlf__icontains=filter_str) |

              Q(receiver__username__icontains=filter_str) |
              Q(receiver__email__icontains=filter_str) |
              Q(receiver__userdata__tlf__icontains=filter_str) |

              Q(action_name__icontains=filter_str) |
              Q(metadata__icontains=filter_str)
            )
            query = query.filter(q2)

        # filter, with constraints
        query = filter_query(
            filters=request.GET,
            query=query,
            constraints=dict(
                filters=dict(
                    id=dict(
                        lt=int,
                        gt=int,
                        equals=int
                    ),
                    executer__id=dict(
                        lt=int,
                        gt=int,
                    ),
                    receiver__id=dict(
                        lt=int,
                        gt=int,
                    ),
                    created=dict(
                        lt=datetime,
                        gt=datetime
                    )
                ),
                order_by=[
                    'created',
                    'executer__id',
                    'receiver__id'
                ],
                default_ordery_by='-created'
            ),
            prefix='activity__',
            contraints_policy='ignore_invalid')


        # paginate query and return
        data = {'status': 'ok', 'activity': []}
        activity_paged = paginate(
            request,
            query,
            serialize_method='serialize',
            elements_name='activity')
        data.update(activity_paged)
        return json_response(data)

activity = login_required(Activity.as_view())

class EditChildrenParentView(View):
    @login_required
    def post(request, pk):
        '''
        Edit the Children Info or Parent info of
        an election
        '''
        from authmethods.utils import verify_children_election_info
        permission_required(request.user, 'AuthEvent', 'edit', pk)
        auth_event = get_object_or_404(AuthEvent, pk=pk, status='notstarted')
        try:
            req = parse_json_request(request)
        except:
            return json_response(
                status=400,
                error_codename=ErrorCodes.BAD_REQUEST)

        # check parent_id
        parent_id = req.get('parent_id', None)
        children_election_info = req.get('children_election_info', None)
        parent = None
        if parent_id is not None:
            if (
                type(parent_id) is not int or
                AuthEvent.objects.filter(pk=parent_id).count() != 1
            ):
                return json_response(
                    status=400,
                    error_codename="INVALID_PARENT_ID"
                )
            parent = AuthEvent.objects.get(pk=parent_id)
            auth_event.parent = parent
        else:
            auth_event.parent = None

        # children_election_info
        # 
        # There's a difference here with when an election is created:
        # children_election_info is verified to relate to valid elections
        # that the requesting user can edit
        if children_election_info is not None:
            try:
                children_election_info_validator(children_election_info)
                verify_children_election_info(
                    auth_event, 
                    request.user, 
                    ['edit'],
                    children_election_info
                )
            except:
                return json_response(
                    status=400,
                    error_codename="INVALID_CHILDREN_ELECTION_INFO"
                )
            auth_event.children_election_info = children_election_info
        else: 
            auth_event.children_election_info = None
        
        auth_event.save()
        data = {'status': 'ok', 'id': auth_event.pk}
        return json_response(data)

edit_children_parent = EditChildrenParentView.as_view()

class AuthEventView(View):
    @login_required
    def post(request, pk=None):
        '''
            Creates a new auth-event or edit auth_event
            create_authevent permission required or
            edit_authevent permission required
        '''
        try:
            req = parse_json_request(request)
        except:
            return json_response(
                status=400,
                error_codename=ErrorCodes.BAD_REQUEST)

        if pk is None: # create
            # requires create perm
            permission_required(request.user, 'AuthEvent', 'create')

            # we allow to request a specific AuthEvent id, and we allow to do an
            # "upsert", i.e. if the AuthEvent exists, update it instead of 
            # create it. But we need to verify permissions in that case.
            requested_id = req.get('id', None)
            election_exists = False
            if requested_id and isinstance(requested_id, int):
              count_existing_elections = AuthEvent.objects.filter(pk=requested_id).count()
              if count_existing_elections != 0:
                permission_required(request.user, 'AuthEvent', 'edit', requested_id)
                election_exists = True
            else:
              requested_id = None

            auth_method = req.get('auth_method', '')

            # check if send code method is authorized
            disable_auth_method = False
            extend_info = plugins.call(
                "extend_disable_auth_method",
                auth_method,
                None
            )
            if extend_info:
                for info in extend_info:
                     disable_auth_method = info
            if disable_auth_method:
                return json_response(
                    status=400,
                    error_codename=ErrorCodes.BAD_REQUEST)

            msg = check_authmethod(auth_method)
            if msg:
                return json_response(status=400, message=msg)

            auth_method_config = {
                    "config": METHODS.get(auth_method).CONFIG,
                    "pipeline": METHODS.get(auth_method).PIPELINES
            }
            config = req.get('auth_method_config', None)
            if config:
                msg += check_config(config, auth_method)

            extra_fields = req.get('extra_fields', None)
            if extra_fields:
                msg += check_extra_fields(
                    extra_fields,
                    METHODS.get(auth_method).USED_TYPE_FIELDS)
                slug_set = set()
                for field in extra_fields:
                    if 'name' in field:
                        field['slug'] = slugify(field['name'])\
                            .replace("-","_")\
                            .upper()
                        slug_set.add(field['slug'])
                    else:
                        msg += "some extra_fields have no name\n"
                if len(slug_set) != len(extra_fields):
                    msg += "some extra_fields may have repeated slug names\n"

            admin_fields = req.get('admin_fields', None)
            if admin_fields:
                msg += check_admin_fields(
                    admin_fields,
                    METHODS.get(auth_method).USED_TYPE_FIELDS)

            # check census mode
            census = req.get('census', '')
            if not census in ('open', 'close'):
                return json_response(
                    status=400,
                    error_codename="INVALID_CENSUS_TYPE")
            error_kwargs = plugins.call("extend_type_census", census)
            if error_kwargs:
                return json_response(**error_kwargs[0])

            # check if it has ballot boxes
            has_ballot_boxes = req.get('has_ballot_boxes', False)
            if not isinstance(has_ballot_boxes, bool):
                return json_response(
                    status=400,
                    error_codename="INVALID_BALLOT_BOXES")

            # check if it has hide_default_login_lookup_field
            hide_default_login_lookup_field = req.get(
                'hide_default_login_lookup_field',
                False
            )
            if not isinstance(hide_default_login_lookup_field, bool):
                return json_response(
                    status=400,
                    error_codename="INVALID_HIDE_DEFAULT_LOGIN_LOOKUP_FIELD")

            # check if census public can query the census
            allow_public_census_query = req.get('allow_public_census_query', False)
            if not isinstance(allow_public_census_query, bool):
                return json_response(
                    status=400,
                    error_codename="INVALID_PUBLIC_CENSUS_QUERY")

            based_in = req.get('based_in', None)
            if (
                based_in and 
                not ACL.objects.filter(
                    user=request.user.userdata,
                    perm='edit',
                    object_type='AuthEvent',
                    object_id=based_in
                )
            ):
                msg += "Invalid id to based_in"
            
            # check parent_id
            parent_id = req.get('parent_id', None)
            parent = None
            if parent_id:
                if (
                    type(parent_id) is not int or
                    AuthEvent.objects.filter(pk=parent_id).count() != 1
                ):
                    return json_response(
                        status=400,
                        error_codename="INVALID_PARENT_ID")
                parent = AuthEvent.objects.get(pk=parent_id)
            
            # children_election_info
            children_election_info = req.get('children_election_info', None)
            if children_election_info:
                try:
                    children_election_info_validator(children_election_info)
                except:
                    return json_response(
                        status=400,
                        error_codename="INVALID_CHILDREN_ELECTION_INFO")


            # Note that a login is only complete if a call has been received and
            # accepted at /authevent/<ID>/successful_login
            num_successful_logins_allowed = req.get(
                'num_successful_logins_allowed', 0)
            if type(num_successful_logins_allowed) is not int:
                msg += "num_successful_logins_allowed invalid type"

            if msg:
                return json_response(
                    status=400,
                    message=msg,
                    error_codename=ErrorCodes.BAD_REQUEST)

            if config:
                auth_method_config.get('config').update(config)

            election_options = dict(
                auth_method=auth_method,
                auth_method_config=auth_method_config,
                extra_fields=extra_fields,
                admin_fields=admin_fields,
                parent=parent,
                census=census,
                num_successful_logins_allowed=num_successful_logins_allowed,
                children_election_info=children_election_info,
                based_in=based_in,
                has_ballot_boxes=has_ballot_boxes,
                hide_default_login_lookup_field=hide_default_login_lookup_field,
                allow_public_census_query=allow_public_census_query
            )
            # If the election exists, we are doing an update. Else, we are 
            # doing an insert. We use this update method instead of just 
            # creating an AuthEvent with the election id set because it would
            # fail to set some properties like the AuthEvent.created attribute.
            if election_exists:
              AuthEvent.objects\
                .filter(pk=requested_id)\
                .update(**election_options)
              ae = AuthEvent.objects.get(pk=requested_id)
            else:
              ae = AuthEvent(
                # this is needed to set the election id if election id is 
                # supplied but the election doesn't exist
                pk=requested_id,
                **election_options
              )
              ae.save()

            acl = ACL(
                user=request.user.userdata,
                perm='edit', 
                object_type='AuthEvent',
                object_id=ae.id
            )
            acl.save()
            acl = ACL(
                user=request.user.userdata,
                perm='create',
                object_type='UserData',
                object_id=ae.id
            )
            acl.save()

            action = Action(
                executer=request.user,
                action_name='authevent:create',
                event=ae,
                metadata=dict(
                    auth_method=auth_method,
                    auth_method_config=auth_method_config,
                    extra_fields=extra_fields,
                    admin_fields=admin_fields,
                    census=census,
                    num_successful_logins_allowed=num_successful_logins_allowed,
                    hide_default_login_lookup_field=hide_default_login_lookup_field,
                    based_in=based_in
                )
            )
            action.save()

            # if necessary, generate captchas
            from authmethods.utils import have_captcha
            if have_captcha(ae):
                generate_captcha(settings.PREGENERATION_CAPTCHA)

        else: # edit
            permission_required(request.user, 'AuthEvent', 'edit', pk)
            auth_method = req.get('auth_method', '')
            msg = check_authmethod(auth_method)
            if msg:
                return json_response(status=400, message=msg)

            # check if send code method is authorized
            disable_auth_method = False
            extend_info = plugins.call("extend_disable_auth_method", auth_method, pk)
            if extend_info:
                for info in extend_info:
                     disable_auth_method = info
            if disable_auth_method:
                return json_response(
                    status=400,
                    error_codename=ErrorCodes.BAD_REQUEST)

            config = req.get('auth_method_config', None)
            if config:
                msg += check_config(config, auth_method)

            extra_fields = req.get('extra_fields', None)
            if extra_fields:
                msg += check_extra_fields(extra_fields)

            if msg:
                return json_response(status=400, message=msg)

            ae = AuthEvent.objects.get(pk=pk)
            ae.auth_method = auth_method
            if config:
                ae.auth_method_config.get('config').update(config)
            if extra_fields:
                ae.extra_fields = extra_fields
            ae.save()

            # TODO: Problem if object_id is None, change None by 0
            acl = get_object_or_404(ACL, user=request.user.userdata,
                    perm='edit', object_type='AuthEvent', object_id=ae.pk)

            action = Action(
                executer=request.user,
                action_name='authevent:edit',
                event=ae,
                metadata=dict(
                    auth_method=auth_method,
                    auth_method_config=ae.auth_method_config.get('config'),
                    extra_fields=extra_fields
                )
            )
            action.save()


        data = {'status': 'ok', 'id': ae.pk, 'perm': acl.get_hmac()}
        return json_response(data)

    def get(self, request, pk=None):
        '''
            Lists all AuthEvents if not pk. If pk show the event with this pk
        '''
        data = {'status': 'ok'}
        user, _, _ = get_login_user(request)

        if pk:
            e = AuthEvent.objects.get(pk=pk)
            if (user is not None and user.is_authenticated and
                permission_required(
                    user,
                    'AuthEvent',
                    ['edit', 'view', 'view-archived'],
                    e.id,
                    return_bool=True)):
                aes = e.serialize()
            else:
                aes = e.serialize_restrict()

            extend_info = plugins.call("extend_ae_info", user, e)
            if extend_info:
                for info in extend_info:
                    aes.update(info.serialize())

            data['events'] = aes
        else:
            ids = request.GET.get('ids', None)
            only_parent_elections = request.GET.get('only_parent_elections', None)
            has_perms = request.GET.get('has_perms', None)
            q = Q()
            if ids is not None:
                try:
                    ids = ids.split('|')
                    ids = [int(id) for id in ids]
                    q &= Q(id__in=ids)
                except:
                    ids = None
            
            if only_parent_elections is not None:
                q &= (
                    Q(parent_id=None) |
                    Q(parent_id__isnull=False, children_election_info__isnull=False)
                )

            serialize_method = 'serialize_restrict'
            if (
                user is not None and
                user.is_authenticated and
                user.userdata is not None
            ):
                if has_perms is not None:
                    perms_split = has_perms.split('|')
                    q &= Q(
                        id__in=user.userdata.acls\
                            .filter(
                                object_type='AuthEvent',
                                perm__in=perms_split
                            )\
                            .annotate(
                                object_id_int=Cast(
                                    'object_id',
                                    output_field=IntegerField()
                                )
                            )\
                            .values('object_id_int')
                    )
            
                    if (
                        'view' in perms_split or
                        'edit' in perms_split or
                        'view-archived' in perms_split
                    ):
                        serialize_method = 'serialize'

            events = AuthEvent.objects.filter(q)
            aes = paginate(
                request, 
                events,
                serialize_method=serialize_method,
                elements_name='events'
            )
            data.update(aes)
        return json_response(data)

    @login_required
    def delete(request, pk):
        '''
            Delete a auth-event.
            delete_authevent permission required
        '''
        permission_required(request.user, 'AuthEvent', ['edit', 'delete'], pk)

        ae = AuthEvent.objects.get(pk=pk)
        ae.delete()

        data = {'status': 'ok'}
        return json_response(data)
authevent = AuthEventView.as_view()


class AuthEventModule(View):
    def get(self, request, name=None):
        '''
            Lists all existing modules if not pk. If pk show the module given.
        '''
        if name is None: # show all
            data = {'methods': []}
            for k in METHODS.keys():
                desc = METHODS.get(k).DESCRIPTION
                config = METHODS.get(k).CONFIG
                pipe = VALID_PIPELINES
                meta = VALID_FIELDS
                data['methods'].append(
                        [k, {
                                'description': desc,
                                'auth_method_config': config,
                                'pipelines': pipe,
                                'extra_fields': meta,
                            }]
                )
        elif name in METHODS.keys(): # show module
            desc = METHODS.get(name).DESCRIPTION
            config = METHODS.get(name).CONFIG
            pipe = VALID_PIPELINES
            meta = VALID_FIELDS
            data = {
                    name: {
                        'description': desc,
                        'auth_method_config': config,
                        'pipelines': pipe,
                        'extra_fields': meta,
                    }
            }
        return json_response(data)
authevent_module = AuthEventModule.as_view()


class UserView(View):
    def post(self, request):
        ''' Edit user. Only can change password. '''
        pk = request.user.pk
        user = request.user

        permission_required(user, 'UserData', 'edit', pk)
        permission_required(user, 'AuthEvent', 'create')

        try:
            req = parse_json_request(request)
        except:
            return json_response(
                status=400,
                error_codename=ErrorCodes.BAD_REQUEST)

        old_pwd = req.get('old_pwd', '')
        new_pwd = req.get('new_pwd', '')
        if not old_pwd or not new_pwd:
            return json_response(
                status=400,
                error_codename=ErrorCodes.BAD_REQUEST)

        if not user.check_password(old_pwd):
            return json_response(
                status=400,
                error_codename="INVALID_OLD_PASSWORD")

        user.set_password(new_pwd)
        user.save()
        data = {'status': 'ok'}
        return json_response(data)

    def get(self, request, pk=None):
        ''' Get user info '''
        userdata = None
        if pk is None:
            pk = request.user.pk
            userdata = request.user.userdata
        permission_required(request.user, 'UserData', 'edit', pk)
        if userdata is None:
            userdata = get_object_or_404(UserData, pk=pk)
        data = userdata.serialize()
        extend_info = plugins.call("extend_user_info", userdata.user)
        if extend_info:
            for info in extend_info:
                data.update(info.serialize())
        return json_response(data)
user = login_required(UserView.as_view())


class UserExtraView(View):
    def post(self, request):
        ''' Edit user. Only can change userdata's metadata. '''
        pk = request.user.pk
        user = request.user

        permission_required(user, 'UserData', 'edit', pk)
        permission_required(user, 'AuthEvent', 'create')

        try:
            new_metadata = parse_json_request(request)
        except:
            return json_response(
                status=400,
                error_codename=ErrorCodes.BAD_REQUEST)

        if not new_metadata:
            return json_response(
                status=400,
                error_codename=ErrorCodes.BAD_REQUEST)

        userdata = request.user.userdata
        if userdata is None:
            userdata = get_object_or_404(UserData, pk=pk)

        aeid = settings.ADMIN_AUTH_ID
        ae = AuthEvent.objects.get(pk=aeid)
        aes = ae.serialize_restrict()

        editable = set([
          f.get('name')
          for f in aes.get('extra_fields', [])
          if f.get('user_editable', False)
        ])

        for key, value in new_metadata.items():
            if key not in editable:
                return json_response(
                    status=400,
                    error_codename=ErrorCodes.BAD_REQUEST)
            userdata.metadata[key] = value

        userdata.save()
        data = {'status': 'ok'}
        return json_response(data)

    def get(self, request):
        ''' Get user info '''
        pk = request.user.pk
        userdata = request.user.userdata
        permission_required(request.user, 'UserData', 'edit', pk)
        if userdata is None:
            userdata = get_object_or_404(UserData, pk=pk)
        data = userdata.serialize()
        metadata = userdata.serialize_metadata()
        data['metadata'] = metadata
        extend_info = plugins.call("extend_user_info", userdata.user)
        if extend_info:
            for info in extend_info:
                data.update(info.serialize())
        return json_response(data)
user_extra = login_required(UserExtraView.as_view())


class UserResetPwd(View):
    ''' Reset password. '''
    def post(self, request):
        pk = request.user.pk
        user = request.user

        permission_required(user, 'UserData', 'edit', pk)
        permission_required(user, 'AuthEvent', 'create')

        new_pwd = random_code(8)
        send_mail.apply_async(args=[
                'Reset password',
                'This is your new password: %s' % new_pwd,
                user.email])
        user.set_password(new_pwd)
        user.save()
        data = {'status': 'ok'}
        return json_response(data)
reset_pwd = login_required(UserResetPwd.as_view())


class UserAuthEvent(View):
    def get(self, request):
        ''' Get ids auth-event of request user. '''
        acls = ACL.objects.filter(user=request.user.pk, object_type='AuthEvent',
                perm='edit')
        ae_ids = []
        for acl in acls:
            ae_ids.append(acl.object_id)
        data = {'ids-auth-event': ae_ids}
        return json_response(data)
user_auth_event = login_required(UserAuthEvent.as_view())


class CensusSendAuth(View):
    def post(self, request, pk):
        ''' Send authentication emails to the whole census '''
        permission_required(request.user, 'AuthEvent', ['edit', 'send-auth'], pk)

        data = {'msg': 'Sent successful'}
        # first, validate input
        e = get_object_or_404(AuthEvent, pk=pk)

        try:
            req = parse_json_request(request)
        except:
            return json_response(status=400, error_codename=ErrorCodes.BAD_REQUEST)

        userids = req.get("user-ids", None)
        if userids is None:
            permission_required(request.user, 'AuthEvent', ['edit', 'send-auth-all'], pk)
        extra_req = req.get('extra', {})
        auth_method = req.get("auth-method", None)
        # force extra_req type to be a dict
        if not isinstance(extra_req, dict):
            return json_response(
                status=400,
                error_codename=ErrorCodes.BAD_REQUEST)

        # check if send code method is authorized
        disable_auth_method = False
        extend_info = plugins.call("extend_disable_auth_method", auth_method, pk)
        if extend_info:
            for info in extend_info:
                 disable_auth_method = info
        if disable_auth_method:
            return json_response(
                status=400,
                error_codename=ErrorCodes.BAD_REQUEST)

        if req.get('msg', '') or req.get('subject', ''):
            config = {}
            if req.get('msg', ''):
                config['msg'] = req.get('msg', '')
            if req.get('subject', ''):
                config['subject'] = req.get('subject', '')
        else:
            send_error = census_send_auth_task(
                pk,
                get_client_ip(request),
                None,
                userids,
                auth_method,
                request.user.id,
                **extra_req)
            if send_error:
                return json_response(**send_error)
            return json_response(data)

        if config.get('msg', None) is not None:
            if type(config.get('msg', '')) != str or len(config.get('msg', '')) > settings.MAX_AUTH_MSG_SIZE[e.auth_method]:
                return json_response(
                    status=400,
                    error_codename=ErrorCodes.BAD_REQUEST)

        send_error = census_send_auth_task(
            pk,
            get_client_ip(request),
            config, userids,
            auth_method,
            request.user.id,
            **extra_req)
        if send_error:
            return json_response(**send_error)
        return json_response(data)
census_send_auth = login_required(CensusSendAuth.as_view())


class CensusResetVoter(View):
    def post(self, request, pk):
        '''
        Reset a voter's registration fields to a pre-registration state. Can
        only be executed for voters who did not vote.
        '''
        permission_required(
            request.user,
            'AuthEvent',
            ['edit', 'reset-voter'],
            pk
        )

        data = dict(status='ok')
        
        # first, validate input
        auth_event = get_object_or_404(AuthEvent, pk=pk)
        try:
            req = parse_json_request(request)
        except:
            return json_response(
                status=400,
                error_codename=ErrorCodes.BAD_REQUEST
            )
        # check data format
        user_ids = req.get("user-ids", None)
        comment = req.get('comment', None)
        try:
          check_contract(CONTRACTS['list_of_ints'], user_ids)
          if comment is not None:
              assert(isinstance(comment, str))
              assert(len(comment) <= 255)
        except:
            return json_response(
                status=400,
                error_codename=ErrorCodes.BAD_REQUEST)

        # get voters
        users = [
            get_object_or_404(
                User,
                pk=user_id, 
                userdata__event=auth_event
            )
            for user_id in user_ids
        ]
        # check voter didn't vote
        for user in users:
            if len(
                user.userdata.serialize_children_voted_elections(auth_event)
            ) > 0:
                return json_response(
                    status=400,
                    error_codename=ErrorCodes.BAD_REQUEST
                )
        # all checks passed: let's reset the voters

        from authmethods.utils import get_trimmed_user

        for user in users:
            trimmed_user_before = get_trimmed_user(user, auth_event)
            reset_voter_to_preregistration(user)
            action = Action(
                executer=request.user,
                receiver=user,
                action_name='user:reset-voter',
                event=auth_event,
                metadata={
                    "trimmed_user_before": trimmed_user_before,
                    "trimmed_user_after": get_trimmed_user(user, auth_event),
                    "comment": comment
                }
            )
            action.save()

        return json_response(data)

census_reset_voter = login_required(CensusResetVoter.as_view())

class GetImage(View):
    def get(self, request, pk, uid):
        permission_required(request.user, 'AuthEvent', 'edit', pk)
        ae = get_object_or_404(AuthEvent, pk=pk)
        u = get_object_or_404(UserData, event__pk=pk, user__username=uid)

        fname = u.user.username
        path = os.path.join(settings.IMAGE_STORE_PATH, fname)
        data = {'img': open(path).read()}
        return json_response(data)
get_img = login_required(GetImage.as_view())

class Legal(View):
    def get(self, request, pk = None):
        data = {}
        extended = plugins.call("extend_get_legal", pk)
        if len(extended) > 0:
            data  = extended[0]
        return json_response(data)
legal = Legal.as_view()


class Draft(View):
    def get(self, request):
        user = request.user
        userdata = request.user.userdata
        authevent_pk = userdata.event.pk

        if settings.ADMIN_AUTH_ID != authevent_pk:
            return json_response(
                status=400,
                error_codename=ErrorCodes.BAD_REQUEST)

        pk = user.pk
        permission_required(user, 'UserData', 'edit', pk)

        draft_election = userdata.serialize_draft()
        return json_response(draft_election)

    def post(self, request):
        try:
            req = parse_json_request(request)
        except:
            return json_response(
                status=400,
                error_codename=ErrorCodes.BAD_REQUEST)

        user = request.user
        userdata = request.user.userdata
        authevent_pk = userdata.event.pk

        if settings.ADMIN_AUTH_ID != authevent_pk:
            return json_response(
                status=400,
                error_codename=ErrorCodes.BAD_REQUEST)
        pk = user.pk

        permission_required(user, 'UserData', 'edit', pk)

        draft_election = req.get('draft_election', False)
        if False == draft_election:
            return json_response(
                status=400,
                error_codename=ErrorCodes.BAD_REQUEST)

        userdata.draft_election = draft_election
        userdata.save()

        data = {'status': 'ok'}
        return json_response(data)
draft = login_required(Draft.as_view())

class Deregister(View):
    def post(self, request):
        try:
            if True != settings.ALLOW_DEREGISTER:
                return json_response(
                    status=400,
                    error_codename=ErrorCodes.BAD_REQUEST)
            req = parse_json_request(request)
        except:
            return json_response(
                status=400,
                error_codename=ErrorCodes.BAD_REQUEST)

        user = request.user
        userdata = request.user.userdata
        authevent_pk = userdata.event.pk

        if settings.ADMIN_AUTH_ID != authevent_pk:
            return json_response(
                status=400,
                error_codename=ErrorCodes.BAD_REQUEST)
        pk = user.pk

        permission_required(user, 'UserData', 'edit', pk)
        user.is_active = False
        user.save()

        LOGGER.debug(\
          "Deregister user %r\n",\
          userdata.serialize() )

        data = {'status': 'ok'}
        return json_response(data)

deregister = login_required(Deregister.as_view())



class NewBallotBoxForm(forms.Form):
    name = forms.CharField(max_length=255)

class BallotBoxView(View):
    '''
    Manages ballot boxes related to an election
    '''

    def post(self, request, pk):
        permission_required(request.user, 'AuthEvent', ['edit', 'add-ballot-boxes'], pk)

        # parse input
        try:
            req = parse_json_request(request)
        except:
            return json_response(
                status=400,
                error_codename=ErrorCodes.BAD_REQUEST)

        # validate event exists and get it
        auth_event = get_object_or_404(AuthEvent, pk=pk)

        # validate input
        new_ballot_box = NewBallotBoxForm(req)
        if not new_ballot_box.is_valid() or not auth_event.has_ballot_boxes:
            return json_response(
                status=400,
                error_codename=ErrorCodes.BAD_REQUEST)


        # try to create new object in the db. might fail if bb already exists
        try:
            ballot_box_obj = BallotBox(name=req['name'], auth_event=auth_event)
            ballot_box_obj.save()

            action = Action(
                executer=request.user,
                receiver=None,
                action_name="ballot-box:create",
                event=auth_event,
                metadata=dict(
                    ballot_box_id=ballot_box_obj.id,
                    ballot_box_name=ballot_box_obj.name)
            )
            action.save()

        except Exception as e:
            return json_response(
                status=400,
                error_codename=ErrorCodes.BAD_REQUEST)

        # success!
        data = {'status': 'ok', 'id': ballot_box_obj.pk}
        return json_response(data)

    def get(self, request, pk):
        permission_required(request.user, 'AuthEvent', ['edit', 'list-ballot-boxes'], pk)
        e = get_object_or_404(AuthEvent, pk=pk)

        if e.children_election_info:
            parents2 = e.children_election_info['natural_order']
        else:
            parents2 = []

        filter_str = request.GET.get('filter', None)
        subq = TallySheet.objects\
            .filter(ballot_box=OuterRef('pk'))\
            .order_by('-created', '-id')
        query = BallotBox.objects\
            .filter(
                Q(auth_event_id=pk) |
                Q(auth_event__parent_id=pk) |
                Q(auth_event__parent_id__in=parents2)
            )\
            .annotate(
                last_updated=Subquery(subq.values('created')[:1]),
                creator_id=Subquery(subq.values('creator_id')[:1]),
                creator_username=Subquery(subq.values('creator__username')[:1]),
                num_tally_sheets=Count('tally_sheets')
            )
        
        if filter_str:
            query = query.filter(name__icontains=filter_str)

        query = filter_query(
            filters=request.GET,
            query=query,
            constraints=dict(
                filters={
                    "id": dict(
                        lt=int,
                        gt=int,
                        equals=int
                    ),
                    "last_updated": dict(
                        lt=datetime,
                        gt=datetime,
                        equals=datetime
                    ),
                    "num_tally_sheets": dict(
                        lt=int,
                        gt=int,
                        equals=int
                    ),
                    "name": {
                        "lt": int,
                        "gt": int,
                        "equals": int,
                        "in": "StringList"
                    }
                },
                order_by=['name', 'created', 'last_updated', 'num_tally_sheets'],
                default_ordery_by='name'
            ),
            prefix='ballotbox__',
            contraints_policy='ignore_invalid'
        )

        def serializer(obj):
          tally_sheet = obj.tally_sheets.order_by('-created').first()
          return {
            "id": obj.pk,
            "event_id": obj.auth_event.pk,
            "name": obj.name,
            "created": obj.created.isoformat(),
            "last_updated": obj.last_updated.isoformat() if obj.last_updated else None,
            "creator_id": obj.creator_id,
            "creator_username": obj.creator_username,
            "num_tally_sheets": obj.tally_sheets.count()
          }

        objs = paginate(
          request,
          query,
          serialize_method=serializer,
          elements_name='object_list')
        return json_response(objs)

    def delete(self, request, pk, ballot_box_pk):
        permission_required(request.user, 'AuthEvent', ['edit', 'delete-ballot-boxes'], pk)

        ballot_box_obj = get_object_or_404(
            BallotBox,
            pk=ballot_box_pk,
            auth_event__pk=pk
        )

        action = Action(
            executer=request.user,
            receiver=None,
            action_name="ballot-box:delete",
            event=ballot_box_obj.auth_event,
            metadata=dict(
                ballot_box_id=ballot_box_obj.id,
                ballot_box_name=ballot_box_obj.name
            )
        )

        action.save()
        ballot_box_obj.delete()

        data = {'status': 'ok'}
        return json_response(data)

ballot_box = login_required(BallotBoxView.as_view())


class TallySheetView(View):
    '''
    Registers and lists tally sheets
    '''

    def post(self, request, pk, ballot_box_pk):
        permission_required(
            request.user, 
            'AuthEvent', 
            ['edit', 'add-tally-sheets'], 
            pk
        )

        # parse input
        try:
            req = parse_json_request(request)
        except:
            return json_response(
                status=400,
                error_codename=ErrorCodes.BAD_REQUEST)

        # validate event exists and get it
        ballot_box_obj = get_object_or_404(
            BallotBox,
            pk=ballot_box_pk,
            auth_event__pk=pk,
            auth_event__status="stopped"
        )

        # require extra permissions to override tally sheet
        num_versions = ballot_box_obj.tally_sheets.count()
        if num_versions > 0:
            permission_required(
                request.user, 
                'AuthEvent', 
                ['edit', 'override-tally-sheets'], 
                pk
            )

        # validate input
        try:
            check_contract(CONTRACTS['tally_sheet'], req)
        except CheckException as error:
            LOGGER.error(\
                "TallySheetView.post\n"\
                "req '%r'\n"\
                "error '%r'\n"\
                "Stack trace: \n%s",\
                req, error, stack_trace_str())
            return json_response(
                status=400,
                error_codename=ErrorCodes.BAD_REQUEST
            )

        # try to create new object in the db
        try:
            tally_sheet_obj = TallySheet(
                ballot_box=ballot_box_obj,
                data=req,
                creator=request.user)
            tally_sheet_obj.save()

            auth_event = ballot_box_obj.auth_event
            if auth_event.parent is None:
                parent_auth_event = auth_event
            else:
                parent_auth_event = auth_event.parent

            action = Action(
                executer=request.user,
                receiver=None,
                action_name="tally-sheet:create",
                event=parent_auth_event,
                metadata=dict(
                    ballot_box_id=ballot_box_obj.id,
                    ballot_box_name=ballot_box_obj.name,
                    num_versions=num_versions,
                    comment=tally_sheet_obj.data['observations'],
                    tally_sheet_id=tally_sheet_obj.id,
                    data=req
                )
            )
            action.save()

        except Exception as e:
            return json_response(
                status=400,
                error_codename=ErrorCodes.BAD_REQUEST
            )

        # send update to agora-elections asynchronously
        update_ballot_boxes_config.apply_async(args=[pk])

        # success!
        data = {'status': 'ok', 'id': tally_sheet_obj.pk}
        return json_response(data)

    def get(self, request, pk, ballot_box_pk, tally_sheet_pk=None):
        permission_required(request.user, 'AuthEvent', ['edit', 'list-tally-sheets'], pk)

        if tally_sheet_pk is None:
            # try to get last tally sheet of the related ballot box, if any
            ballot_box_obj = get_object_or_404(
              BallotBox,
              pk=ballot_box_pk,
              auth_event__pk=pk
            )
            try:
                tally_sheet_obj = ballot_box_obj.tally_sheets.order_by('-created')[0]
            except IndexError:
                return json_response(status=404)
        else:
          # get the tally sheet
          tally_sheet_obj = get_object_or_404(
              TallySheet,
              pk=tally_sheet_pk,
              ballot_box__pk=ballot_box_pk,
              ballot_box__auth_event__pk=pk
          )

        return json_response(dict(
            id=tally_sheet_obj.id,
            created=tally_sheet_obj.created.isoformat(),
            creator_id=tally_sheet_obj.creator.id,
            creator_username=tally_sheet_obj.creator.username,
            ballot_box_id=tally_sheet_obj.ballot_box.id,
            data=tally_sheet_obj.data,
        ))

    def delete(self, request, pk, ballot_box_pk, tally_sheet_pk):
        permission_required(request.user, 'AuthEvent', ['edit', 'delete-tally-sheets'], pk)

        # get the tally sheet
        tally_sheet_obj = get_object_or_404(
            TallySheet,
            pk=tally_sheet_pk,
            ballot_box__pk=ballot_box_pk,
            ballot_box__auth_event__pk=pk
        )

        auth_event = tally_sheet_obj.ballot_box.auth_event
        if auth_event.parent is None:
            parent_auth_event = auth_event
        else:
            parent_auth_event = auth_event.parent

        action = Action(
            executer=request.user,
            receiver=None,
            action_name="tally-sheet:delete",
            event=parent_auth_event,
            metadata=dict(
                id=tally_sheet_obj.id,
                created=tally_sheet_obj.created.isoformat(),
                ballot_box_id=tally_sheet_obj.ballot_box.id,
                ballot_box_name=tally_sheet_obj.ballot_box.name,
                data=tally_sheet_obj.data,
                creator_id=tally_sheet_obj.creator.id,
                creator_username=tally_sheet_obj.creator.username
            )
        )

        action.save()
        tally_sheet_obj.delete()

        # send update to agora-elections asynchronously
        update_ballot_boxes_config.apply_async(args=[pk])

        data = {'status': 'ok'}
        return json_response(data)

tally_sheet = login_required(TallySheetView.as_view())


class TallyStatusView(View):

    def post(self, request, pk):
        '''
        Launches the tallly in a celery background task. If the
        election has children, also launches the tally for them.
        '''
        # check permissions
        permission_required(
            request.user, 
            'AuthEvent', 
            ['edit', 'tally'], 
            pk
        )

        # get AuthEvent and parse request json
        auth_event = get_object_or_404(AuthEvent, pk=pk)
        req = parse_json_request(request)

        # cannot launch tally on an election whose voting period is still open
        # or has not even started.
        if auth_event.status != 'stopped':
            return json_response(
                status=400,
                error_codename=ErrorCodes.BAD_REQUEST
            )

        # Stablishes the tally force type. It can be eith:
        # - 'do-not-force': only initiates the tally for an election if it
        #   didn't start.
        # - 'force-untallied': starts again the tally of any pending or
        #   untallied  election.
        # - 'force-all': starts again the tally of all the elections, even 
        #   those already tallied.
        force_tally = req.get('force_tally', 'do-not-force')
        if force_tally not in ['do-not-force', 'force-untallied', 'force-all']:
            return json_response(
                status=400,
                error_codename=ErrorCodes.BAD_REQUEST
            )
        
        # allows to launch only the tally of specific children elections
        # when an election is a parent election
        children_election_ids = req.get('children_election_ids', None)
        if children_election_ids is not None:
            if (
                type(children_election_ids) != list or
                (
                    len(children_election_ids) > 0 and
                    auth_event.children_election_info is None
                )
            ):
                return json_response(
                    status=400,
                    error_codename=ErrorCodes.BAD_REQUEST
                )
            for election_id in children_election_ids:
                if (
                    type(election_id) != int or
                    election_id not in auth_event.children_election_info['natural_order']
                ):
                    return json_response(
                        status=400,
                        error_codename=ErrorCodes.BAD_REQUEST
                    )
        
        # list with all the elections to be tallied. Parent elections
        # are also tallied, although as virtual
        if auth_event.children_election_info is None:
            auth_events = [auth_event]
        else:
            auth_events = [
                get_object_or_404(AuthEvent, pk=election_id)
                for election_id in auth_event.children_election_info['natural_order']
                if (
                    election_id in children_election_ids or
                    children_election_ids is None
                )
            ] + [auth_event]
        
        # set the pending status accordingly
        for auth_event_to_tally in auth_events:
            if (
                auth_event_to_tally.tally_status == 'notstarted' or
                (
                    auth_event_to_tally.tally_status == 'pending' and
                    force_tally in ['force-untallied', 'force-all']
                ) or (
                    auth_event_to_tally.tally_status in ['started', 'success'] and
                    force_tally in ['force-all']
                )
            ):
                # set tally status to pending
                previous_tally_status = auth_event_to_tally.tally_status
                auth_event_to_tally.tally_status = 'pending'
                auth_event_to_tally.save()

                # log the action
                action = Action(
                    executer=request.user,
                    receiver=None,
                    action_name='authevent:tally',
                    event=auth_event,
                    metadata=dict(
                        auth_event=auth_event_to_tally.pk,
                        previous_tally_status=previous_tally_status,
                        force_tally=force_tally,
                        forced=(previous_tally_status != 'notstarted')
                    )
                )
                action.save()

        # we don't launch the tally here, it will be catched by
        # celery task
        return json_response()

    def get(self, request, pk):
        '''
        Returns the tally status of an election and its children
        '''
        permission_required(
            request.user, 
            'AuthEvent', 
            ['edit', 'view-stats'], 
            pk
        )
        auth_event = get_object_or_404(AuthEvent, pk=pk)
        if election.children_election_info is not None:
            children_election_info = [
                dict(
                    election_id=election_id,
                    tally_status=AuthEvent.objects\
                        .get(pk=election_id)\
                        .tally_status
                )
                for election_id in election.children_election_info
            ]
        else:
            children_election_info = None

        data = dict(
            auth_event_id=auth_event.id,
            tally_status=auth_event.tally_status,
            children_election_info=children_election_info
        )
        return json_response(data)

tally_status = login_required(TallyStatusView.as_view())


class CalculateResultsView(View):

    def post(self, request, pk):
        '''
        Launches the results calculation in a celery background task. 
        If the election has parents and children, also launches the results 
        calculation there.
        '''
        # check permissions
        permission_required(
            request.user, 
            'AuthEvent', 
            ['edit', 'calculate-results'], 
            pk
        )

        # calculate this and parent elections
        auth_event = get_object_or_404(AuthEvent, pk=pk)
        event_id_list = []
        config = request.body.decode('utf-8')

        def append_children(auth_event, event_id_list, config):
            '''
            It appends first the leaves in the tree, then its parents
            '''
            if auth_event.children_election_info is not None:
                for child_id in auth_event.children_election_info['natural_order']:
                    child_obj = AuthEvent.objects.get(pk=child_id)
                    
                    # config is only for current auth_event, set to None for
                    # the others so that we don't change other's config
                    append_children(child_obj, event_id_list, None)

            event_id_list.append({"id": auth_event.id, "config": config})

        def append_parents(auth_event, event_id_list):
            '''
            Append to the list the parents recursively
            '''
            if auth_event.parent:
                event_id_list.append({"id": auth_event.parent.id, "config": None})
                append_parents(auth_event.parent, event_id_list)

        append_children(auth_event, event_id_list, config)
        append_parents(auth_event, event_id_list)

        calculate_results_task.apply_async(
            args=[
                request.user.id,
                event_id_list
            ]
        )

        return json_response()
calculate_results = login_required(CalculateResultsView.as_view())


class PublishResultsView(View):

    def post(self, request, pk):
        '''
        Launches the results publication in a celery background task. 
        If the election has children, also launches the results 
        publication there.
        '''
        # check permissions
        permission_required(
            request.user, 
            'AuthEvent', 
            ['edit', 'publish-results'], 
            pk
        )
        
        # publish this and children elections
        auth_event = get_object_or_404(AuthEvent, pk=pk)
        publish_results_task.apply_async(
            args=[
                request.user.id,
                auth_event.id,
                True # visit_children
            ]
        )

        if auth_event.parent:
            publish_results_task.apply_async(
                args=[
                    request.user.id,
                    auth_event.parent.id,
                    False # visit_children
                ]
            )
            if auth_event.parent.parent:
                publish_results_task.apply_async(
                    args=[
                        request.user.id,
                        auth_event.parent.parent.id,
                        False # visit_children
                    ]
                )

        return json_response()
publish_results = login_required(PublishResultsView.as_view())


class UnpublishResultsView(View):

    def post(self, request, pk):
        '''
        Launches the results depublication in a celery background task. 
        If the election has children, also launches the results 
        depublication there.
        '''
        # check permissions
        permission_required(
            request.user, 
            'AuthEvent', 
            ['edit', 'publish-results'], 
            pk
        )
        
        # unpublish this and children elections
        auth_event = get_object_or_404(AuthEvent, pk=pk)
        unpublish_results_task.apply_async(
            args=[
                request.user.id,
                auth_event.id
            ]
        )

        return json_response()
unpublish_results = login_required(UnpublishResultsView.as_view())


class AllowTallyView(View):

    def post(self, request, pk):
        '''
        Launches the results publication in a celery background task. 
        If the election has children, also launches the results 
        publication there.
        '''
        # check permissions
        permission_required(
            request.user, 
            'AuthEvent', 
            ['edit', 'allow-tally'], 
            pk
        )
        
        # allow tally of this and children elections
        auth_event = get_object_or_404(AuthEvent, pk=pk)
        allow_tally_task.apply_async(
            args=[
                request.user.id,
                auth_event.id
            ]
        )

        return json_response()
allow_tally = login_required(AllowTallyView.as_view())
