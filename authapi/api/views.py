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

# This file contains all the API views
import os
import json
import mimetypes
from datetime import datetime
from django.conf import settings
from django.contrib.auth.models import User
from django.views.generic import View
from django.shortcuts import get_object_or_404
from django.http import HttpResponse
from base64 import encodestring

import plugins
from authmethods import (
    auth_authenticate,
    auth_census,
    auth_register,
    auth_resend_auth_code,
    check_config,
    METHODS,
)
from utils import (
    check_authmethod,
    check_extra_fields,
    check_pipeline,
    genhmac,
    json_response,
    paginate,
    permission_required,
    random_code,
    send_mail,
    ErrorCodes,
    VALID_FIELDS,
    VALID_PIPELINES,
    filter_query
)
from .decorators import login_required, get_login_user
from .models import AuthEvent, ACL
from .models import User, UserData
from .tasks import census_send_auth_task
from django.db.models import Q
from captcha.views import generate_captcha
from utils import send_codes, get_client_ip, parse_json_request

# import fields checks
from pipelines.field_register import *
from pipelines.field_authenticate import *
from contracts.base import check_contract

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
    ])

class CensusDelete(View):
    '''
    Delete census in the auth-event
    '''
    def post(self, request, pk):
        permission_required(request.user, 'AuthEvent', 'edit', pk)
        ae = get_object_or_404(AuthEvent, pk=pk)
        req = parse_json_request(request)
        user_ids = req.get('user-ids', [])
        check_contract(CONTRACTS['list_of_ints'], user_ids)

        for uid in user_ids:
            u = get_object_or_404(User, pk=uid, userdata__event=ae)
            for acl in u.userdata.acls.all():
                acl.delete()
            u.delete()
        return json_response()
census_delete = login_required(CensusDelete.as_view())


class CensusActivate(View):
    '''
    Activates an user in the auth-event census
    '''

    activate = True

    def post(self, request, pk):
        permission_required(request.user, 'AuthEvent', 'edit', pk)
        ae = get_object_or_404(AuthEvent, pk=pk)
        req = parse_json_request(request)
        user_ids = req.get('user-ids', [])
        check_contract(CONTRACTS['list_of_ints'], user_ids)

        for uid in user_ids:
            u = get_object_or_404(User, pk=uid, userdata__event=ae)
            u.is_active = self.activate
            u.save()
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
        permission_required(request.user, 'AuthEvent', 'edit', pk)
        e = get_object_or_404(AuthEvent, pk=pk)
        error_kwargs = plugins.call("extend_add_census", e, request)
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
        e = get_object_or_404(AuthEvent, pk=pk)

        filter_str = request.GET.get('filter', None)
        query = e.get_census_query()

        if filter_str is not None:
            q = (Q(user__user__username__icontains=filter_str) |
              Q(user__user__email__icontains=filter_str) |
              Q(user__tlf__icontains=filter_str) |
              Q(user__metadata__icontains=filter_str))

            query = query.filter(q)

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
                    'user__user__date_joined']
            ),
            prefix='census__',
            contraints_policy='ignore_invalid')

        def serializer(acl):
          return {
            "id": acl.user.user.pk,
            "username": acl.user.user.username,
            "active": acl.user.user.is_active,
            "date_joined": acl.user.user.date_joined.isoformat(),
            "metadata": acl.user.serialize_data()
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
        if int(pk) == 0:
            e = 0
        else:
            e = get_object_or_404(AuthEvent, pk=pk)

        if not hasattr(request.user, 'account'):
            error_kwargs = plugins.call("extend_auth", e)
            if error_kwargs:
                return json_response(**error_kwargs[0])
        try:
            data = auth_authenticate(e, request)
        except:
            return json_response(status=400, error_codename=ErrorCodes.BAD_REQUEST)

        if data and 'status' in data and data['status'] == 'ok':
            return json_response(data)
        else:
            return json_response(
              status=400,
              error_codename=data.get('error_codename'),
              message=data.get('msg', '-'))
authenticate = Authenticate.as_view()


class Ping(View):
    ''' Returns true if the user is authenticated, else returns false.
        If the user is authenticated a new authtoken is sent
    '''

    def get(self, request, pk):
        u, error = get_login_user(request)
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


class Register(View):
    ''' Register into the authapi '''

    def post(self, request, pk):
        e = get_object_or_404(AuthEvent, pk=pk)
        if (e.census == 'close'):
            return json_response(
                status=400,
                error_codename="REGISTER_IS_DISABLED")
        if e.census == 'open' and e.status != 'started': # register is closing
            return json_response(
                status=400,
                error_codename="AUTH_EVENT_NOT_STARTED")

        data = auth_register(e, request)
        if data['status'] == 'ok':
            return json_response(data)
        else:
            return json_response(
                status=400,
                error_codename=data.get('error_codename'))
register = Register.as_view()


class ResendAuthCode(View):
    ''' Register into the authapi '''

    def post(self, request, pk):
        e = get_object_or_404(AuthEvent, pk=pk)
        if (e.census == 'close'):
            return json_response(
                status=400,
                error_codename="AUTH_EVENT_NOT_STARTED")
        if e.census == 'open' and e.status != 'started': # register is closing
            return json_response(
                status=400,
                error_codename="AUTH_EVENT_NOT_STARTED")

        data = auth_resend_auth_code(e, request)
        if data['status'] == 'ok':
            return json_response(data)
        else:
            return json_response(
                status=400,
                message=data.get('msg', '-'),
                error_codename=data.get('error_codename'))
resend_auth_code = ResendAuthCode.as_view()


class AuthEventStatus(View):
    ''' Change the status of auth-event '''

    def post(self, request, pk, status):
        permission_required(request.user, 'AuthEvent', 'edit', pk)
        e = get_object_or_404(AuthEvent, pk=pk)
        if e.status != status:
            e.status = status
            e.save()
            st = 200
        else:
            st = 400
        return json_response(status=st, message='Authevent status:  %s' % status)
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
            permission_required(request.user, 'AuthEvent', 'create')

            auth_method = req.get('auth_method', '')
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

            census = req.get('census', '')
            # check census mode
            if not census in ('open', 'close'):
                return json_response(
                    status=400,
                    error_codename="INVALID_CENSUS_TYPE")
            error_kwargs = plugins.call("extend_type_census", census)
            if error_kwargs:
                return json_response(**error_kwargs[0])

            real = req.get('real', False)
            based_in = req.get('based_in', None)
            if based_in and not ACL.objects.filter(user=request.user.userdata, perm='edit',
                    object_type='AuthEvent', object_id=based_in):
                msg += "Invalid id to based_in"
            if msg:
                return json_response(
                    status=400,
                    message=msg,
                    error_codename=ErrorCodes.BAD_REQUEST)

            if config:
                auth_method_config.get('config').update(config)

            ae = AuthEvent(auth_method=auth_method,
                           auth_method_config=auth_method_config,
                           extra_fields=extra_fields,
                           census=census,
                           real=real,
                           based_in=based_in)
            # Save before the acl creation to get the ae id
            ae.save()
            acl = ACL(user=request.user.userdata, perm='edit', object_type='AuthEvent',
                      object_id=ae.id)
            acl.save()
            acl = ACL(user=request.user.userdata, perm='create',
                    object_type='UserData', object_id=ae.id)
            acl.save()

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

        data = {'status': 'ok', 'id': ae.pk, 'perm': acl.get_hmac()}
        return json_response(data)

    def get(self, request, pk=None):
        '''
            Lists all AuthEvents if not pk. If pk show the event with this pk
        '''
        data = {'status': 'ok'}
        user, _ = get_login_user(request)

        if pk:
            e = AuthEvent.objects.get(pk=pk)
            if (user is not None and user.is_authenticated() and
                permission_required(
                    user,
                    'AuthEvent',
                    ['edit', 'view'],
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
            events = AuthEvent.objects.all()
            aes = paginate(request, events,
                           serialize_method='serialize_restrict',
                           elements_name='events')
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
        if e.status != 'started':
            return json_response(
                status=400,
                error_codename="AUTH_EVENT_NOT_STARTED")

        try:
            req = parse_json_request(request)
        except:
            return json_response(status=400, error_codename=ErrorCodes.BAD_REQUEST)

        userids = req.get("user-ids", None)
        if userids is None:
            permission_required(request.user, 'AuthEvent', ['send-auth-all'], pk)
        extra_req = req.get('extra', {})
        auth_method = req.get("auth-method", None)
        # force extra_req type to be a dict
        if not isinstance(extra_req, dict):
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
