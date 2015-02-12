import json
from django.conf import settings
from django.contrib.auth.models import User
from django.core.exceptions import PermissionDenied
from django.http import HttpResponse, HttpResponseBadRequest
from django.views.generic import View
from django.shortcuts import get_object_or_404

from authmethods import auth_authenticate, METHODS, auth_register, auth_census, check_config
from utils import genhmac, paginate, VALID_FIELDS, VALID_PIPELINES
from utils import check_authmethod, check_pipeline, check_extra_fields
from .decorators import login_required, get_login_user
from .models import AuthEvent, ACL, CreditsAction
from .models import User, UserData
from .tasks import census_send_auth_task
from django.db.models import Q
from captcha.views import generate_captcha


def permission_required(user, object_type, permission, object_id=0):
    if user.is_superuser:
        return
    if object_id and user.userdata.has_perms(object_type, permission, 0):
        return
    if not user.userdata.has_perms(object_type, permission, object_id):
        raise PermissionDenied('Permission required: ' + permission)


class Test(View):
    ''' Test view that returns the response data '''

    def get(self, request):
        req = request.GET
        data = {'status': 'ok', 'method': 'GET'}
        data['get'] = req
        jsondata = json.dumps(data)
        return HttpResponse(jsondata, content_type='application/json')

    def post(self, request):
        try:
            req = json.loads(request.body.decode('utf-8'))
        except:
            bad_request = json.dumps({"error": "bad_request"})
            return HttpResponseBadRequest(bad_request, content_type='application/json')
        data = {'status': 'ok', 'method': 'POST'}
        data['post'] = req
        jsondata = json.dumps(data)
        return HttpResponse(jsondata, content_type='application/json')
test = Test.as_view()


class Census(View):
    ''' Add census in the auth-event '''

    def post(self, request, pk):
        e = get_object_or_404(AuthEvent, pk=pk)
        try:
            data = auth_census(e, request)
        except:
            bad_request = json.dumps({"error": "bad_request"})
            return HttpResponseBadRequest(bad_request, content_type='application/json')
        status = 200 if data['status'] == 'ok' else 400
        jsondata = json.dumps(data)
        return HttpResponse(jsondata, status=status, content_type='application/json')

    def get(self, request, pk):
        permission_required(request.user, 'AuthEvent', 'edit', pk)
        e = get_object_or_404(AuthEvent, pk=pk)
        acls = ACL.objects.filter(object_type='AuthEvent', perm='vote', object_id=pk)
        userids = []
        users = {}
        for acl in acls:
            userids.append(acl.user.pk)
            users[acl.user.user.username] = acl.user.user.email
        jsondata = json.dumps({'userids': userids, 'users': users})
        return HttpResponse(jsondata, content_type='application/json')
census = login_required(Census.as_view())


class UsedCensus(View):
    ''' Add used census in the auth-event. Users in this census won't able to
    vote. '''

    def post(self, request, pk):
        e = get_object_or_404(AuthEvent, pk=pk)
        try:
            data = auth_census(e, request, used=True)
        except:
            bad_request = json.dumps({"error": "bad_request"})
            return HttpResponseBadRequest(bad_request, content_type='application/json')
        status = 200 if data['status'] == 'ok' else 400
        jsondata = json.dumps(data)
        return HttpResponse(jsondata, status=status, content_type='application/json')
used_census = login_required(UsedCensus.as_view())


class Authenticate(View):
    ''' Authenticate into the authapi '''

    def post(self, request, pk):
        if int(pk) == 0:
            e = 0
        else:
            e = get_object_or_404(AuthEvent, pk=pk)

        try:
            data = auth_authenticate(e, request)
        except:
            return HttpResponseBadRequest("", content_type='application/json')

        status = 200 if data['status'] == 'ok' else 400
        jsondata = json.dumps(data)
        return HttpResponse(jsondata, status=status, content_type='application/json')
authenticate = Authenticate.as_view()


class Ping(View):
    ''' Returns true if the user is authenticated, else returns false.
        If the user is authenticated a new authtoken is sent
    '''

    def get(self, request, pk):
        u = get_login_user(request)
        data = {'status': 'ok', 'logged': False}

        if u:
            data['logged'] = True
            data['auth-token'] = genhmac(settings.SHARED_SECRET, u.username)
        status = 200 if data['status'] == 'ok' else 400
        jsondata = json.dumps(data)
        return HttpResponse(jsondata, status=status, content_type='application/json')
ping = Ping.as_view()


class Register(View):
    ''' Register into the authapi '''

    def post(self, request, pk):
        e = get_object_or_404(AuthEvent, pk=pk)
        if (e.census == 'close'):
            jsondata = json.dumps({
                "msg": "Register disable: the auth-event is close"
            })
            return HttpResponse(jsondata, status=400, content_type='application/json')
        if e.census == 'open' and e.status != 'started': # register is closing
            jsondata = json.dumps({
                "msg": "Register disable: the auth-event doesn't started"
            })
            return HttpResponse(jsondata, status=400, content_type='application/json')

        data = auth_register(e, request)
        status = 200 if data['status'] == 'ok' else 400
        jsondata = json.dumps(data)
        return HttpResponse(jsondata, status=status, content_type='application/json')
register = Register.as_view()


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
        jsondata = json.dumps({'msg': 'Authevent status:  %s' % status})
        return HttpResponse(jsondata, status=st, content_type='application/json')
ae_status = login_required(AuthEventStatus.as_view())


class GetPerms(View):
    ''' Returns the permission token if the user has this perm '''

    def post(self, request):
        data = {'status': 'ok'}

        try:
            req = json.loads(request.body.decode('utf-8'))
        except:
            bad_request = json.dumps({"error": "bad_request"})
            return HttpResponseBadRequest(bad_request, content_type='application/json')

        if 'permission' not in req or 'object_type' not in req:
            jsondata = json.dumps(data)
            return HttpResponse(jsondata, status=400, content_type='application/json')

        object_type = req['object_type']
        perm = req['permission']
        obj_id = req.get('object_id', 0)

        if not request.user.is_superuser and\
                not request.user.userdata.has_perms(object_type, perm, obj_id):
            jsondata = json.dumps(data)
            return HttpResponse(jsondata, status=400, content_type='application/json')

        msg = ':'.join((request.user.username, object_type, str(obj_id), perm))

        data['permission-token'] = genhmac(settings.SHARED_SECRET, msg)
        jsondata = json.dumps(data)
        return HttpResponse(jsondata, content_type='application/json')
getperms = login_required(GetPerms.as_view())


class ACLView(View):
    ''' Returns the permission token if the user has this perm '''

    def delete(self, request, username, object_type, perm, object_id=0):
        permission_required(request.user, 'ACL', 'delete')
        u = get_object_or_404(User, username=username)
        for acl in u.userdata.get_perms(object_type, perm, object_id):
            acl.delete()
        data = {'status': 'ok'}
        jsondata = json.dumps(data)
        return HttpResponse(jsondata, content_type='application/json')

    def get(self, request, username, object_type, perm, object_id=0):
        permission_required(request.user, 'ACL', 'view')
        data = {'status': 'ok'}
        u = get_object_or_404(User, username=username)
        if u.userdata.has_perms(object_type, perm, object_id):
            data['perm'] = True
        else:
            data['perm'] = False
        jsondata = json.dumps(data)
        return HttpResponse(jsondata, content_type='application/json')

    def post(self, request):
        permission_required(request.user, 'ACL', 'create')
        data = {'status': 'ok'}

        try:
            req = json.loads(request.body.decode('utf-8'))
        except:
            bad_request = json.dumps({"error": "bad_request"})
            return HttpResponseBadRequest(bad_request, content_type='application/json')
        u = User.objects.get(pk=req['userid'])
        for perm in req['perms']:
            user = get_object_or_404(UserData, user__username=perm['user'])
            acl = ACL(user=user, perm=perm['perm'], object_type=perm['object_type'],
                    object_id=perm.get('object_id', 0))
            acl.save()
        jsondata = json.dumps(data)
        return HttpResponse(jsondata, content_type='application/json')
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
            q &= Q(perm=perm)

        query = request.user.userdata.acls.filter(q)

        acls = paginate(request, query,
                       serialize_method='serialize',
                       elements_name='perms')
        data.update(acls)

        jsondata = json.dumps(data)
        return HttpResponse(jsondata, content_type='application/json')
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
            req = json.loads(request.body.decode('utf-8'))
        except:
            bad_request = json.dumps({"error": "bad_request"})
            return HttpResponseBadRequest(bad_request, content_type='application/json')

        if pk is None: # create
            permission_required(request.user, 'AuthEvent', 'create')

            auth_method = req.get('auth_method', '')
            msg = check_authmethod(auth_method)
            if msg:
                data = {'msg': msg}
                jsondata = json.dumps(data)
                return HttpResponse(jsondata, status=400, content_type='application/json')

            auth_method_config = {
                    "config": METHODS.get(auth_method).CONFIG,
                    "pipeline": METHODS.get(auth_method).PIPELINES
            }
            config = req.get('config', None)
            if config:
                msg += check_config(config, auth_method)

            extra_fields = req.get('extra_fields', None)
            if extra_fields:
                msg += check_extra_fields(extra_fields, METHODS.get(auth_method).USED_TYPE_FIELDS)

            census = req.get('census', '')
            if not census in ('open', 'close'):
                msg += "Invalid type of census\n"

            if msg:
                data = {'msg': msg}
                jsondata = json.dumps(data)
                return HttpResponse(jsondata, status=400, content_type='application/json')

            if config:
                auth_method_config.get('config').update(config)

            ae = AuthEvent(auth_method=auth_method,
                           auth_method_config=auth_method_config,
                           extra_fields=extra_fields,
                           census=census)
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
                data = {'msg': msg}
                jsondata = json.dumps(data)
                return HttpResponse(jsondata, status=400, content_type='application/json')

            config = req.get('auth_method_config', None)
            if config:
                msg += check_config(config, auth_method)

            extra_fields = req.get('extra_fields', None)
            if extra_fields:
                msg += check_extra_fields(extra_fields)

            if msg:
                data = {'msg': msg}
                jsondata = json.dumps(data)
                return HttpResponse(jsondata, status=400, content_type='application/json')

            ae = AuthEvent.objects.get(pk=pk)
            ae.auth_method = auth_method
            if config:
                ae.auth_method_config.get('auth_method_config').update(config)
            if extra_fields:
                ae.extra_fields = extra_fields
            ae.save()

            # TODO: Problem if object_id is None, change None by 0
            acl = get_object_or_404(ACL, user=request.user.userdata,
                    perm='edit', object_type='AuthEvent', object_id=ae.pk)

        data = {'status': 'ok', 'id': ae.pk, 'perm': acl.get_hmac()}
        jsondata = json.dumps(data)
        return HttpResponse(jsondata, content_type='application/json')

    def get(self, request, pk=None):
        '''
            Lists all AuthEvents if not pk. If pk show the event with this pk
        '''
        data = {'status': 'ok'}

        if pk:
            e = AuthEvent.objects.get(pk=pk)
            u = request.user
            if (u.is_authenticated() and
                u.userdata.has_perms("AuthEvent", "admin", e.id)):
                aes = e.serialize()
            else:
                aes = e.serialize_restrict()
            data['events'] = aes
        else:
            events = AuthEvent.objects.all()
            aes = paginate(request, events,
                           serialize_method='serialize_restrict',
                           elements_name='events')
            data.update(aes)

        jsondata = json.dumps(data)
        return HttpResponse(jsondata, content_type='application/json')

    @login_required
    def delete(request, pk):
        '''
            Delete a auth-event.
            delete_authevent permission required
        '''
        permission_required(request.user, 'AuthEvent', 'edit', pk)

        ae = AuthEvent.objects.get(pk=pk)
        ae.delete()

        data = {'status': 'ok'}
        jsondata = json.dumps(data)
        return HttpResponse(jsondata, content_type='application/json')
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

        jsondata = json.dumps(data)
        return HttpResponse(jsondata, content_type='application/json')
authevent_module = AuthEventModule.as_view()


class UserView(View):
    def get(self, request, pk):
        ''' Get user info '''
        permission_required(request.user, 'UserData', 'view', pk)
        user = get_object_or_404(UserData, pk=pk)
        jsondata = json.dumps(user.serialize())
        return HttpResponse(jsondata, content_type='application/json')
user = login_required(UserView.as_view())



class UserAuthEvent(View):
    def get(self, request):
        ''' Get ids auth-event of request user. '''
        acls = ACL.objects.filter(user=request.user.pk, object_type='AuthEvent',
                perm='edit')
        ae_ids = []
        for acl in acls:
            ae_ids.append(acl.object_id)
        jsondata = json.dumps({'ids-auth-event': ae_ids})
        return HttpResponse(jsondata, content_type='application/json')
user_auth_event = login_required(UserAuthEvent.as_view())


class CreditsActionView(View):
    def post(self, request):
        ''' Create new action of add_credit in mode create '''

        try:
            req = json.loads(request.body.decode('utf-8'))
        except:
            bad_request = json.dumps({"error": "bad_request"})
            return HttpResponseBadRequest(bad_request, content_type='application/json')
        pack_id = req.get("pack_id")
        quantity = req.get("num_credits")
        payment = req.get("payment_method")
        # TODO create paypal_url
        paypal_url = 'foo'
        action = CreditsAction(user=request.user.userdata, quantity=quantity,
                payment_metadata={'payment_method': payment})
        action.save()
        jsondata = json.dumps({'paypal_url': paypal_url})
        return HttpResponse(jsondata, content_type='application/json')
creditsaction = login_required(CreditsActionView.as_view())

class CensusSendAuth(View):
    def post(self, request, pk):
        ''' Send authentication emails to the whole census '''
        permission_required(request.user, 'AuthEvent', 'edit', pk)

        # first, validate input
        e = get_object_or_404(AuthEvent, pk=pk)
        if e.status != 'started':
          jsondata = json.dumps({'error': 'AuthEvent with id = %s has not started' % pk})
          return HttpResponseBadRequest(jsondata, content_type='application/json')

        invalid_json = json.dumps({'error': "Invalid json"})
        try:
            req = json.loads(request.body.decode('utf-8'))
        except:
            return HttpResponseBadRequest(invalid_json, content_type='application/json')

        userids = req.get("user-ids", None)
        if req.get('msg') or req.get('subject'):
            config = {}
            if req.get('msg'):
                config['msg'] = req.get('msg')
            if req.get('subject'):
                config['subject'] = req.get('subject')
        else:
            census_send_auth_task.apply_async(args=[pk, None, userids])
            return HttpResponse("", content_type='application/json')

        if config.get('msg', None) is not None:
            if type(config.get('msg')) != str or len(config.get('msg')) > settings.MAX_AUTH_MSG_SIZE[e.auth_method]:
                return HttpResponseBadRequest(invalid_json, content_type='application/json')

        census_send_auth_task.apply_async(args=[pk, config, userids])
        return HttpResponse("", content_type='application/json')
census_send_auth = login_required(CensusSendAuth.as_view())

def available_packs(request):
    jsondata = json.dumps(settings.AVAILABLE_PACKS)
    return HttpResponse(jsondata, content_type='application/json')


def available_payment_methods(request):
    jsondata = json.dumps(settings.AVAILABLE_PAYMENT_METHODS)
    return HttpResponse(jsondata, content_type='application/json')
