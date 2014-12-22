import json
from django.conf import settings
from django.contrib.auth.models import User
from django.core.exceptions import PermissionDenied
from django.http import HttpResponse
from django.views.generic import View
from django.shortcuts import get_object_or_404

from authmethods import auth_login
from utils import genhmac
from .decorators import login_required
from .models import AuthEvent, ACL
from .models import User, UserData
from django.db.models import Q


def permission_required(user, object_type, permission, object_id=None):
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
        req = json.loads(request.body.decode('utf-8'))
        data = {'status': 'ok', 'method': 'POST'}
        data['post'] = req
        jsondata = json.dumps(data)
        return HttpResponse(jsondata, content_type='application/json')
test = Test.as_view()


class Login(View):
    ''' Login into the authapi '''

    def post(self, request):
        req = json.loads(request.body.decode('utf-8'))
        m = req.get('auth-method', 'user-and-password')
        d = req.get('auth-data', '{}')
        data = auth_login(m, d)
        status = 200 if data['status'] == 'ok' else 400
        jsondata = json.dumps(data)
        return HttpResponse(jsondata, status=status, content_type='application/json')
login = Login.as_view()


class GetPerms(View):
    ''' Returns the permission token if the user has this perm '''

    def post(self, request):
        data = {'status': 'ok'}
        req = json.loads(request.body.decode('utf-8'))

        if 'permission' not in req or 'object_type' not in req:
            jsondata = json.dumps(data)
            return HttpResponse(jsondata, status=400, content_type='application/json')

        object_type = req['object_type']
        perm = req['permission']
        obj_id = req.get('object_id', None)

        if not request.user.userdata.has_perms(object_type, perm, obj_id):
            jsondata = json.dumps(data)
            return HttpResponse(jsondata, status=400, content_type='application/json')

        if not obj_id:
            msg = ':'.join((request.user.username, object_type, perm))
        else:
            msg = ':'.join((request.user.username, object_type, obj_id, perm))

        data['permission-token'] = genhmac(settings.SHARED_SECRET, msg)
        jsondata = json.dumps(data)
        return HttpResponse(jsondata, content_type='application/json')
getperms = login_required(GetPerms.as_view())


class ACLView(View):
    ''' Returns the permission token if the user has this perm '''

    def delete(self, request, username, object_type, perm, object_id=None):
        permission_required(request.user, 'ACL', 'delete')
        u = get_object_or_404(User, username=username)
        for acl in u.userdata.get_perms(object_type, perm, object_id):
            acl.delete()
        data = {'status': 'ok'}
        jsondata = json.dumps(data)
        return HttpResponse(jsondata, content_type='application/json')

    def get(self, request, username, object_type, perm, object_id=None):
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
        req = json.loads(request.body.decode('utf-8'))
        u = User.objects.get(pk=req['userid'])
        for perm in req['perms']:
            user = get_object_or_404(UserData, user__username=perm['user'])
            acl = ACL(user=user, perm=perm['perm'], object_type=perm['object_type'])
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

        for p in request.user.userdata.acls.filter(q):
            data['perms'].append(p.serialize())
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
        req = json.loads(request.body.decode('utf-8'))
        if pk is None: # create
            permission_required(request.user, 'AuthEvent', 'create')
            ae = AuthEvent(name=req['name'],
                           auth_method=req['auth_method'],
                           auth_method_config=req['auth_method_config'],
                           metadata=req)
        else: # edit
            permission_required(request.user, 'AuthEvent', 'edit')
            ae = AuthEvent.objects.get(pk=pk)
            ae.name = req['name']
            ae.auth_method = req['auth_method']
            ae.auth_method_config = req['auth_method_config']
            ae.metadata = req
        ae.save()

        data = {'status': 'ok', 'id': ae.pk}
        jsondata = json.dumps(data)
        return HttpResponse(jsondata, content_type='application/json')

    def get(self, request, pk=None):
        '''
            Lists all AuthEvents if not pk. If pk show the event with this pk
        '''
        # TODO paginate and filter with GET params
        if pk:
            e = AuthEvent.objects.get(pk=pk)
            aes = e.serialize_restrict()
        else:
            events = AuthEvent.objects.all()
            aes = []
            for e in events:
                aes.append(e.serialize_restrict())

        data = {'status': 'ok', 'events': aes}
        jsondata = json.dumps(data)
        return HttpResponse(jsondata, content_type='application/json')

    @login_required
    def delete(request, pk):
        '''
            Delete a auth-event.
            delete_authevent permission required
        '''
        permission_required(request.user, 'AuthEvent', 'delete')

        ae = AuthEvent.objects.get(pk=pk)
        ae.delete()

        data = {'status': 'ok'}
        jsondata = json.dumps(data)
        return HttpResponse(jsondata, content_type='application/json')
authevent = AuthEventView.as_view()
