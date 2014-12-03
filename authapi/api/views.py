import json
from django.conf import settings
from django.contrib.auth.models import User
from django.core.exceptions import PermissionDenied
from django.http import HttpResponse
from django.views.generic import View

from authmethods import auth_login
from utils import genhmac
from .decorators import login_required
from .models import AuthEvent, ACL


def permission_required(user, permission):
    if not user.userdata.has_perms(permission):
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
        jsondata = json.dumps(data)
        return HttpResponse(jsondata, content_type='application/json')
login = Login.as_view()


class GetPerms(View):
    ''' Returns the permission token if the user has this perm '''

    def post(self, request):
        data = {'status': 'ok'}
        req = json.loads(request.body.decode('utf-8'))

        if not 'permission' in req:
            data = {'status': 'nok'}
            jsondata = json.dumps(data)
            return HttpResponse(jsondata, content_type='application/json')

        p = req['permission']
        d = req.get('permission_data', '')

        if not request.user.userdata.has_perms(p):
            data = {'status': 'nok'}
            jsondata = json.dumps(data)
            return HttpResponse(jsondata, content_type='application/json')

        if d:
            msg = '%s:%s:%s' % (request.user.username, p, d)
        else:
            msg = '%s:%s' % (request.user.username, p)

        data['permission-token'] = genhmac(settings.SHARED_SECRET, msg)
        jsondata = json.dumps(data)
        return HttpResponse(jsondata, content_type='application/json')
getperms = login_required(GetPerms.as_view())


class ACLView(View):
    ''' Returns the permission token if the user has this perm '''

    def delete(self, request):
        permission_required(request.user, 'delete_acl')
        req = json.loads(request.body.decode('utf-8'))
        u = User.objects.get(pk=req['userid'])
        for acl in ACL.objects.filter(user=u.userdata, perm=['perm']):
            acl.delete()
        data = {'status': 'ok'}
        jsondata = json.dumps(data)
        return HttpResponse(jsondata, content_type='application/json')

    def get(self, request, userid, perm):
        permission_required(request.user, 'view_acl')
        data = {'status': 'ok'}
        if ACL.objects.filter(user=userid, perm=perm).count() > 0:
            data['perm'] = True
        else:
            data['perm'] = False
        jsondata = json.dumps(data)
        return HttpResponse(jsondata, content_type='application/json')

    def post(self, request):
        permission_required(request.user, 'create_acl')
        data = {'status': 'ok'}
        req = json.loads(request.body.decode('utf-8'))
        u = User.objects.get(pk=req['userid'])
        for perm in req['perms']:
            acl = ACL(user=u.userdata, perm=perm)
            acl.save()
        jsondata = json.dumps(data)
        return HttpResponse(jsondata, content_type='application/json')
acl = login_required(ACLView.as_view())


class AuthEventView(View):
    def post(self, request):
        '''
            Creates a new auth-event.
            create_authevent permission required
        '''
        permission_required(request.user, 'create_authevent')
        req = json.loads(request.body.decode('utf-8'))

        ae = AuthEvent(name=req['name'],
                       auth_method=req['auth_method'],
                       auth_method_config=req['auth_method_config'],
                       metadata=req)
        ae.save()

        data = {'status': 'ok', 'id': ae.pk}
        jsondata = json.dumps(data)
        return HttpResponse(jsondata, content_type='application/json')

    def get(self, request):
        '''
            Lists all AuthEvents
        '''
        permission_required(request.user, 'list_authevent')
        # TODO paginate and filter with GET params
        events = AuthEvent.objects.all()
        aes = []
        for e in events:
            aes.append(e.serialize())

        data = {'status': 'ok', 'events': aes}
        jsondata = json.dumps(data)
        return HttpResponse(jsondata, content_type='application/json')

    def delete(self, request, pk):
        '''
            Delete a auth-event.
            delete_authevent permission required
        '''
        permission_required(request.user, 'delete_authevent')

        ae = AuthEvent.objects.get(pk=pk)
        ae.delete()

        data = {'status': 'ok'}
        jsondata = json.dumps(data)
        return HttpResponse(jsondata, content_type='application/json')
authevent = login_required(AuthEventView.as_view())
