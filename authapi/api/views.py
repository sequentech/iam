from django.http import HttpResponse
from django.views.generic import View
from authmethods import auth_login
from utils import genhmac
from django.conf import settings
from .decorators import login_required
import json


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
