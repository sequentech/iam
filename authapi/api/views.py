from django.http import HttpResponse
from django.views.generic import View
from authmethods import auth_login
import json


class Test(View):
    ''' Test view that returns the response data '''

    def get(self, request):
        req = json.loads(request.body.decode('utf-8'))
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
