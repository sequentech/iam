from django.http import HttpResponse
from django.views.generic import View
import json


class Test(View):
    ''' Test view that returns the response data '''

    def get(self, request):
        data = {'status': 'ok', 'method': 'GET'}
        data['get'] = dict(request.GET)
        jsondata = json.dumps(data)
        return HttpResponse(jsondata, content_type='application/json')

    def post(self, request):
        data = {'status': 'ok', 'method': 'POST'}
        data['post'] = dict(request.POST)
        jsondata = json.dumps(data)
        return HttpResponse(jsondata, content_type='application/json')
test = Test.as_view()
