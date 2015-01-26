import json
from django.conf import settings
from django.conf.urls import patterns, url
from django.contrib.auth.models import User
from django.http import HttpResponse
from string import ascii_letters, digits
from utils import genhmac, constant_time_compare, send_code

from . import register_method
from authmethods.utils import check_census, create_user, is_user_repeat
from authmethods.utils import check_metadata, check_fields_in_request
from api.models import AuthEvent
from authmethods.models import Code


class Email:
    DESCRIPTION = 'Register by email. You need to confirm your email.'
    CONFIG = {
        'subject': 'Confirm your email',
        'msg': 'Click in this link for validate your email: ',
        'mail_from': 'authapi@agoravoting.com',
        'give_perms': {'object_type': 'Vote', 'perms': ['create',] },
    }
    PIPELINES = {
        "register-pipeline": [
            ["check_whitelisted", {"field": "ip"}],
            ["check_blacklisted", {"field": "ip"}],
            ["check_total_max", {"field": "ip", "max": 8}],
        ],
        "authenticate-pipeline": [
            #['check_total_connection', {'times': 5 }],
        ]
    }

    def census(self, ae, request):
        req = json.loads(request.body.decode('utf-8'))
        msg = check_census(req, ae)
        if msg:
            data = {'status': 'nok', 'msg': msg}
            return data
        for r in req:
            msg += is_user_repeat(r, ae)
            if msg:
                continue
            u = create_user(r, ae)
        if msg:
            data = {'status': 'nok', 'msg': msg}
        else:
            data = {'status': 'ok'}
        return data

    def register(self, ae, request):
        req = json.loads(request.body.decode('utf-8'))
        msg = check_fields_in_request(req, ae)
        if msg:
            data = {'status': 'nok', 'msg': msg}
            return data

        msg = is_user_repeat(req, ae)
        if msg:
            data = {'status': 'nok', 'msg': msg}
            return data
        u = create_user(req, ae)

        msg = send_code(u)
        if msg:
            data = {'status': 'nok', 'msg': msg}
            return data
        data = {'status': 'ok'}
        return data

    def authenticate_error(self):
        d = {'status': 'nok'}
        return d

    def authenticate(self, ae, request):
        d = {'status': 'ok'}
        req = json.loads(request.body.decode('utf-8'))
        msg = check_fields_in_request(req, ae)
        if msg:
            data = {'status': 'nok', 'msg': msg}
            return data

        email = req['email']
        code = req['code']

        try:
            u = User.objects.get(email=email, userdata__event=ae)
        except:
            return self.authenticate_error()
        codedb = Code.objects.filter(user=u.userdata)[0].code
        if constant_time_compare(codedb, code):
            msg = check_metadata(req, u)
            if msg:
                data = {'status': 'nok', 'msg': msg}
                return data

            u.is_active = True
            u.save()

            data = {'status': 'ok', 'username': u.username}
            status = 200
        else:
            data = {'status': 'nok'}
            status = 400

        d['auth-token'] = genhmac(settings.SHARED_SECRET, u.username)
        return d

register_method('email', Email)
