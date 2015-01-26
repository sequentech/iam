import json
from django.conf import settings
from django.conf.urls import patterns, url
from django.contrib.auth.models import User
from django.http import HttpResponse
from string import ascii_letters, digits
from utils import genhmac, constant_time_compare, send_code

from . import register_method
from authmethods.utils import *
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

    email_definition = { "name": "email", "type": "text", "required": True, "min": 4, "max": 255, "required_on_authentication": True }
    code_definition = { "name": "code", "type": "text", "required": True, "min": 6, "max": 255, "required_on_authentication": True }

    def census(self, ae, request):
        req = json.loads(request.body.decode('utf-8'))
        msg = ''
        current_emails = []
        for r in req:
            email = r.get('email')
            msg += check_value(self.email_definition, email)
            msg += check_fields_in_request(r, ae)
            if User.objects.filter(email=email, userdata__event=ae):
                msg += "Email %s repeat." % email
            if email in current_emails:
                msg += "Email %s repeat." % email
            current_emails.append(email)
        if msg:
            data = {'status': 'nok', 'msg': msg}
            return data

        for r in req:
            u = create_user(r, ae)
        return {'status': 'ok'}

    def register(self, ae, request):
        req = json.loads(request.body.decode('utf-8'))
        msg = ''
        email = req.get('email')
        msg += check_value(self.email_definition, email)
        msg += check_fields_in_request(req, ae)
        if User.objects.filter(email=email, userdata__event=ae):
            msg += "Email %s repeat." % email
        if msg:
            data = {'status': 'nok', 'msg': msg}
            return data
        u = create_user(req, ae)
        send_code(u)
        return {'status': 'ok'}

    def authenticate_error(self):
        d = {'status': 'nok'}
        return d

    def authenticate(self, ae, request):
        req = json.loads(request.body.decode('utf-8'))
        msg = ''
        email = req.get('email')
        msg += check_value(self.email_definition, email)
        msg += check_value(self.code_definition, req.get('code'))
        msg += check_fields_in_request(req, ae)
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

        data['auth-token'] = genhmac(settings.SHARED_SECRET, u.username)
        return data

register_method('email', Email)
