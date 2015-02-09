import json
from django.conf import settings
from django.conf.urls import patterns, url
from django.contrib.auth.models import User
from utils import genhmac, constant_time_compare, send_code

from . import register_method
from authmethods.utils import *
from api.models import AuthEvent
from authmethods.models import Code


class Email:
    DESCRIPTION = 'Register by email. You need to confirm your email.'
    CONFIG = {
        'subject': 'Confirm your email',
        'msg': 'Click in this %(url)s for validate your email: ',
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
    USED_TYPE_FIELDS = ['email']

    email_definition = { "name": "email", "type": "email", "required": True, "min": 4, "max": 255, "required_on_authentication": True }
    code_definition = { "name": "code", "type": "text", "required": True, "min": 6, "max": 255, "required_on_authentication": True }

    def check_config(self, config):
        """ Check config when create auth-event. """
        msg = ''
        for c in config:
            if not c in ('subject', 'msg'):
                msg += "Invalid config: %s not possible.\n" % c
        return msg

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
            give_perms(u, ae)
        return {'status': 'ok'}

    def register(self, ae, request):
        req = json.loads(request.body.decode('utf-8'))

        msg = check_pipeline(request, ae)
        if msg:
            return msg

        msg = ''
        email = req.get('email')
        msg += check_value(self.email_definition, email)
        msg += check_fields_in_request(req, ae)
        if User.objects.filter(email=email, userdata__event=ae): # repeat
            u = User.objects.get(email=email, userdata__event=ae)
            if u.is_active:
                msg += "%s already registered." % email
            codes = Code.objects.filter(user=u.userdata).count()
            if codes > settings.SEND_CODES_EMAIL_MAX:
                msg += "Maximun number of email sent to %s." % email
            else:
                u = edit_user(u, req)
        else:
            u = create_user(req, ae)
            give_perms(u, ae)

        if msg:
            data = {'status': 'nok', 'msg': msg}
            return data

        send_code(u)
        return {'status': 'ok'}

    def authenticate_error(self):
        d = {'status': 'nok'}
        return d

    def authenticate(self, ae, request):
        req = json.loads(request.body.decode('utf-8'))
        msg = ''
        email = req.get('email')
        msg += check_value(self.email_definition, email, 'authenticate')
        msg += check_value(self.code_definition, req.get('code'), 'authenticate')
        msg += check_fields_in_request(req, ae, 'authenticate')
        if msg:
            data = {'status': 'nok', 'msg': msg}
            return data

        msg = check_pipeline(request, ae, 'authenticate')
        if msg:
            return msg

        try:
            u = User.objects.get(email=email, userdata__event=ae)
            code = Code.objects.filter(user=u.userdata,
                    code=req.get('code')).order_by('created').first()
        except:
            return {'status': 'nok', 'msg': 'Invalid code.'}

        msg = check_metadata(req, u)
        if msg:
            data = {'status': 'nok', 'msg': msg}
            return data
        u.is_active = True
        u.save()

        data = {'status': 'ok'}
        data['auth-token'] = genhmac(settings.SHARED_SECRET, u.username)
        return data

register_method('email', Email)
