import json
from django.conf import settings
from django.conf.urls import patterns, url
from django.contrib.auth.models import User
from utils import genhmac, constant_time_compare, send_codes

from . import register_method
from authmethods.utils import *
from api.models import AuthEvent
from authmethods.models import Code


class Email:
    DESCRIPTION = 'Register by email. You need to confirm your email.'
    CONFIG = {
        'subject': 'Confirm your email',
        'msg': 'Click %(url)s and put this code %(code)s'
    }
    PIPELINES = {
        'give_perms': [
            {'object_type': 'UserData', 'perms': ['edit',], 'object_id': 'UserDataId' },
            {'object_type': 'AuthEvent', 'perms': ['vote',], 'object_id': 'AuthEventId' }
        ],
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
        validation = req.get('field-validation', 'enabled') == 'enabled'

        msg = ''
        current_emails = []
        for r in req.get('census'):
            email = r.get('email')
            msg += check_field_type(self.email_definition, email)
            if validation:
                msg += check_field_type(self.email_definition, email)
                msg += check_field_value(self.email_definition, email)
            msg += check_fields_in_request(r, ae, 'census', validation=validation)
            if validation:
                msg += exist_user(r, ae)
                if email in current_emails:
                    msg += "Email %s repeat in this census." % email
                current_emails.append(email)
            else:
                if msg:
                    msg = ''
                    continue
                exist = exist_user(r, ae)
                if exist and not exist.count('None'):
                    continue
                used = r.get('status', 'registered') == 'used'
                u = create_user(r, ae, used)
                give_perms(u, ae)
        if msg and validation:
            data = {'status': 'nok', 'msg': msg}
            return data

        if validation:
            for r in req.get('census'):
                used = r.get('status', 'registered') == 'used'
                u = create_user(r, ae, used)
                give_perms(u, ae)
        return {'status': 'ok'}

    def register(self, ae, request):
        req = json.loads(request.body.decode('utf-8'))

        msg = check_pipeline(request, ae)
        if msg:
            return msg

        msg = ''
        email = req.get('email')
        msg += check_field_type(self.email_definition, email)
        msg += check_field_value(self.email_definition, email)
        msg += check_fields_in_request(req, ae)
        if msg:
            data = {'status': 'nok', 'msg': msg}
            return data
        msg_exist = exist_user(req, ae, get_repeated=True)
        if msg_exist:
            u = msg_exist.get('user')
            if u.is_active:
                msg += msg_exist.get('msg') + "Already registered."
            codes = Code.objects.filter(user=u.userdata).count()
            if codes > settings.SEND_CODES_EMAIL_MAX:
                msg += msg_exist.get('msg')  + "Maximun number of codes sent."
            else:
                u = edit_user(u, req)
        else:
            u = create_user(req, ae)
            msg += give_perms(u, ae)

        if msg:
            data = {'status': 'nok', 'msg': msg}
            return data

        send_codes.apply_async(args=[[u.id,]])
        return {'status': 'ok'}

    def authenticate_error(self):
        d = {'status': 'nok'}
        return d

    def authenticate(self, ae, request):
        req = json.loads(request.body.decode('utf-8'))
        msg = ''
        email = req.get('email')
        msg += check_field_type(self.email_definition, email, 'authenticate')
        msg += check_field_value(self.email_definition, email, 'authenticate')
        msg += check_field_type(self.code_definition, req.get('code'), 'authenticate')
        msg += check_field_value(self.code_definition, req.get('code'), 'authenticate')
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
