import json
from django.conf import settings
from django.conf.urls import patterns, url
from django.contrib.auth.models import User
from django.shortcuts import get_object_or_404
from utils import genhmac, send_code

from . import register_method
from authmethods.utils import *


class Sms:
    DESCRIPTION = 'Provides authentication using an SMS code.'
    CONFIG = {
        'SMS_PROVIDER': 'console',
        'SMS_DOMAIN_ID': '',
        'SMS_LOGIN': '',
        'SMS_PASSWORD': '',
        'SMS_URL': '',
        'SMS_SENDER_ID': '',
        'SMS_VOICE_LANG_CODE': '',
        'msg': 'Click %(url)s and put this code %(code)s',
    }
    PIPELINES = {
        "register-pipeline": [
            ["check_whitelisted", {"field": "tlf"}],
            ["check_whitelisted", {"field": "ip"}],
            ["check_blacklisted", {"field": "ip"}],
            ["check_blacklisted", {"field": "tlf"}],
            ["check_total_max", {"field": "ip", "max": 8}],
            ["check_total_max", {"field": "tlf", "max": 7}],
            ["check_total_max", {"field": "tlf", "period": 1440, "max": 5}],
            ["check_total_max", {"field": "tlf", "period": 60, "max": 3}],
        ],
        "authenticate-pipeline": [
            #['check_total_connection', {'times': 5 }],
            #['check_sms_code', {'timestamp': 5 }]
        ]
    }
    USED_TYPE_FIELDS = ['tlf']

    tlf_definition = { "name": "tlf", "type": "text", "required": True, "min": 4, "max": 20, "required_on_authentication": True }
    code_definition = { "name": "code", "type": "text", "required": True, "min": 6, "max": 255, "required_on_authentication": True }

    def check_config(self, config):
        """ Check config when create auth-event. """
        msg = ''
        for c in config:
            if c != "msg":
                msg += "Invalid config: %s not possible.\n" % c
        return msg


    def census(self, ae, request):
        req = json.loads(request.body.decode('utf-8'))

        msg = ''
        current_tlfs = []
        for r in req:
            tlf = r.get('tlf')
            msg += check_value(self.tlf_definition, tlf)
            msg += check_fields_in_request(r, ae)
            if User.objects.filter(userdata__tlf=tlf, userdata__event=ae):
                msg += "Tlf %s repeat." % tlf
            if tlf in current_tlfs:
                msg += "Tlf %s repeat." % tlf
            current_tlfs.append(tlf)
        if msg:
            data = {'status': 'nok', 'msg': msg}
            return data

        for r in req:
            u = create_user(r, ae)
            give_perms(u, ae)
        return {'status': 'ok'}

    def register(self, ae, request):
        req = json.loads(request.body.decode('utf-8'))

        msg = ''
        tlf = req.get('tlf')
        msg += check_value(self.tlf_definition, tlf)
        msg += check_fields_in_request(req, ae)
        if User.objects.filter(userdata__tlf=tlf, userdata__event=ae):
            msg += "Tlf %s repeat." % tlf
        if msg:
            data = {'status': 'nok', 'msg': msg}
            return data

        msg = check_pipeline(request, ae)
        if msg:
            return msg

        u = create_user(req, ae)
        give_perms(u, ae)
        send_code(u)
        return {'status': 'ok'}

    def authenticate_error(self):
        d = {'status': 'nok'}
        return d

    def authenticate(self, ae, request):
        req = json.loads(request.body.decode('utf-8'))

        msg = ''
        tlf = req.get('tlf')
        msg += check_value(self.tlf_definition, tlf, 'authenticate')
        msg += check_value(self.code_definition, req.get('code'), 'authenticate')
        msg += check_fields_in_request(req, ae, 'authenticate')
        if msg:
            data = {'status': 'nok', 'msg': msg}
            return data

        msg = check_pipeline(request, ae, 'authenticate')
        if msg:
            return msg

        u = get_object_or_404(User, userdata__tlf=tlf, userdata__event=ae)
        msg = check_metadata(req, u)
        if msg:
            data = {'status': 'nok', 'msg': msg}
            return data

        u.is_active = True
        u.save()

        data = {'status': 'ok'}
        data['auth-token'] = genhmac(settings.SHARED_SECRET, u.username)
        return data

register_method('sms', Sms)
