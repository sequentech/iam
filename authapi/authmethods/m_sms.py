import json
from django.conf import settings
from django.conf.urls import patterns, url
from django.contrib.auth.models import User
from django.shortcuts import get_object_or_404
from utils import genhmac, send_codes

import plugins
from . import register_method
from authmethods.utils import *


class Sms:
    DESCRIPTION = 'Provides authentication using an SMS code.'
    CONFIG = {
        'msg': 'Enter in %(url)s and put this code %(code)s'
    }
    PIPELINES = {
        'give_perms': [
            {'object_type': 'UserData', 'perms': ['edit',], 'object_id': 'UserDataId' },
            {'object_type': 'AuthEvent', 'perms': ['vote',], 'object_id': 'AuthEventId' }
        ],
        "register-pipeline": [
            ["check_whitelisted", {"field": "tlf"}],
            ["check_whitelisted", {"field": "ip"}],
            ["check_blacklisted", {"field": "ip"}],
            ["check_blacklisted", {"field": "tlf"}],
            ["check_total_max", {"field": "ip", "max": 8}],
            ["check_total_max", {"field": "tlf", "max": 7}],
            ["check_total_max", {"field": "tlf", "period": 1440, "max": 5}],
        ],
        "authenticate-pipeline": [
            #['check_total_connection', {'times': 5 }],
            #['check_sms_code', {'timestamp': 5 }]
        ],
        "resend-auth-pipeline": [
            ["check_whitelisted", {"field": "tlf"}],
            ["check_whitelisted", {"field": "ip"}],
            ["check_blacklisted", {"field": "ip"}],
            ["check_blacklisted", {"field": "tlf"}],
            ["check_total_max", {"field": "tlf", "period": 3600, "max": 5}],
            ["check_total_max", {"field": "tlf", "period": 3600*24, "max": 15}],
            ["check_total_max", {"field": "ip", "period": 3600, "max": 10}],
            ["check_total_max", {"field": "ip", "period": 3600*24, "max": 20}],
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
        validation = req.get('field-validation', 'enabled') == 'enabled'
        data = {'status': 'ok'}

        msg = ''
        current_tlfs = []
        for r in req.get('census'):
            if r.get('tlf'):
                r['tlf'] = get_cannonical_tlf(r.get('tlf'))
            tlf = r.get('tlf')
            if isinstance(tlf, str):
                tlf = tlf.strip()
            msg += check_field_type(self.tlf_definition, tlf)
            if validation:
                msg += check_field_value(self.tlf_definition, tlf)
            msg += check_fields_in_request(r, ae, 'census', validation=validation)
            if validation:
                msg += exist_user(r, ae)
                if tlf in current_tlfs:
                    msg += "Tlf %s repeat." % tlf
                current_tlfs.append(tlf)
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
        return data

    def register(self, ae, request):
        req = json.loads(request.body.decode('utf-8'))
        msg = check_pipeline(request, ae)
        if msg:
            return msg

        msg = ''
        if req.get('tlf'):
            req['tlf'] = get_cannonical_tlf(req.get('tlf'))
        tlf = req.get('tlf')
        if isinstance(tlf, str):
            tlf = tlf.strip()
        msg += check_field_type(self.tlf_definition, tlf)
        msg += check_field_value(self.tlf_definition, tlf)
        msg += check_fields_in_request(req, ae)
        if msg:
            data = {'status': 'nok', 'msg': msg}
            return data
        msg_exist = exist_user(req, ae, get_repeated=True)
        if msg_exist:
            u = msg_exist.get('user')
            if u.is_active:
                return error("Invalid credentials", error_codename="invalid_credentials")
            codes = Code.objects.filter(user=u.userdata).count()
            if codes > settings.SEND_CODES_SMS_MAX:
                return error("Invalid credentials", error_codename="invalid_credentials")
        else:
            u = create_user(req, ae)
            msg += give_perms(u, ae)

        if msg:
            data = {'status': 'nok', 'msg': msg}
            return data

        result = plugins.call("extend_send_sms", ae, 1)
        if result:
            return {'status': 'nok', 'msg': result}
        send_codes.apply_async(args=[[u.id,]])
        return {'status': 'ok'}

    def authenticate_error(self):
        d = {'status': 'nok'}
        return d

    def authenticate(self, ae, request):
        req = json.loads(request.body.decode('utf-8'))

        msg = ''
        if req.get('tlf'):
            req['tlf'] = get_cannonical_tlf(req.get('tlf'))
        tlf = req.get('tlf')
        if isinstance(tlf, str):
            tlf = tlf.strip()
        msg += check_field_type(self.tlf_definition, tlf, 'authenticate')
        msg += check_field_value(self.tlf_definition, tlf, 'authenticate')
        msg += check_field_type(self.code_definition, req.get('code'), 'authenticate')
        msg += check_field_value(self.code_definition, req.get('code'), 'authenticate')
        msg += check_fields_in_request(req, ae, 'authenticate')
        if msg:
            data = {'status': 'nok', 'msg': msg}
            return data

        try:
            u = User.objects.get(userdata__tlf=tlf, userdata__event=ae)
        except:
            return error("Invalid credentials", error_codename="invalid_credentials")

        code = Code.objects.filter(user=u.userdata,
                code=req.get('code')).order_by('created').first()
        if not code:
            return error("Invalid credentials", error_codename="invalid_credentials")

        msg = check_pipeline(request, ae, 'authenticate')
        if msg:
            return msg

        msg = check_metadata(req, u)
        if msg:
            data = {'status': 'nok', 'msg': msg}
            return data

        u.is_active = True
        u.save()

        data = {'status': 'ok'}
        data['auth-token'] = genhmac(settings.SHARED_SECRET, u.username)
        return data

    def resend_auth_code(self, ae, request):
        req = json.loads(request.body.decode('utf-8'))

        msg = ''
        if req.get('tlf'):
            req['tlf'] = get_cannonical_tlf(req.get('tlf'))
        tlf = req.get('tlf')
        if isinstance(tlf, str):
            tlf = tlf.strip()
        msg += check_field_type(self.tlf_definition, tlf, 'authenticate')
        msg += check_field_value(self.tlf_definition, tlf, 'authenticate')
        if msg:
            return error("Invalid credentials", error_codename="invalid_credentials")

        try:
            u = User.objects.get(userdata__tlf=tlf, userdata__event=ae, is_active=True)
        except:
            return error("Invalid credentials", error_codename="invalid_credentials")

        msg = check_pipeline(
          request,
          ae,
          'resend-auth-pipeline',
          Sms.PIPELINES['resend-auth-pipeline'])

        if msg:
            return msg

        result = plugins.call("extend_send_sms", ae, 1)
        if result:
            return {'status': 'nok', 'msg': result}
        send_codes.apply_async(args=[[u.id,]])
        return {'status': 'ok'}

register_method('sms', Sms)
