import json
from django.conf import settings
from django.conf.urls import patterns, url
from django.contrib.auth.models import User
from utils import genhmac, constant_time_compare, send_codes

from . import register_method
from authmethods.utils import *
from api.models import AuthEvent
from authmethods.models import Code
from pipelines.base import execute_pipeline, PipeReturnvalue
from contracts import CheckException, JSONContractEncoder

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
            if isinstance(email, str):
                email = email.strip()
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
                # By default we creates the user as active we don't check
                # the pipeline
                u = create_user(r, ae, True)
                give_perms(u, ae)
        if msg and validation:
            return self.error("Incorrect data", error_codename="invalid_credentials")

        if validation:
            for r in req.get('census'):
                # By default we creates the user as active we don't check
                # the pipeline
                u = create_user(r, ae, True)
                give_perms(u, ae)
        return {'status': 'ok'}

    def error(self, msg, error_codename):
        d = {'status': 'nok', 'msg': msg, 'error_codename': error_codename}
        return d

    def register(self, ae, request):
        req = json.loads(request.body.decode('utf-8'))

        msg = check_pipeline(request, ae)
        if msg:
            return msg

        # create the user as active? Usually yes, but the execute_pipeline call
        # might modify this
        active = True

        pipedata = dict(
            active=active,
            request=req)
        if ae.extra_fields:
            for field in ae.extra_fields:
                name = 'register-pipeline'
                if name in field:
                    try:
                        ret = execute_pipeline(field[name], name, pipedata, field['name'], ae)
                    except CheckException as e:
                        return self.error(
                            JSONContractEncoder().encode(e.data['context']),
                            error_codename=e.data['key'])
                    except Exception as e:
                        return self.error(
                            "unknown-exception: " + str(e),
                            error_codename="unknown-exception")
                    if ret != PipeReturnvalue.CONTINUE:
                        key = "stopped-field-register-pipeline"
                        return self.error(key, key)

        active = pipedata['active']
        msg = ''
        email = req.get('email')
        if isinstance(email, str):
            email = email.strip()
        msg += check_field_type(self.email_definition, email)
        msg += check_field_value(self.email_definition, email)
        msg += check_fields_in_request(req, ae)
        if msg:
            return self.error("Incorrect data", error_codename="invalid_credentials")
        msg_exist = exist_user(req, ae, get_repeated=True)
        if msg_exist:
            u = msg_exist.get('user')
            if u.is_active:
                return self.error("Incorrect data", error_codename="invalid_credentials")
        else:
            u = create_user(req, ae, active)
            msg += give_perms(u, ae)

        if msg:
            return self.error("Incorrect data", error_codename="invalid_credentials")
        elif not active:
            # Note, we are not calling to extend_send_sms because we are not
            # sending the code in here
            return {'status': 'ok'}

        send_codes.apply_async(args=[[u.id,], request])
        return {'status': 'ok'}

    def authenticate_error(self):
        d = {'status': 'nok'}
        return d

    def authenticate(self, ae, request):
        req = json.loads(request.body.decode('utf-8'))
        msg = ''
        email = req.get('email')
        if isinstance(email, str):
            email = email.strip()
        msg += check_field_type(self.email_definition, email, 'authenticate')
        msg += check_field_value(self.email_definition, email, 'authenticate')
        msg += check_field_type(self.code_definition, req.get('code'), 'authenticate')
        msg += check_field_value(self.code_definition, req.get('code'), 'authenticate')
        msg += check_fields_in_request(req, ae, 'authenticate')
        if msg:
            return self.error("Incorrect data", error_codename="invalid_credentials")

        msg = check_pipeline(request, ae, 'authenticate')
        if msg:
            return self.error("Incorrect data", error_codename="invalid_credentials")

        try:
            u = User.objects.get(email=email, userdata__event=ae, is_active=True)
        except:
            return self.error("Incorrect data", error_codename="invalid_credentials")

        code = Code.objects.filter(user=u.userdata,
                code=req.get('code')).order_by('created').first()
        if not code:
            return self.error("Incorrect data", error_codename="invalid_credentials")

        msg = check_metadata(req, u)
        if msg:
            data = {'status': 'nok', 'msg': msg}
            return self.error("Incorrect data", error_codename="invalid_credentials")
        u.save()

        data = {'status': 'ok'}
        data['auth-token'] = genhmac(settings.SHARED_SECRET, u.username)
        return data

register_method('email', Email)
