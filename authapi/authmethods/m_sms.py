import json
from django.conf import settings
from django.conf.urls import patterns, url
from django.contrib.auth.models import User
from django.http import HttpResponse
from django.utils import timezone
from string import ascii_letters, digits
from utils import genhmac, constant_time_compare, send_sms_code

from . import register_method
from authmethods.utils import *
from authmethods.models import Message, Code, Connection
from api.models import AuthEvent, ACL


def check_whitelisted(data, **kwargs):
    field = kwargs.get('field')
    if field == 'tlf':
        check = check_tlf_whitelisted(data)
    elif field == 'ip':
        check = check_tlf_whitelisted(data)
    return 0 if check == 0 else check


def check_blacklisted(data, **kwargs):
    field = kwargs.get('field')
    if field == 'tlf':
        check = check_tlf_blacklisted(data)
    elif field == 'ip':
        check = check_tlf_blacklisted(data)
    return 0 if check == 0 else check


def check_total_max(data, **kwargs):
    check = check_tlf_total_max(data, **kwargs)
    if check != 0:
        return check
    check = check_ip_total_max(data, **kwargs)
    return 0 if check == 0 else check



def send_sms(data, conf):
    m = Message(ip=data['ip_addr'], tlf=data['tlf'])
    m.save()
    send_sms_code.apply_async(args=[data, conf])
    return 0


def check_total_connection(data, req, **kwargs):
    conn = Connection.objects.filter(tlf=req.get('tlf')).count()
    if conn >= kwargs.get('times'):
        return error('Exceeded the level os attempts',
                error_codename='check_total_connection')
    #import ipdb;ipdb.set_trace()
    conn = Connection(ip=data['ip'], tlf=req.get('tlf'))
    conn.save()
    return 0


def check_sms_code(data, req, **kwargs):
    ae = AuthEvent.objects.get(pk=data['event'])

    # check code
    if req.get('email'):
        u = User.objects.get(email=req['email'], userdata__event=ae)
    else:
        # TODO: search tlf in metadata
        u = User.objects.filter(userdata__event=ae)[0]
    code = Code.objects.filter(user=u.userdata)
    if not code:
        return error('Not exist any code.', error_codename='check_sms_code')
    else:
        code = code.last()

    # check code constant_time
    if not constant_time_compare(code.code, req.get('code')):
        return error('Invalid code.', error_codename='check_sms_code')

    # check timestamp
    time_thr = timezone.now() - timedelta(seconds=kwargs.get('timestamp'))
    if not Message.objects.filter(tlf=req.get('tlf'), created__gt=time_thr):
        return error('Timeout.', error_codename='check_sms_code')

    user = code.user
    user.is_active = True
    data['user'] = user
    user.save()
    return 0


def give_perms(data, req, **kwargs):
    user = data['user']
    obj = kwargs.get('object_type')
    for perm in kwargs.get('perms'):
        acl = ACL(user=user, object_type=obj, perm=perm, object_id=data['event'])
        acl.save()
    return 0


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
        'sms-message': 'Confirm your sms code: ',
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
            ['check_total_connection', {'times': 5 }],
            ['check_sms_code', {'timestamp': 5 }]
        ]
    }

    def census(self, ae, request):
        req = json.loads(request.body.decode('utf-8'))
        msg = check_census(req, ae)
        if msg:
            data = {'status': 'nok', 'msg': msg}
            return data
        for r in req:
            u = create_user(r, ae)
            # add perm
            acl = ACL(user=u.userdata, object_type='UserData', perm='edit', object_id=u.pk)
            acl.save()
        data = {'status': 'ok'}
        return data

    def register(self, ae, request):
        req = json.loads(request.body.decode('utf-8'))
        msg = check_fields_in_request(req, ae)
        if msg:
            data = {'status': 'nok', 'msg': msg}
            return data

        data = {'status': 'ok', 'msg': '', 'event': ae.id}
        data['tlf'] = req.get('tlf')
        data['ip_addr'] = get_client_ip(request)

        conf = ae.auth_method_config
        pipeline = conf.get('pipeline').get('register-pipeline')
        for pipe in pipeline:
            classname = pipe[0]
            check = getattr(eval(classname), '__call__')(data, **pipe[1])

            if check != 0:
                data.update(json.loads(check.content.decode('utf-8')))
                data['status'] = check.status_code
                return data

        u = create_user(req, ae)

        check = send_sms(data, conf.get('config'))
        if check != 0:
            data.update(json.loads(check.content.decode('utf-8')))
            data['status'] = check.status_code
            return data

        return data

    def authenticate_error(self):
        d = {'status': 'nok'}
        return d

    def authenticate(self, ae, request):
        req = json.loads(request.body.decode('utf-8'))
        msg = check_fields_in_request(req, ae)
        if msg:
            data = {'status': 'nok', 'msg': msg}
            return data

        data = {'status': 'ok', 'event': ae.id, 'ip': get_client_ip(request)}
        conf = ae.auth_method_config
        pipeline = conf.get('pipeline').get('authenticate-pipeline')
        for pipe in pipeline:
            check = getattr(eval(pipe[0]), '__call__')(data, req, **pipe[1])
            if check != 0:
                data.update(json.loads(check.content.decode('utf-8')))
                data['status'] = check.status_code
                return data

        data.pop('user')

        email = req['email']
        try:
            u = User.objects.filter(email=email)[0]
        except:
            return self.authenticate_error()
        u.is_active = True
        data['auth-token'] = genhmac(settings.SHARED_SECRET, u.username)
        return d

register_method('sms', Sms)
