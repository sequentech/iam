import json
from django.conf import settings
from django.conf.urls import patterns, url
from django.contrib.auth.models import User
from django.http import HttpResponse
from django.shortcuts import get_object_or_404
from django.utils import timezone
from utils import genhmac, constant_time_compare, send_code

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


def check_total_connection(data, req, **kwargs):
    conn = Connection.objects.filter(tlf=req.get('tlf')).count()
    if conn >= kwargs.get('times'):
        return error('Exceeded the level os attempts',
                error_codename='check_total_connection')
    conn = Connection(ip=data['ip'], tlf=req.get('tlf'))
    conn.save()
    return 0


def check_sms_code(data, req, **kwargs):
    ae = AuthEvent.objects.get(pk=data['event'])

    # check code
    u = User.objects.get(userdata__tlf=req['tlf'], userdata__event=ae)
    data['user'] = u.pk
    time_thr = timezone.now() - timedelta(seconds=kwargs.get('timestamp'))
    code = Code.objects.get(user=u.pk, code=req.get('code'),
            created__gt=time_thr)
    if not code:
        return error('Invalid code', error_codename='check_sms_code')

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

        msg = send_code(u)
        if msg:
            data = {'status': 'nok', 'msg': msg}
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

        u = get_object_or_404(User, pk=data['user'])
        u.is_active = True
        u.save()
        data.pop('user')

        data['auth-token'] = genhmac(settings.SHARED_SECRET, u.username)
        return data

register_method('sms', Sms)
