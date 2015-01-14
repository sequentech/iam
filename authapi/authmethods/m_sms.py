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


def check_request(request, data):
    req = json.loads(request.body.decode('utf-8'))

    eo = AuthEvent.objects.get(pk=data['event'])
    conf = eo.metadata
    pipeline = conf.get('fieldsRegister')
    for pipe in pipeline:
        classname = pipe.get('name')
        if classname not in ('dni', 'email'):
            continue
        attr = req.get(classname)
        if not getattr(eval(classname + '_constraint'), '__call__')(attr):
            data['status'] = 'nok'
            data['msg'] += 'Invalid %s.' % classname

    if data['status'] == 'nok':
        jsondata = json.dumps(data)
        return HttpResponse(jsondata, status=400, content_type='application/json')

    data['tlf'] = req.get('tlf')
    data['ip_addr'] = get_client_ip(request)
    return 0


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


def register_request(data, request):
    req = json.loads(request.body.decode('utf-8'))

    u = User(username=random_username())
    u.set_password(req.get('password'))
    u.email = req.get('email')
    u.save()

    data['code'] = random_code(8, ascii_letters+digits)
    valid_link = request.build_absolute_uri(
            '/authmethod/sms-code/validate/%s/' % (data['code']))
    eo = AuthEvent.objects.get(pk=data.get('event'))
    conf = eo.auth_method_config
    msg = conf.get('sms-message') + valid_link

    u.userdata.event = eo
    u.userdata.metadata = json.dumps({
            'first_name': req.get('first_name'),
            'last_name': req.get('last_name'),
            'tlf': req.get('tlf'),
            'code': data['code'],
            'sms_verified': False
    })
    u.userdata.save()
    code = Code(user=u.userdata, tlf=req.get('tlf'), dni=req.get('dni'), code=data['code'])
    code.save()

    data['user'] = u.pk
    return 0


def send_sms(data, conf):
    m = Message(ip=data['ip_addr'], tlf=data['tlf'])
    m.save()
    send_sms_code.apply_async(args=[data, conf])
    return 0


def check_total_connection(data, req, **kwargs):
    conn = Connection.objects.filter(tlf=req.get('tlf'), dni=req.get('dni')).count()
    if conn >= kwargs.get('times'):
        return error('Exceeded the level os attempts',
                error_codename='check_total_connection')
    conn = Connection(ip=data['ip'], tlf=req.get('tlf'), dni=req.get('dni'))
    conn.save()
    return 0


def check_sms_code(data, req, **kwargs):
    eo = AuthEvent.objects.get(pk=data['event'])
    conf = eo.auth_method_config

    # check code
    code = Code.objects.filter(tlf=req.get('tlf'), dni=req.get('dni'))
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
    data['user'] = user
    u_meta = json.loads(user.metadata)
    u_meta.update({ 'sms_verified': True })
    user.metadata = json.dumps(u_meta)
    user.save()
    return 0


def give_perms(data, req, **kwargs):
    user = data['user']
    obj = kwargs.get('object_type')
    for perm in kwargs.get('perms'):
        acl = ACL(user=user, object_type=obj, perm=perm, object_id=data['event'])
        acl.save()
    return 0


def register(request, event):
    data = {'status': 'ok', 'msg': '', 'event': event}

    check = check_request(request, data)
    if check != 0:
        return check

    eo = AuthEvent.objects.get(pk=event)
    conf = eo.auth_method_config
    pipeline = conf.get('register-pipeline')
    for pipe in pipeline:
        classname = pipe[0]
        if classname == 'register_request':
            check = getattr(eval(classname), '__call__')(data, request)
        elif classname == 'send_sms':
            check = getattr(eval(classname), '__call__')(data, conf)
        else:
            check = getattr(eval(classname), '__call__')(data, **pipe[1])

        if check != 0:
            return check

    data.pop('code')
    jsondata = json.dumps(data)
    return HttpResponse(jsondata, content_type='application/json')


def validate(request, event):
    data = {'status': 'ok', 'event': event, 'ip': get_client_ip(request)}
    req = json.loads(request.body.decode('utf-8'))

    eo = AuthEvent.objects.get(pk=event)
    conf = eo.auth_method_config
    pipeline = conf.get('validate-pipeline')
    for pipe in pipeline:
        check = getattr(eval(pipe[0]), '__call__')(data, req, **pipe[1])

        if check != 0:
            return check

    pwd = data['user'].user.password
    data['auth-token'] = genhmac(settings.SHARED_SECRET, pwd)
    data.pop('user')
    jsondata = json.dumps(data)
    return HttpResponse(jsondata, content_type='application/json')


class Sms:
    DESCRIPTION = 'Provides authentication using an SMS code.'
    TPL_CONFIG = {
            'SMS_PROVIDER': 'console',
            'SMS_DOMAIN_ID': '',
            'SMS_LOGIN': '',
            'SMS_PASSWORD': '',
            'SMS_URL': '',
            'SMS_SENDER_ID': '',
            'SMS_VOICE_LANG_CODE': '',
            'sms-message': 'Confirm your sms code: ',
            'register-pipeline': [
                #["check_tlf_expire_max", {"field": "tlf", "expire-secs": 120}],
                ["check_whitelisted", {"field": "tlf"}],
                ["check_whitelisted", {"field": "ip"}],
                ["check_blacklisted", {"field": "ip"}],
                ["check_blacklisted", {"field": "tlf"}],
                #["check_ip_total_unconfirmed_requests_max", {"max": 30}],
                ["check_total_max", {"field": "ip", "max": 8}],
                ["check_total_max", {"field": "tlf", "max": 7}],
                ["check_total_max", {"field": "tlf", "period": 1440, "max": 5}],
                ["check_total_max", {"field": "tlf", "period": 60, "max": 3}],
                #["check_id_in_census", {"fields": "tlf"}],
                ["register_request"],
                #["generate_token", {"land_line_rx": "^\+34[89]"}],
                ["send_sms"],
            ],
            'validate-pipeline': [
                ['check_total_connection', {'times': 5 }],
                ['check_sms_code', {'timestamp': 5 }], # seconds
                ['give_perms', {'object_type': 'Vote', 'perms': ['create',] }],
            ],
    }
    METADATA_DEFAULT = {
        'steps': [ 'register', 'validate', 'login' ],
        'fieldsRegister': [
            {'name': 'name', 'type': 'text', 'required': False},
            {'name': 'surname', 'type': 'text', 'required': False},
            {'name': 'dni', 'type': 'text', 'required': True, 'max': 9},
            {'name': 'tlf', 'type': 'text', 'required': True, 'max': 12},
            {'name': 'email', 'type': 'text', 'required': True},
            {'name': 'password', 'type': 'password', 'required': True, 'min': 6},
        ],
        'fieldsValidate': [
            {'name': 'dni', 'type': 'text', 'required': True, 'max': 9},
            {'name': 'tlf', 'type': 'text', 'required': True, 'max': 12},
            {'name': 'code', 'type': 'password', 'required': True, 'min': 4},
        ],
        'capcha': False,
    }

    def login_error(self):
        d = {'status': 'nok'}
        return d

    def login(self, data):
        d = {'status': 'ok'}
        email = data['email']
        pwd = data['password']

        try:
            u = User.objects.filter(email=email)[0]
        except:
            return self.login_error()

        u_meta = json.loads(u.userdata.metadata)
        if not u.check_password(pwd) or not u_meta['sms_verified']:
            return self.login_error()

        d['auth-token'] = genhmac(settings.SHARED_SECRET, u.username)
        return d

    views = patterns('',
        url(r'^register/(?P<event>\d+)$', register),
        url(r'^validate/(?P<event>\d+)$', validate),
    )

register_method('sms-code', Sms)
