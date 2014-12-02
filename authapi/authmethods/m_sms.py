import json
from django.conf import settings
from django.conf.urls import patterns, url
from django.contrib.auth.models import User
from django.http import HttpResponse
from string import ascii_letters, digits
from utils import genhmac

from . import register_method
from authmethods.utils import *
from authmethods.models import Message
from api.models import AuthEvent, ACL


def send_sms(provider, user, pwd, msg, tlf, ip):
    # TODO: send sms
    m = Message(ip=ip, tlf=tlf)
    m.save()


def register(request, event):
    req = json.loads(request.body.decode('utf-8'))
    data = {'status': 'ok', 'msg': ''}

    email = req.get('email')
    if not email_constraint(email):
        data['status'] = 'nok'
        data['msg'] += 'Invalid email.'

    dni = req.get('dni')
    if not dni_constraint(dni):
        data['status'] = 'nok'
        data['msg'] += 'Invalid dni. '

    if data['status'] == 'nok':
        jsondata = json.dumps(data)
        return HttpResponse(jsondata, content_type='application/json')

    tlf = req.get('tlf')
    data['tlf'] = tlf
    data['ip_addr'] = get_client_ip(request)

    c = check_tlf_whitelisted(data)
    if c != 0:
        return c
    c = check_ip_whitelisted(data)
    if c != 0:
        return c
    c = check_tlf_blacklisted(data)
    if c != 0:
        return c
    c = check_ip_blacklisted(data)
    if c != 0:
        return c

    c = check_tlf_total_max(data)
    if c != 0:
        return c
    c = check_ip_total_max(data)
    if c != 0:
        return c

    first_name = req.get('first_name')
    last_name = req.get('last_name')

    u = User(username=random_username())
    u.email = email
    u.save()

    eo = AuthEvent.objects.get(pk=event)
    conf = json.loads(eo.auth_method_config)
    provider = conf.get('provider')
    user = conf.get('user')
    pwd = conf.get('pwd')

    code = random_code(8, ascii_letters+digits)
    valid_link = request.build_absolute_uri(
            '/authmethod/sms-code/validate/%d/%s' % (u.pk,  code))
    msg = conf.get('msg') + valid_link

    u.userdata.event = eo
    u.userdata.metadata = json.dumps({
            'first_name': first_name,
            'last_name': last_name,
            'tlf': tlf,
            'code': code,
            'sms_verified': False
    })
    u.userdata.save()

    send_sms(provider, user, pwd, msg, tlf, get_client_ip(request))
    data['code'] = code

    jsondata = json.dumps(data)
    return HttpResponse(jsondata, content_type='application/json')


def validate(request, user, code):
    u = User.objects.get(username=user)
    u_meta = json.loads(u.userdata.metadata)
    if u_meta.get('code') == code:
        u_meta.update({ 'sms_verified': True })
        u.userdata.metadata = json.dumps(u_meta)
        u.save()

        # giving perms
        acl = ACL(user=u.userdata, perm='vote')
        acl.save()
        data = {'status': 'ok', 'username': u.username}
    else:
        data = {'status': 'nok'}

    jsondata = json.dumps(data)
    return HttpResponse(jsondata, content_type='application/json')


class Sms:
    DESCRIPTION = 'Provides authentication using an SMS code.'
    TPL_CONFIG = {
            'provider': 'provider',
            'user': 'user',
            'pwd': 'pwd',
            'msg': 'Confirm your sms code: ',
    }

    def login_error(self):
        d = {'status': 'nok'}
        return d

    def login(self, data):
        d = {'status': 'ok'}
        msg = data['user']
        pwd = data['password']

        try:
            u = User.objects.get(username=msg)
        except:
            return self.login_error()

        u_meta = json.loads(u.userdata.metadata)
        if not u.check_password(pwd) or not u_meta['sms_verified']:
            return self.login_error()

        d['auth-token'] = genhmac(settings.SHARED_SECRET, msg)
        return d

    views = patterns('',
        url(r'^register/(?P<event>\d+)$', register),
        url(r'^validate/(?P<user>\w+)/(?P<code>\w+)$', validate),
    )

register_method('sms-code', Sms)
