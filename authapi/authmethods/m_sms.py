import json
from django.conf import settings
from django.conf.urls import patterns, url
from django.contrib.auth.models import User
from django.http import HttpResponse
from string import ascii_letters, digits
from utils import genhmac

from . import register_method
from . import random_username
from api.models import AuthEvent, ACL


def send_sms(provider, user, pwd, msg, tlf):
    # TODO
    pass


def register(request, method):
    req = json.loads(request.body.decode('utf-8'))
    tlf = req.get('tlf')
    u = User(username=random_username())
    u.save()

    # check method event
    eo = AuthEvent.objects.get(pk=method)
    if eo.auth_method == 'sms-code':
        conf = json.loads(eo.auth_method_config)
        provider = conf.get('provider')
        user = conf.get('user')
        pwd = conf.get('pwd')

        code = random_username(8, ascii_letters+digits)
        valid_link = request.build_absolute_uri(
                '/authmethod/sms-code/validate/%d/%s' % (u.pk,  code))
        msg = conf.get('msg') + valid_link

        u.userdata.event = eo
        u.userdata.metadata = json.dumps({
                'tlf': tlf,
                'code': code,
                'sms_verified': False
        })
        u.userdata.save()

        send_sms(provider, user, pwd, msg, tlf)
        data = {'status': 'ok', 'code': code}
    else:
        data = {'status': 'nok'}

    jsondata = json.dumps(data)
    return HttpResponse(jsondata, content_type='application/json')


def validate(request, user, code):
    u = User.objects.get(pk=int(user))
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

        if not u.check_password(pwd):
            return self.login_error()

        d['auth-token'] = genhmac(settings.SHARED_SECRET, msg)
        return d

    views = patterns('',
        url(r'^register/(?P<method>\d+)$', register),
        url(r'^validate/(?P<user>\d+)/(?P<code>\w+)$', validate),
    )

register_method('sms-code', Sms)
