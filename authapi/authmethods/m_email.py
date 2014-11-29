import json
from django.conf import settings
from django.conf.urls import patterns, url
from django.contrib.auth.models import User
from django.core.mail import send_mail
from django.http import HttpResponse
from string import ascii_letters, digits
from utils import genhmac

from . import register_method
from . import random_username
from api.models import AuthEvent, ACL


def register(request, method):
    req = json.loads(request.body.decode('utf-8'))
    mail_to = req.get('email')
    u = User(username=random_username())
    u.save()

    # check method event
    eo = AuthEvent.objects.get(pk=method)
    if eo.auth_method == 'email':
        conf = json.loads(eo.auth_method_config)
        subject = conf.get('subject')
        mail_from = conf.get('mail_from')

        code = random_username(64, ascii_letters+digits)
        valid_link = request.build_absolute_uri(
                '/authmethod/email/validate/%d/%s' % (u.pk,  code))
        msg = conf.get('msg') + valid_link

        u.userdata.event = eo
        u.userdata.metadata = json.dumps({
                'email': mail_to,
                'code': code,
                'email_verified': False
        })
        u.userdata.save()

        send_mail(subject, msg, mail_from, (mail_to,), fail_silently=False)
        data = {'status': 'ok'}
    else:
        data = {'status': 'nok'}

    jsondata = json.dumps(data)
    return HttpResponse(jsondata, content_type='application/json')


def validate(request, user, code):
    u = User.objects.get(pk=int(user))
    u_meta = json.loads(u.userdata.metadata)
    if u_meta.get('code') == code:
        u_meta.update({ 'email_verified': True })
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


class Email:
    DESCRIPTION = 'Register by email. You need to confirm your email.'
    TPL_CONFIG = {
            'subject': 'Confirm your email',
            'msg': 'Click in this link for validate your email: ',
            'mail_from': 'authapi@agoravoting.com'
    }

    def login_error(self):
        d = {'status': 'nok'}
        return d

    def login(self, data):
        d = {'status': 'ok'}
        msg = data['email']
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

register_method('email', Email)
