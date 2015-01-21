import json
from django.conf import settings
from django.conf.urls import patterns, url
from django.contrib.auth.models import User
from django.http import HttpResponse
from string import ascii_letters, digits
from utils import genhmac, constant_time_compare, send_email

from . import register_method
from authmethods.utils import random_code, random_username
from api.models import AuthEvent, ACL


class Email:
    DESCRIPTION = 'Register by email. You need to confirm your email.'
    VALID_PIPELINES = ('check_whitelisted', 'check_blacklisted',
            'check_total_max')
    VALID_FIELDS = ('name', 'type', 'required', 'regex', 'min', 'max')
    CONFIG = {
        'subject': 'Confirm your email',
        'msg': 'Click in this link for validate your email: ',
        'mail_from': 'authapi@agoravoting.com',
        'give_perms': {'object_type': 'Vote', 'perms': ['create',] },
    }
    PIPELINES = {
        "register-pipeline": [],
        "validate-pipeline": [],
        "login-pipeline": []
    }

    def census(self, ae, request):
        req = json.loads(request.body.decode('utf-8'))
        for r in req:
            user = random_username()
            mail_to = r.get('email')

            try:
                u = User(username=user, email=mail_to)
                u.save()
                u.userdata.event = ae
                u.userdata.status = 'pen'
                u.userdata.save()
                acl = ACL(user=request.user.userdata, object_type='UserData', perm='edit', object_id=u.pk)
                acl.save()
            except:
                data = {'status': 'nok', 'msg': 'user already exist'}
                return data
        data = {'status': 'ok'}
        return data

    def register(self, ae, request):
        req = json.loads(request.body.decode('utf-8'))
        mail_to = req.get('email')
        user = random_username()
        pwd = req.get('password')

        try:
            u = User(username=user, email=mail_to)
            u.set_password(pwd)
            u.save()
            acl = ACL(user=u.userdata, object_type='UserData', perm='edit', object_id=u.pk)
            acl.save()
        except:
            data = {'status': 'nok', 'msg': 'user already exist'}
            return data

        conf = ae.auth_method_config
        subject = conf.get('subject')
        mail_from = conf.get('mail_from')

        code = random_code(64, ascii_letters+digits)
        valid_link = request.build_absolute_uri(
                '/api/authmethod/email/validate/%d/%s/' % (u.pk,  code))
        msg = conf.get('msg') + valid_link

        u.userdata.event = ae
        u.userdata.metadata = json.dumps({
                'email': mail_to,
                'code': code,
                'email_verified': False
        })
        u.userdata.save()

        send_email.apply_async(args=[subject, msg, mail_from, (mail_to,)])
        data = {'status': 'ok'}
        return data


    def validate(self, ae, request):
        req = json.loads(request.body.decode('utf-8'))
        userid = req['userid']
        code = req['code']

        u = User.objects.get(pk=userid)
        u_meta = json.loads(u.userdata.metadata)
        if constant_time_compare(u_meta.get('code'), code):
            u_meta.update({ 'email_verified': True })
            u.userdata.metadata = json.dumps(u_meta)
            u.userdata.save()

            # giving perms
            authconfig = u.userdata.event.auth_method_config
            give_perms = authconfig.get('give_perms')
            obj = give_perms.get('object_type')
            if give_perms.get('object_id') == 'all':
                object_id = None
            else:
                object_id = u.userdata.event.id
            for perm in give_perms.get('perms'):
                acl = ACL(user=u.userdata, object_type=obj, perm=perm,
                        object_id=object_id)
                acl.save()
            data = {'status': 'ok', 'username': u.username}
            status = 200
        else:
            data = {'status': 'nok'}
            status = 400
        return data

    def login_error(self):
        d = {'status': 'nok'}
        return d

    def login(self, event, data):
        d = {'status': 'ok'}
        email = data['email']
        pwd = data['password']

        try:
            u = User.objects.get(email=email, userdata__event=event)
        except:
            return self.login_error()

        u_meta = json.loads(u.userdata.metadata)
        if not u.check_password(pwd) or not u_meta.get('email_verified'):
            return self.login_error()

        d['auth-token'] = genhmac(settings.SHARED_SECRET, u.username)
        return d

register_method('email', Email)
