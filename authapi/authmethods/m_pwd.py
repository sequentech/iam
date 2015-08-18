import json
from . import register_method
from utils import genhmac
from django.conf import settings
from django.contrib.auth.models import User
from django.conf.urls import patterns, url
from django.db.models import Q

from utils import json_response


def testview(request, param):
    data = {'status': 'ok'}
    return json_response(data)


class PWD:
    DESCRIPTION = 'Register using user and password. '
    CONFIG = {}
    PIPELINES = {
        "register-pipeline": [],
        "authenticate-pipeline": []
    }

    def authenticate_error(self):
        d = {'status': 'nok'}
        return d

    def authenticate(self, ae, request):
        d = {'status': 'ok'}
        req = json.loads(request.body.decode('utf-8'))
        email = req.get('email', '')
        pwd = req.get('password', '')

        try:
            u = User.objects.get(email=email, userdata__event=ae, is_active=True)
        except:
            return self.authenticate_error()

        if not u.check_password(pwd):
            return self.authenticate_error()

        d['username'] = u.username
        d['auth-token'] = genhmac(settings.SHARED_SECRET, u.username)

        # add redirection
        auth_action = ae.auth_method_config['config']['authentication-action']
        if auth_action['mode'] == 'go-to-url':
            data['redirect-to-url'] = auth_action['mode-config']['url']
        return d

    views = patterns('',
        url(r'^test/(\w+)$', testview),
    )


register_method('user-and-password', PWD)
