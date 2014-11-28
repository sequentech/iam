import json
from . import register_method
from utils import genhmac
from django.conf import settings
from django.contrib.auth.models import User


class PWD:
    def login_error(self):
        d = {'status': 'nok'}
        return d
    def login(self, data):
        d = {'status': 'ok'}
        msg = data['username']
        pwd = data['password']

        try:
            u = User.objects.get(username=msg)
        except:
            return self.login_error()

        if not u.check_password(pwd):
            return self.login_error()

        d['auth-token'] = genhmac(settings.SHARED_SECRET, msg)
        return d


register_method('user-and-password', PWD)
