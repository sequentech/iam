import json
from . import register_method
from utils import genhmac
from django.conf import settings


class PWD:
    def login(data):
        # Fake login, always logins
        # TODO checks agains the django db
        d = {'status': 'ok'}
        msg = data['username']
        d['auth-token'] = genhmac(settings.SHARED_SECRET, msg.encode('utf-8'))
        return d


register_method('user-and-password', PWD)
