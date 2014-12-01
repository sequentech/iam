import os
from importlib import import_module
from django.contrib.auth.models import User
from random import choice
from string import ascii_lowercase, digits
from uuid import uuid4


METHODS = {}


def auth_login(method, data):
    return METHODS[method].login(data)


def register_method(name, klass):
    METHODS[name] = klass()


def random_username():
    username = uuid4()
    try:
        User.objects.get(username=username)
        return random_username()
    except User.DoesNotExist:
        return username;

def random_code(length=16, chars=ascii_lowercase+digits):
    return ''.join([choice(chars) for i in range(length)])
    return code;


files = os.listdir(os.path.dirname(__file__))
for f in files:
    if f.startswith('m_'):
        import_module('authmethods.' + f.split('.')[0])
