import os
from importlib import import_module
from django.contrib.auth.models import User
from random import choice
from string import ascii_lowercase, digits


METHODS = {}


def auth_login(method, data):
    return METHODS[method].login(data)


def register_method(name, klass):
    METHODS[name] = klass()


def random_username(length=16, chars=ascii_lowercase+digits, split=0, delimiter='-'):
    username = ''.join([choice(chars) for i in range(length)])
    if split:
        username = delimiter.join([username[start:start+split] for start in range(0, len(username), split)])
    try:
        User.objects.get(username=username)
        return generate_random_username(length=length, chars=chars, split=split, delimiter=delimiter)
    except User.DoesNotExist:
        return username;


files = os.listdir(os.path.dirname(__file__))
for f in files:
    if f.startswith('m_'):
        import_module('authmethods.' + f.split('.')[0])
