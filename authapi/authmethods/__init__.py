import os
from importlib import import_module


METHODS = {}


def auth_login(method, data):
    return METHODS[method].login(data)


def validate_register(event, data):
    return METHODS[event.auth_method].register(event, data)


def validate_validate(event, data):
    return METHODS[event.auth_method].validate(event, data)


def register_method(name, klass):
    METHODS[name] = klass()


files = os.listdir(os.path.dirname(__file__))
for f in files:
    if f.startswith('m_'):
        import_module('authmethods.' + f.split('.')[0])
