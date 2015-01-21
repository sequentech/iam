import os
from importlib import import_module


METHODS = {}


def auth_census(event, data):
    return METHODS[event.auth_method].census(event, data)


def auth_register(event, data):
    return METHODS[event.auth_method].register(event, data)


def auth_validate(event, data):
    return METHODS[event.auth_method].validate(event, data)


def auth_login(event, data):
    if event == 0:
        return METHODS['user-and-password'].login(event, data)
    return METHODS[event.auth_method].login(event, data)


def register_method(name, klass):
    METHODS[name] = klass()


files = os.listdir(os.path.dirname(__file__))
for f in files:
    if f.startswith('m_'):
        import_module('authmethods.' + f.split('.')[0])
