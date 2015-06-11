import os
from importlib import import_module


METHODS = {}

def check_config(config, auth_method):
    """ Check config when create auth-event. """
    return METHODS[auth_method].check_config(config)


def auth_census(event, data):
    return METHODS[event.auth_method].census(event, data)


def auth_register(event, data):
    return METHODS[event.auth_method].register(event, data)


def auth_authenticate(event, data):
    if event == 0:
        return METHODS['user-and-password'].authenticate(event, data)
    return METHODS[event.auth_method].authenticate(event, data)


def auth_resend_auth_code(event, data):
    return METHODS[event.auth_method].resend_auth_code(event, data)

def register_method(name, klass):
    METHODS[name] = klass()


files = os.listdir(os.path.dirname(__file__))
for f in files:
    if f.startswith('m_'):
        import_module('authmethods.' + f.split('.')[0])
