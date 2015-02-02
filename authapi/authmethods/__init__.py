import os
from importlib import import_module
from authmethods.utils import have_captcha
from captcha.decorators import valid_capcha


METHODS = {}

def check_config(config, auth_method):
    """ Check config when create auth-event. """
    return METHODS[auth_method].check_config(config)


def auth_census(event, data):
    return METHODS[event.auth_method].census(event, data)


def auth_register(event, data):
    if have_captcha(event):
        if not valid_capcha(data):
            return {'status': 'nok', 'msg': 'Invalid captcha'}
    return METHODS[event.auth_method].register(event, data)


def auth_authenticate(event, data):
    if event == 0:
        return METHODS['user-and-password'].authenticate(event, data)
    if have_captcha(event, 'authenticate'):
        if not valid_capcha(data):
            return {'status': 'nok', 'msg': 'Invalid captcha'}
    return METHODS[event.auth_method].authenticate(event, data)


def register_method(name, klass):
    METHODS[name] = klass()


files = os.listdir(os.path.dirname(__file__))
for f in files:
    if f.startswith('m_'):
        import_module('authmethods.' + f.split('.')[0])
