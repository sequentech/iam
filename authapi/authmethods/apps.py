import os
from importlib import import_module
from django.apps import AppConfig


class AuthmethodsConfig(AppConfig):
    name = 'authmethods'

    def ready(self):
        files = os.listdir(os.path.dirname(__file__))
        for f in files:
            if f.startswith('m_'):
                import_module('authmethods.' + f.split('.')[0])

