from contracts import CheckException
from pipelines import PipeReturnvalue
from pipelines.base import Pipe
from authmethods.utils import dni_constraint
from authmethods.utils import exist_user
from pipelines import external_soap
from pipelines import argfuncs
from utils import send_msg
from contracts.base import check_contract


class CanonizeDni(Pipe):
    '''
    Canonize dni
    '''
    @staticmethod
    def execute(data, config, name, ae):
        data['request'][name] = data['request'][name].upper()
        return PipeReturnvalue.CONTINUE

Pipe.register_pipe(CanonizeDni, 'register-pipeline')


class DniChecker(Pipe):
    '''
    Checks dni
    '''
    @staticmethod
    def execute(data, config, name, ae):
        if not dni_constraint(data['request'].get(name, '')):
            raise CheckException(
                key='invalid-dni',
                context=data['request'].get(name, ''))
        return PipeReturnvalue.CONTINUE

Pipe.register_pipe(DniChecker, 'register-pipeline')


class ExternalAPICheckAndSave(Pipe):
    '''
    Looksup the field value into an external API. Save the lookup-status
    '''

    @staticmethod
    def check_config(config):
        '''
        Implement this method to check that the input data is valid. Example
        config:
        {
          "mode": "lugo",
          "mode-config": {
            "baseurl": "http://foo/conecta/services",
            "query":"obterPersoa",
            "check_field":"empadroado",
            "store_fields":["nomeCompreto"],
            "inactive_subject": "",
            "inactive_msg": "",
            "arg_func": "lugo"
          }
        }
        '''
        check_contract([
          {
            'check': 'isinstance',
            'type': dict
          },
          {
            'check': 'dict-keys-exact',
            'keys': ['mode', 'mode-config']
          },
          {
            'check': 'index-check-list',
            'index': 'mode',
            'check-list': [
              {
                'check': 'isinstance',
                'type': str
              },
              {
                'check': 'lambda',
                'lambda': lambda d: d in ['lugo']
              }
            ]
          },
          {
            'check': 'index-check-list',
            'index': 'mode-config',
            'check-list': [
              {
                'check': 'isinstance',
                'type': dict
              }
            ]
          },
          #{
          #  'check': 'switch-contract-by-dict-key',
          #  'switch-key': 'mode',
          #  'contract-key': 'mode-config',
          #  'contracts': {
          #    # start LUGO
          #    'lugo': [
          #      {
          #        'check': 'dict-keys-exact',
          #        'keys': ['baseurl', 'check_field', 'store_fields',
          #                 'query', 'arg_func',
          #                 'inactive_msg']
          #      },
          #      {
          #        'check': 'index-check-list',
          #        'index': 'baseurl',
          #        'check-list': [
          #          {
          #            'check': 'isinstance',
          #            'type': str
          #          },
          #          {
          #            'check': 'length',
          #            'range': [1, 512]
          #          }
          #        ]
          #      },
          #    ]
          #    # end LUGO
          #  }
          #}
        ], config)

    @staticmethod
    def get_external_data(data, config, name, ae):
        field = data['request'].get(name, '')

        args = getattr(argfuncs, config['arg_func'])(field)
        valid, custom_data = external_soap.api_call(args=args, **config)
        if not valid:
            data['request']['active'] = False
            if not exist_user(data['request'], ae):
                msg = config['inactive_msg']
                subject = config.get('inactive_subject', '')
                send_msg(data['request'], msg, subject)

        else:
            # Adding external data to the user metadata
            data['request']['external_data'] = custom_data

    @staticmethod
    def execute(data, config, name, ae):
        if config['mode'] == 'lugo':
            mconfig = config['mode-config']
            ExternalAPICheckAndSave.get_external_data(data, mconfig, name, ae)

        return PipeReturnvalue.CONTINUE

Pipe.register_pipe(ExternalAPICheckAndSave, 'register-pipeline')
