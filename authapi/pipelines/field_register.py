from contracts import CheckException
from pipelines import PipeReturnvalue
from pipelines.base import Pipe
from authmethods.utils import dni_constraint


class DniChecker(Pipe):
    '''
    Checks dni
    '''
    @staticmethod
    def execute(data, config):
        if not dni_constraint(data['request'].get('dni', '')):
            raise CheckException(
                key='invalid-dni',
                context=data['request'].get('dni', ''))

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
            "user": "foo",
            "password": "bar"
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
                'type': str
              }
            ]
          },
          {
            'check': 'switch-contract-by-dict-key',
            'switch-key': 'mode',
            'contract-key': 'mode-config',
            'contracts': {
              # start LUGO
              'lugo': [
                {
                  'check': 'dict-keys-exact',
                  'keys': ['baseurl', 'user', 'password']
                },
                {
                  'check': 'index-check-list',
                  'index': 'baseurl',
                  'check-list': [
                    {
                      'check': 'isinstance',
                      'type': str
                    },
                    {
                      'check': 'length',
                      'range': [1, 512]
                    }
                  ]
                },
                {
                  'check': 'index-check-list',
                  'index': 'user',
                  'check-list': [
                    {
                      'check': 'isinstance',
                      'type': str
                    },
                    {
                      'check': 'length',
                      'range': [1, 255]
                    }
                  ]
                },
                {
                  'check': 'index-check-list',
                  'index': 'password',
                  'check-list': [
                    {
                      'check': 'isinstance',
                      'type': str
                    },
                    {
                      'check': 'length',
                      'range': [4, 255]
                    }
                  ]
                }
              ]
              # end LUGO
            }
          }
        ], config)

    @staticmethod
    def execute(data, config):
        # TODO check with census via DNI instead of checking DNI number
        if not dni_constraint(data['request'].get('dni', '')):
            data['active'] = False
            # TODO: send message saying that user registration is being checked

Pipe.register_pipe(ExternalAPICheckAndSave, 'register-pipeline')
