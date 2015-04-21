from contracts import CheckException
from pipelines import PipeReturnvalue
from pipelines.base import Pipe
from authmethods.utils import dni_constraint

class DniChecker(Pipe):
    '''
    Checks dni
    '''
    def execute(self, data, config):
        if not dni_constraint(data):
          raise CheckException(key="invalid-dni", context=data)

Pipe.register_pipe(DniChecker, 'register-pipeline')
