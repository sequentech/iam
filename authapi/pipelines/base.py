import functools
from collections import defaultdict
from enum import Enum, unique
from contracts.base import check_contract
from contracts import CheckException
from pipelines import PipeReturnvalue, PipeNotFoundException

DEFAULT_CHECKER_CONF = {
  "max-num-pipes": 10,
}


class Pipe(object):
    '''
    Base class for generating a pipe for a pipeline
    '''
    pipeline_pipes = defaultdict(dict)

    @classmethod
    def register_pipe(cls, cls2, pipeline_name):
        Pipe.pipeline_pipes[pipeline_name][cls2.__name__]=cls2

    @classmethod
    def get_pipes(cls, pipeline_name):
        '''
        Returns the dictionary of valid pipes classes in a pipeline by name
        '''
        return Pipe.pipeline_pipes[pipeline_name]

    @staticmethod
    def check_config(config):
        '''
        Implement this method to check that the input data is valid. It should
        be as strict as possible. By default, config is checked to be empty.
        '''
        check_contract([{
            'check': 'lambda',
            'lambda': lambda data: data is None,
            'help': 'check config is empty'
        }], config)

    @staticmethod
    def execute(data, config, name, ae):
        '''
        Executes the pipe. Should return a PipeReturnValue. "data" is the value
        that one pipe passes to the other, and config is the specific config of
        a pipe.
        '''
        pass

def check_pipeline_conf(pipeline_conf, name, checker_conf=DEFAULT_CHECKER_CONF):
    '''
    Checks the pipeline_conf is valid
    '''
    pipeline_pipes = Pipe.get_pipes(name)
    return check_contract([
      {
        'check': "isinstance",
        'type': list
      },
      {
        'check': 'length',
        'range': [0, checker_conf['max-num-pipes']]
      },
      {
        'check': "iterate-list",
        'check-list': [
          {
            'check': 'isinstance',
            'type': list
          },
          {
            'check': 'length',
            'range': [2,2]
          },
          {
            'check': 'index-check-list',
            'index': 0,
            'check-list': [
              {
                'check': 'isinstance',
                'type': str
              },
              {
                'check': 'length',
                'range': [1,255]
              },
            ]
          },
          {
            'check': 'lambda',
            'lambda': lambda data: data[0] in pipeline_pipes.keys(),
            'help': 'check the pipe is valid'
          },
          {
            'check': 'lambda',
            'lambda': lambda data: pipeline_pipes[data[0]].check_config(data[1]),
            'help': 'check the pipe conf is valid'
          }
        ]
      }
    ], pipeline_conf)

def execute_pipeline(pipeline_conf, name, data, field, ae):
    '''
    Executes the pipeline with the given name, starting with the initial data.

    * name is a string, with the name of the pipe
    * this function is agnostic on the format of data, but this is the
      data passes as a reference from pipe to pipe.
    * pipeline_confis a list of items, each item being itself a tuple with
      two things: the pipe name and the pipe configuration.
    '''
    valid_pipes = Pipe.get_pipes(name)

    for pipe_name, pipe_conf in pipeline_conf:
        ret = valid_pipes[pipe_name].execute(data=data, config=pipe_conf, name=field, ae=ae)
        if ret != PipeReturnvalue.CONTINUE:
            return ret

    return PipeReturnvalue.CONTINUE
