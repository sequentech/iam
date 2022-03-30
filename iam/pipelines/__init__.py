from enum import Enum, unique

@unique
class PipeReturnvalue(Enum):
    '''
    The values used as return values in the execution of pipes in a pipeline.
    If a pipe return CONTINUE, then the next pipe is executed. If a pipe returns
    STOP, no other pipe is executed.
    '''
    CONTINUE = 0
    STOP = 1

class PipeNotFoundException(Exception):
    pass
