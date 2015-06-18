from pipelines.base import Pipe
from pipelines.field_register import CanonizeDni

Pipe.register_pipe(CanonizeDni, 'authenticate-pipeline')
