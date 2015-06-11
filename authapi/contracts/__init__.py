from json import JSONEncoder


class CheckException(Exception):
  def __init__(self, key, context):
      self.data = {"key": key, "context": context}


class JSONContractEncoder(JSONEncoder):
    encoded_types = [
      int,
      str,
      float,
      complex,
      bool,
      bytes,
      bytearray,
      list,
      tuple,
      dict
    ]
    def default(self, obj):
        if type(obj) not in self.encoded_types:
            return str(type(obj))
        else:
            return JSONEncoder.default(self, obj)
