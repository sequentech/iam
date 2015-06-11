import string
from authmethods.utils import dni_constraint


def lugo(arg):
    ident = ''
    l = None

    if not arg:
        return ident, l

    if arg[0].upper() in string.ascii_uppercase:
        # is NIE
        ident = arg[0:-1]
        l = arg[-1]
    elif dni_constraint(arg):
        # is DNI
        ident = '0' + arg[0:-1]
        l = arg[-1]
    else:
        # passport?
        ident = arg

    return ident, l
