from django.conf import settings


def call(func, *args):
    '''
    Method to implement extension points in the code of authapi. It will
    call the corresponding function by name (func) with the given args in each
    plugin.

    Note: it does not mask exceptions: if the plugin function raises an
    exception, it will raise the exception.
    '''
    res = []
    for plugin in settings.PLUGINS:
        views = __import__(plugin + '.views', fromlist=[''])

        # check that this plugin has this extension point, or continue otherwise
        if not hasattr(views, func):
            continue
        method = getattr(views, func)

        aux_res = method(*args)
        if aux_res:
            res.append(aux_res)
    return res
