from django.conf import settings


def call(func, *args):
    res = []
    for plugin in settings.PLUGINS:
        views = __import__(plugin + '.views', fromlist=[''])
        try:
            method = getattr(views, func)
            aux_res = method(*args)
            if aux_res:
                res.append(aux_res)
        except:
            continue
    return res
