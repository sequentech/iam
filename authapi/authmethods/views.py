from . import METHODS
from django.http import HttpResponseNotFound
from django.core import urlresolvers


class Resolver(urlresolvers.RegexURLResolver):
    def __init__(self, method):
        super(Resolver, self).__init__('', '')
        self.method = method

    @property
    def url_patterns(self):
        return self.method.views


def view(request, path):
    spath = path.split('/')
    method, path = spath[0], '/'.join(spath[1:])
    if method in METHODS:
        m = METHODS[method]
        if hasattr(m, 'views'):
            resolver = Resolver(m)
            r = resolver.resolve(path)
            return r.func(request, *r.args, **r.kwargs)

    return HttpResponseNotFound('<h1>Page not found</h1>')
