# This file is part of authapi.
# Copyright (C) 2014-2016  Agora Voting SL <agora@agoravoting.com>

# authapi is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License.

# authapi  is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.

# You should have received a copy of the GNU Affero General Public License
# along with authapi.  If not, see <http://www.gnu.org/licenses/>.

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
