# This file is part of authapi.
# Copyright (C) 2014-2020  Agora Voting SL <contact@nvotes.com>

# authapi is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License.

# authapi  is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.

# You should have received a copy of the GNU Affero General Public License
# along with authapi.  If not, see <http://www.gnu.org/licenses/>.

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
