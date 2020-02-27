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

from time import time
from logging import getLogger


class LoggingMiddleware(object):
    def __init__(self, get_response):
        self.logger = getLogger('authapi.request')
        self.get_response = get_response

    def __call__(self, request):
        # Code to be executed for each request before
        # the view (and later middleware) are called.
        timer = time()

        response = self.get_response(request)

        # Code to be executed for each request/response after
        # the view is called.
        if response.status_code >= 200 and response.status_code < 400:
            return response

        self.logger.info(
            '[%s] %s %s (%.1fs)\n\trequest=%s\n\tresponse=%s',
            response.status_code,
            request.method,
            request.get_full_path(),
            time() - self.timer,
            request.body,
            response.content
        )
        return response
