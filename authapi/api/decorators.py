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

from django.contrib.auth.models import User
from django.http import HttpResponseForbidden
import json
import functools
from utils import verifyhmac, HMACToken
from django.conf import settings

def get_auth_key(request):
    key = request.META.get('HTTP_AUTHORIZATION', None)
    if not key:
        key = request.META.get('HTTP_AUTH', None)
        if not key:
            key = request.META.get('HTTP_HTTP_AUTH', None)
    return key

def get_login_user(request):
    key = get_auth_key(request)
    hmac_token = None

    if not key:
        return None, dict(error_codename="empty_hmac"), hmac_token

    try:
      hmac_token = HMACToken(key)
      if not hmac_token.check_expiration(settings.TIMEOUT):
          return None, dict(error_codename="expired_hmac_key"), hmac_token

      v = verifyhmac(settings.SHARED_SECRET, key, settings.TIMEOUT, at=hmac_token)

      if not v:
          return None, dict(error_codename="invalid_hmac"), hmac_token

      user = User.objects.get(username=hmac_token.get_userid())
    except:
        return None, dict(error_codename="invalid_hmac_userid"), hmac_token

    return user, None, hmac_token


class login_required(object):

    def __init__(self, func):
        self.func = func
        functools.wraps(self.func)(self)

    def __call__(self, request, *args, **kwargs):
        user, error, _ = get_login_user(request)
        if not user:
            return HttpResponseForbidden(json.dumps(error))

        request.user = user

        return self.func(request, *args, **kwargs)
