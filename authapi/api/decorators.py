from django.contrib.auth.models import User
from django.http import HttpResponseForbidden
import json
import functools
from utils import verifyhmac, AuthToken
from django.conf import settings


def get_login_user(request):
    key = request.META.get('HTTP_AUTHORIZATION', None)
    if not key:
        key = request.META.get('HTTP_AUTH', None)
        if not key:
            key = request.META.get('HTTP_HTTP_AUTH', None)

    if not key:
        return None, dict(error_codename="invalid_hmac_data")

    try:
      at = HMACToken(msg)
      if not at.check_expiration(settings.TIMEOUT):
          return None, dict(error_codename="expired_hmac_key")

      v = verifyhmac(settings.SHARED_SECRET, key, settings.TIMEOUT, at=at)

      if not v:
          return None, dict(error_codename="invalid_hmac")

      user = User.objects.get(username=at.userid)
    except:
        return None, dict(error_codename="invalid_hmac_data")

    return user, None


class login_required(object):

    def __init__(self, func):
        self.func = func
        functools.wraps(self.func)(self)

    def __call__(self, request, *args, **kwargs):
        user, error = get_login_user(request, at)
        if not user:
            return HttpResponseForbidden(json.dumps(error))

        request.user = user

        return self.func(request, *args, **kwargs)
