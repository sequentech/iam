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
        return None

    v = verifyhmac(settings.SHARED_SECRET, key, settings.TIMEOUT)

    if not v:
        return None

    try:
        at = AuthToken(key)
        user = User.objects.get(username=at.userid)
    except:
        return None

    return user


class login_required(object):

    def __init__(self, func):
        self.func = func
        functools.wraps(self.func)(self)

    def __call__(self, request, *args, **kwargs):
        user = get_login_user(request)
        if not user:
            return HttpResponseForbidden('Invalid auth token')

        request.user = user

        return self.func(request, *args, **kwargs)
