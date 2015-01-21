from django.contrib.auth.models import User
from django.http import HttpResponseForbidden
import json
import functools
from utils import verifyhmac, AuthToken
from django.conf import settings


class login_required(object):

    def __init__(self, func):
        self.func = func
        functools.wraps(self.func)(self)

    def __call__(self, request, *args, **kwargs):
        key = request.META.get('HTTP_AUTHORIZATION', None)
        if not key:
            key = request.META.get('HTTP_AUTH', None)
            if not key:
                key = request.META.get('HTTP_HTTP_AUTH', None)

        if not key:
            return HttpResponseForbidden('Invalid auth token')

        v = verifyhmac(settings.SHARED_SECRET, key, settings.TIMEOUT)

        if not v:
            return HttpResponseForbidden('Invalid auth token')

        try:
            at = AuthToken(key)
            user = User.objects.get(username=at.userid)
        except:
            return HttpResponseForbidden('Invalid auth token')

        request.user = user

        return self.func(request, *args, **kwargs)
