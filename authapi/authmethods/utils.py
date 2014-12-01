from django.contrib.auth.models import User
from random import choice
from string import ascii_lowercase, digits
from uuid import uuid4


def random_username():
    username = uuid4()
    try:
        User.objects.get(username=username)
        return random_username()
    except User.DoesNotExist:
        return username;


def random_code(length=16, chars=ascii_lowercase+digits):
    return ''.join([choice(chars) for i in range(length)])
    return code;
