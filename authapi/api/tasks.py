from django.conf import settings
from djcelery import celery
from django.contrib.auth.models import User
from django.core.mail import send_mail
from django.shortcuts import get_object_or_404

from authmethods.sms_provider import SMSProvider
from .models import AuthEvent, ACL
from utils import send_code

@celery.task
def census_send_auth_task(pk, msg=None, userids=None):
    """
    Send an auth token to census
    """

    e = get_object_or_404(AuthEvent, pk=pk)
    if e.status != "started":
        print("event is stopped, ignoring request..")
        return

    census = []
    if userids is None:
        census = ACL.objects.filter(perm="vote", object_type="AuthEvent", object_id=str(pk))
        census = [i.user.user for i in census]
    else:
        for ids in userids:
            census.append(get_object_or_404(User, pk=ids))

    for user in census:
        send_code(user, msg)
