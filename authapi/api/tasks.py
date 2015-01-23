from django.conf import settings
from djcelery import celery
from django.core.mail import send_mail
from django.shortcuts import get_object_or_404

from authmethods.sms_provider import SMSProvider
from .models import AuthEvent, ACL
from utils import send_code

@celery.task
def census_send_auth_task(pk, templ):
    """
    Send an auth token to census
    """

    e = get_object_or_404(AuthEvent, pk=pk)
    if e.status != "started":
        print("event is stopped, ignoring request..")
        return

    census = ACL.objects.filter(perm="vote", object_type="AuthEvent", object_id=str(pk))

    for user in census:
        send_code(user, templ)
