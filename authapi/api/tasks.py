from django.conf import settings
from django.core.mail import send_mail
from django.shortcuts import get_object_or_404

import plugins
from authmethods.sms_provider import SMSProvider
from utils import send_codes


def census_send_auth_task(pk, ip, config=None, userids=None):
    """
    Send an auth token to census
    """
    from .models import AuthEvent, ACL

    e = get_object_or_404(AuthEvent, pk=pk)
    if e.status != "started":
        print("event is stopped, ignoring request..")
        return

    census = []
    if userids is None:
        census = ACL.objects.filter(perm="vote", object_type="AuthEvent", object_id=str(pk))
        census = [i.user.user.id for i in census]
    else:
        census = userids

    if e.auth_method == "sms":
      msg = plugins.call("extend_send_sms", e, len(census))
      if msg:
          return msg
    send_codes.apply_async(args=[census, ip, config])
