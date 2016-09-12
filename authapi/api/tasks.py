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

from django.conf import settings
from django.core.mail import send_mail
from django.shortcuts import get_object_or_404

import plugins
from authmethods.sms_provider import SMSProvider
from utils import send_codes


def census_send_auth_task(pk, ip, config=None, userids=None, auth_method=None, **kwargs):
    """
    Send an auth token to census
    """
    from .models import AuthEvent, ACL

    e = get_object_or_404(AuthEvent, pk=pk)
    if e.status != "started":
        print("event is stopped, ignoring request..")
        return

    # If the auth_method is not set, use the default authmethod for the election
    if auth_method is None:
        auth_method = e.auth_method

    new_census = []
    if userids is None:
        new_census = ACL.objects.filter(perm="vote", object_type="AuthEvent", object_id=str(pk))
    else:
        new_census = userids

    census = []
    if e.auth_method == auth_method:
        census = [i.user.user.id for i in new_census]
    else:
        for item in new_census:
           if "sms" == auth_method and item.user.tlf:
               census.append(item.user.user.id)
           elif "email" == auth_method and item.user.user.email:
               census.append(item.user.user.id)
    

    extend_errors = plugins.call("extend_send_message", e, len(census), kwargs)
    if extend_errors:
        # Only can return one error at least for now
        return extend_errors[0]
    send_codes.apply_async(args=[census, ip, auth_method, config])
