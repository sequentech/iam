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


def census_send_auth_task(pk, ip, config=None, userids=None, **kwargs):
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

    extend_errors = plugins.call("extend_send_message", e, len(census), kwargs)
    if extend_errors:
        # Only can return one error at least for now
        return extend_errors[0]
    send_codes.apply_async(args=[census, ip, config])
