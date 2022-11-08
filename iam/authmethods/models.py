# This file is part of iam.
# Copyright (C) 2014-2020  Sequent Tech Inc <legal@sequentech.io>

# iam is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License.

# iam  is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.

# You should have received a copy of the GNU Affero General Public License
# along with iam.  If not, see <http://www.gnu.org/licenses/>.

import uuid
from django.db import models
from jsonfield import JSONField

from api.models import UserData


class ColorList(models.Model):
    ACTION_BLACKLIST = 'blacklist'
    ACTION_WHITELIST = 'whitelist'
    ACTION = (
        ('black', ACTION_BLACKLIST),
        ('white', ACTION_WHITELIST),
    )
    KEY_IP = 'ip'
    KEY_TLF = 'tlf'

    key = models.CharField(max_length=3, default=KEY_IP)
    value = models.CharField(max_length=255)
    action = models.CharField(max_length=255, choices=ACTION, default="black")
    created = models.DateTimeField(auto_now_add=True)
    auth_event_id = models.IntegerField()

class Message(models.Model):
    ip = models.CharField(max_length=15)
    tlf = models.CharField(max_length=20)
    created = models.DateTimeField(auto_now_add=True)
    auth_event_id = models.IntegerField()

class MsgLog(models.Model):
    authevent_id = models.IntegerField()
    receiver = models.CharField(max_length=255)
    msg = JSONField()
    created = models.DateTimeField(auto_now_add=True)

class Connection(models.Model):
    ip = models.CharField(max_length=15)
    tlf = models.CharField(max_length=20)
    created = models.DateTimeField(auto_now_add=True)
    auth_event_id = models.IntegerField()

class Code(models.Model):
    user = models.ForeignKey(UserData, models.CASCADE, related_name="codes")
    code = models.CharField(max_length=64)
    created = models.DateTimeField(auto_now_add=True)
    auth_event_id = models.IntegerField()
    is_enabled = models.BooleanField(default=True)

class OneTimeLink(models.Model):
    '''
    Stores information related to "secret" One Time Links (OTLs) that are used
    to obtain voter authentication codes.
    '''
    # The OTL will be valid only for this user 
    user = models.ForeignKey(
        UserData,
        models.CASCADE,
        related_name="one_time_links"
    )

    # The OTL will be valid only for this auth event
    auth_event_id = models.IntegerField()

    # stores the secret that is part of the one time link and makes it secure
    # because it's difficult to guess. See for security 
    # https://stackoverflow.com/questions/41505448/is-python-uuid-uuid4-strong-enough-for-password-reset-links
    secret = models.UUIDField(default=uuid.uuid4, editable=False, db_index=True)
    
    # Time at which this link was created. If a user has multiple enabled links,
    # only the last one should work.
    created = models.DateTimeField(auto_now_add=True)

    # time at which the link was used - the link should be used only once so
    # when used, it should be disabled
    used = models.DateTimeField(
        auto_now=False,
        auto_now_add=False,
        null=True,
        blank=True
    )

    # is the link enabled? it could be manually disabled
    is_enabled = models.BooleanField(default=True)
