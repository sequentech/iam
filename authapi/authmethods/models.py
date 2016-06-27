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
    user = models.ForeignKey(UserData, related_name="codes")
    code = models.CharField(max_length=64)
    created = models.DateTimeField(auto_now_add=True)
    auth_event_id = models.IntegerField()
