# This file is part of authapi.
# Copyright (C) 2016  Agora Voting SL <agora@agoravoting.com>

# authapi is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License.

# authapi  is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.

# You should have received a copy of the GNU Affero General Public License
# along with authapi.  If not, see <http://www.gnu.org/licenses/>.

from django.core.management.base import BaseCommand, CommandError
from django.contrib.auth.models import User
from api.models import AuthEvent, ACL
import json

def insert_or_update(cls, kwargs):
    l = cls.objects.filter(**kwargs)
    if len(l) == 0:
        obj = ACL(**kwargs)
        obj.save()

class Command(BaseCommand):
    help = 'updates valid dnis'

    def add_arguments(self, parser):
        parser.add_argument(
            'dnispath',
            nargs=1,
            type=str)
        parser.add_argument(
            'eventid',
            nargs=1,
            type=str)

    def handle(self, *args, **options):
        dnis_text = json.loads(open(options['dnispath'][0], 'r').read())
        dnis = [dni.strip() for dni in dnis_text.split("\n")]
        event_id = int(options['event_id'][0])
        event = AuthEvent.objects.get(pk=event_id)
        dni_field = [
            field
            for field in event.extra_fields
            if field.name == 'dni'
        ][0]

        dni_field.regex = "^(%s)$" % ("|".join(dnis))
        event.save()