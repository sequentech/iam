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

import json
from django.db import models
from django.core.validators import MaxValueValidator, MinValueValidator
from django.contrib.auth.models import User

from django.contrib.postgres import fields
from jsonfield import JSONField

from django.dispatch import receiver
from django.db.models.signals import post_save
from django.db.models import Q
from django.conf import settings
from utils import genhmac

CENSUS = (
    ('close', 'Close census'),
    ('open', 'Open census'),
)

AE_STATUSES = (
    ('notstarted', 'not-started'),
    ('started', 'started'),
    ('stopped', 'stopped'),
)


class AuthEvent(models.Model):
    '''
    An Auth Event is an object used for authentication and authorization. It's
    an abstract interface that anyone should be able to use, although the main
    use case is that each AuthEvent corresponds with an Election, in principle
    it could be used for any kind of authentication and authorization event.
    '''

    auth_method = models.CharField(max_length=255)
    census = models.CharField(max_length=5, choices=CENSUS, default="close")
    auth_method_config = JSONField()
    extra_fields = JSONField(blank=True, null=True)
    status = models.CharField(max_length=15, choices=AE_STATUSES, default="notstarted")
    created = models.DateTimeField(auto_now_add=True)
    real = models.BooleanField(default=False)
    admin_fields = JSONField(blank=True, null=True)

    # 0 means any number of logins is allowed
    num_successful_logins_allowed = models.IntegerField(
        default=True,
        validators=[
            MinValueValidator(0)
        ]
    )
    based_in = models.IntegerField(null=True) # auth_event_id

    def serialize(self, restrict=False):
        '''
        Used to serialize data when the user has priviledges to see all the data
        (for example, admins). This includes auth method config, stats, and
        access to private extra_fields.
        '''
        # auth codes sent by authmethod
        from authmethods.models import Code

        d = {
            'id': self.id,
            'auth_method': self.auth_method,
            'census': self.census,
            'users': self.len_census(),
            'created': (self.created.isoformat()
                        if hasattr(self.created, 'isoformat')
                        else self.created),
            'real': self.real,
            'based_in': self.based_in,
            'num_successful_logins_allowed': self.num_successful_logins_allowed
        }

        def none_list(e):
          if e is None:
              return []
          return e

        if restrict:
            d.update({
                'extra_fields': [
                    f for f in none_list(self.extra_fields)
                        if not f.get('private', False)
                ],
                'admin_fields': [
                    f for f in none_list(self.admin_fields)
                        if not f.get('private', True)
                ]
            })
        else:
            d.update({
                'extra_fields': self.extra_fields,
                'auth_method_config': self.auth_method_config,
                'auth_method_stats': {
                    self.auth_method: Code.objects.filter(auth_event_id=self.id).count()
                },
                'admin_fields': self.admin_fields,
            })

        return d

    def serialize_restrict(self):
        '''
        Used to serialize public data that anyone should be able to see about an
        AuthEvent.
        '''
        return self.serialize(restrict=True)

    def get_census_query(self):
        '''
        returns a query with all the census of this event.
        '''
        return ACL.objects.filter(
            object_type='AuthEvent',
            perm='vote',
            object_id=self.id)
     
    def get_owners(self):
        '''
        Returns the list of people that can edit this event
        '''
        return ACL.objects.filter(
            object_type='AuthEvent',
            perm='edit',
            object_id=self.id)

    def len_census(self):
        return self.get_census_query().count()

    def __str__(self):
        return "%s - %s" % (self.id, self.census)


STATUSES = (
    ('act', 'Active'),
    ('pen', 'Pending'),
    ('dis', 'Disabled'),
)


class UserData(models.Model):
    '''
    This is a class attached one to one to a user, that stores extra user
    information.  We store some user authentication and status information
    like telephone number (in case authentication works via telephone), and
    metadat, in this model.

    In authapi each user is created in relation with a specific authevent.
    '''
    user = models.OneToOneField(User, related_name="userdata")
    event = models.ForeignKey(AuthEvent, related_name="userdata", null=True)
    tlf = models.CharField(max_length=20, blank=True, null=True)
    metadata = fields.JSONField(default=dict(), blank=True, null=True, db_index=True)
    status = models.CharField(max_length=255, choices=STATUSES, default="act", db_index=True)

    def get_perms(self, obj, permission, object_id=0):
        q = Q(object_type=obj, perm=permission)
        q2 = Q(object_id=object_id)
        if not object_id:
            q2 |= Q(object_id='')

        return self.acls.filter(q & q2)

    def has_perms(self, obj, permission, object_id=0):
        return bool(self.get_perms(obj, permission, object_id).count())

    def serialize(self):
        d = {
            'username': self.user.username,
            'active': self.user.is_active,
        }
        if self.user.email:
            d['email'] = self.user.email
        if self.tlf:
            d['tlf'] = self.tlf
        return d

    def serialize_metadata(self):
        d = {}
        if self.metadata:
            if type(self.metadata) == str:
                metadata = json.loads(self.metadata)
                if type(metadata) == str:
                    metadata = json.loads(metadata)
            else:
                metadata = self.metadata
            d.update(metadata)
        return d

    def serialize_data(self):
        d = self.serialize()
        del d['username']
        if self.metadata:
            if type(self.metadata) == str:
                metadata = json.loads(self.metadata)
                if type(metadata) == str:
                    metadata = json.loads(metadata)
            else:
                metadata = self.metadata
            d.update(metadata)
        return d

    def __str__(self):
        return self.user.username

@receiver(post_save, sender=User)
def create_user_data(sender, instance, created, *args, **kwargs):
    ud, _ = UserData.objects.get_or_create(user=instance)
    ud.save()


class ACL(models.Model):
    '''
    The permission model is based in Access Control Lists, and this data model
    stores these lists in the database. A permission specifies things like:
    "user <foo> has permission <permission> over object_id <1> of object_type <bar>".

    This allows for a very flexible permission system. The idea is that these
    permissions can be used outside authapi through HMAC tokens that contain
    authenticated permission information.
    '''
    user = models.ForeignKey(UserData, related_name="acls")
    perm = models.CharField(max_length=255)
    object_type = models.CharField(max_length=255, blank=True, null=True)
    object_id = models.CharField(max_length=255, default=0)
    created = models.DateTimeField(auto_now_add=True)

    def serialize(self):
        d = {
            'perm': self.perm,
            'object_type': self.object_type or '',
            'object_id': self.object_id or '',
            'created': self.created.isoformat() if hasattr(self.created, 'isoformat') else self.created
        }
        return d

    def get_hmac(self):
        msg = ':'.join((self.user.user.username, self.object_type, str(self.object_id), self.perm))
        khmac = genhmac(settings.SHARED_SECRET, msg)
        return khmac

    def __str__(self):
        return "%s - %s - %s - %s" % (self.user.user.username, self.perm,
                                      self.object_type, self.object_id)

class SuccessfulLogin(models.Model):
    '''
    Each successful login attempt is recorded with an object of this type, and
    usually triggered by a explicit call to /authevent/<ID>/successful_login
    '''
    user = models.ForeignKey(UserData, related_name="successful_logins")
    created = models.DateTimeField(auto_now_add=True)
    # when counting the number of successful logins, only active ones count
    is_active = models.BooleanField(default=True)

    def __str__(self):
        return "%d: %s - %s" % (self.id, self.user.user.username, str(self.created))
