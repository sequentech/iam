import json
from django.db import models
from django.contrib.auth.models import User

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
            'users': self.userdata.count(),
            'created': (self.created.isoformat()
                        if hasattr(self.created, 'isoformat')
                        else self.created)
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
                ]
            })
        else:
            d.update({
                'extra_fields': self.extra_fields,
                'auth_method_config': self.auth_method_config,
                'auth_method_stats': {
                    self.auth_method: Code.objects.filter(auth_event_id=self.id).count()
                }
            })

        return d

    def serialize_restrict(self):
        '''
        Used to serialize public data that anyone should be able to see about an
        AuthEvent.
        '''
        return self.serialize(restrict=True)

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
    metadata = JSONField(default="{}", blank=True, null=True)
    status = models.CharField(max_length=255, choices=STATUSES, default="act")

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
        }
        if self.user.email:
            d['email'] = self.user.email
        if self.tlf:
            d['tlf'] = self.tlf
        return d

    def serialize_data(self):
        d = self.serialize()
        del d['username']
        if self.metadata:
            d.update(json.loads(self.metadata))
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
