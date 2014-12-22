from django.db import models
from django.contrib.auth.models import User

from jsonfield import JSONField

from django.dispatch import receiver
from django.db.models.signals import post_save
from django.db.models import Q


class AuthEvent(models.Model):
    name = models.CharField(max_length=255)
    auth_method = models.CharField(max_length=255)
    auth_method_config = JSONField()
    metadata = JSONField()

    def serialize(self):
        d = {
            'id': self.id,
            'name': self.name,
            'auth_method': self.auth_method,
            'auth_method_config': self.auth_method_config,
            'metadata': self.metadata,
        }
        return d

    def serialize_restrict(self):
        d = {
            'id': self.id,
            'name': self.name,
            'auth_method': self.auth_method,
            'metadata': self.metadata,
        }
        return d


STATUSES = (
    ('act', 'Active'),
    ('pen', 'Pending'),
    ('dis', 'Disabled'),
)

class UserData(models.Model):
    user = models.OneToOneField(User, related_name="userdata")
    event = models.ForeignKey(AuthEvent, related_name="userdata", null=True)
    metadata = JSONField(default="{}")
    status = models.CharField(max_length=255, choices=STATUSES, default="act")

    def get_perms(self, obj, permission, object_id=None):
        q = Q(object_type=obj, perm=permission)
        q2 = Q(object_id=object_id)
        if not object_id:
            q2 |= Q(object_id='')

        return self.acls.filter(q & q2)

    def has_perms(self, obj, permission, object_id=None):
        return bool(self.get_perms(obj, permission, object_id).count())

    def __str__(self):
        return self.user.username

@receiver(post_save, sender=User)
def create_user_data(sender, instance, created, *args, **kwargs):
    ud, _ = UserData.objects.get_or_create(user=instance)
    ud.save()


class ACL(models.Model):
    user = models.ForeignKey(UserData, related_name="acls")
    perm = models.CharField(max_length=255)
    object_type = models.CharField(max_length=255, null=True)
    object_id = models.CharField(max_length=255, null=True, blank=True)

    def serialize(self):
        d = {
            'perm': self.perm,
            'object_type': self.object_type or '',
            'object_id': self.object_id or '',
        }
        return d
