from django.db import models
from django.contrib.auth.models import User

from jsonfield import JSONField

from django.dispatch import receiver
from django.db.models.signals import post_save


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

    def has_perms(self, permission):
        return self.acls.filter(perm=permission).count()

@receiver(post_save, sender=User)
def create_user_data(sender, instance, created, *args, **kwargs):
    ud, _ = UserData.objects.get_or_create(user=instance)
    ud.save()


class ACL(models.Model):
    user = models.ForeignKey(UserData, related_name="acls")
    perm = models.CharField(max_length=255)
