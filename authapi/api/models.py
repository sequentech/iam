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


class UserData(models.Model):
    user = models.OneToOneField(User, related_name="userdata")
    event = models.ForeignKey(AuthEvent, related_name="userdata", null=True)
    metadata = JSONField()
    status = models.CharField(max_length=255) 

@receiver(post_save, sender=User)
def create_user_data(sender, instance, created, *args, **kwargs):
    ud, _ = UserData.objects.get_or_create(user=instance)
    ud.save()


class ACL(models.Model):
    user = models.ForeignKey(UserData, related_name="admin")
    perm = models.CharField(max_length=255)
