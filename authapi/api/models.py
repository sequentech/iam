from django.db import models
from django.contrib.auth.models import User

from jsonfield import JSONField


class AuthEvent(models.Model):
    name = models.CharField(max_length=255)
    auth_method = models.CharField(max_length=255)
    auth_method_config = JSONField()
    metadata = JSONField()


class UserData(models.Model):
    user = models.OneToOneField(User, related_name="admin")
    event = models.ForeignKey(AuthEvent, related_name="admin", null=True)
    metadata = JSONField()
    status = models.CharField(max_length=255) 


class ACL(models.Model):
    user = models.ForeignKey(UserData, related_name="admin")
    perm = models.CharField(max_length=255)
