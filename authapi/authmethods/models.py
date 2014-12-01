from django.db import models


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
    created = models.CharField(max_length=255)
    modified = models.CharField(max_length=255)
