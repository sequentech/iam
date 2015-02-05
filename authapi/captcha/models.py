import os
from django.db import models
from django.conf import settings


class Captcha(models.Model):
    code = models.CharField(max_length=10)
    path = models.CharField(max_length=100)
    challenge = models.CharField(max_length=4)
    used = models.BooleanField(default=False)
    created = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.code

    def delete(self):
        image_path = settings.STATIC_ROOT + '/captcha/'
        path = str(os.path.join(image_path, '%s.png' % self.code))
        os.unlink(path)
        super(Captcha, self).delete()
