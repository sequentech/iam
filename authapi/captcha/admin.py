from django.contrib import admin
from .models import Captcha


class CaptchaAdmin(admin.ModelAdmin):
    pass

admin.site.register(Captcha, CaptchaAdmin)
