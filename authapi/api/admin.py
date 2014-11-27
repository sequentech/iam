from django.contrib import admin
from api.models import AuthEvent, UserData, ACL

# Register your models here.

class AuthEventAdmin(admin.ModelAdmin):
    pass


class UserDataAdmin(admin.ModelAdmin):
    pass


class ACLAdmin(admin.ModelAdmin):
    pass


admin.site.register(AuthEvent, AuthEventAdmin)
admin.site.register(UserData, UserDataAdmin)
admin.site.register(ACL, ACLAdmin)
