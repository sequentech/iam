from django import forms
from django.contrib import admin
from api.models import AuthEvent, UserData, ACL
from authmethods import METHODS

# Register your models here.

class AuthEventAdminForm(forms.ModelForm):
    class Meta:
        model = AuthEvent
        fields = ('name', 'auth_method', 'auth_method_config', 'metadata')
        choices = []
        for k in METHODS.keys():
            choices.append((k, k + ': ' + METHODS.get(k).DESCRIPTION))

        widgets = {
                'auth_method':
                forms.Select(attrs={'obj':'str'}, choices=choices),
        }

class AuthEventAdmin(admin.ModelAdmin):
    form = AuthEventAdminForm


class UserDataAdmin(admin.ModelAdmin):
    pass


class ACLAdmin(admin.ModelAdmin):
    pass


admin.site.register(AuthEvent, AuthEventAdmin)
admin.site.register(UserData, UserDataAdmin)
admin.site.register(ACL, ACLAdmin)
