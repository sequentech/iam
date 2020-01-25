# This file is part of authapi.
# Copyright (C) 2014-2020  Agora Voting SL <contact@nvotes.com>

# authapi is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License.

# authapi  is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.

# You should have received a copy of the GNU Affero General Public License
# along with authapi.  If not, see <http://www.gnu.org/licenses/>.

from django import forms
from django.contrib import admin
from api.models import AuthEvent, UserData, ACL, User
from authmethods.models import Message, ColorList, Code, Connection
from authmethods import METHODS
from django.contrib.auth.admin import UserAdmin


class AuthEventAdminForm(forms.ModelForm):
    class Meta:
        model = AuthEvent
        fields = ('auth_method', 'census', 'auth_method_config', 'extra_fields',
                'status')
        choices = []
        for k in METHODS.keys():
            choices.append((k, k + ': ' + METHODS.get(k).DESCRIPTION))

        widgets = {
                'auth_method':
                forms.Select(attrs={'obj':'str'}, choices=choices),
        }

class AuthEventAdmin(admin.ModelAdmin):
    form = AuthEventAdminForm
    list_display = ('id', 'auth_method', 'status')
    list_filter = ('auth_method', 'status')
    search_fields = ('id',)

    def get_form(self, request, obj=None, **kwargs):
        choices = []
        for k in METHODS.keys():
            choices.append((k, k + ': ' + METHODS.get(k).DESCRIPTION))
        AuthEventAdminForm.Meta.widgets['auth_method'] = forms.Select(attrs={'obj':'str'}, choices=choices)
        f = super(AuthEventAdmin, self).get_form(request, obj, **kwargs)
        return f


class UserDataAdmin(admin.ModelAdmin):
    list_display = ('user', 'status')
    search_fields = ('user__username', 'status', 'metadata', 'user__email', 'tlf')


class ACLAdmin(admin.ModelAdmin):
    list_display = ('user', 'perm', 'object_type', 'object_id')
    list_filter = ('perm', 'object_type')
    search_fields = ('user__user__username', 'user__user__email', 'user__metadata',
                     'perm', 'object_type', 'object_id')


class ColorListAdmin(admin.ModelAdmin):
    pass


class MessageAdmin(admin.ModelAdmin):
    pass


class CodeAdmin(admin.ModelAdmin):
    list_display = ('auth_event_id', 'user', 'code', 'created')
    date_hierarchy = 'created'


class ConnectionAdmin(admin.ModelAdmin):
    pass

class UserDataInline(admin.StackedInline):
    model = UserData

class CustomUserAdmin(UserAdmin):
    def change_view(self, request, obj_id):
        # Has required fields and don't let us to modify users in the admin
        #self.inlines=[UserDataInline,]
        return super(CustomUserAdmin, self).change_view(request, obj_id)

    def add_view(self, request):
        self.inlines=[]
        return super(CustomUserAdmin, self).add_view(request)


admin.site.unregister(User)
admin.site.register(User, CustomUserAdmin)

admin.site.register(AuthEvent, AuthEventAdmin)
admin.site.register(UserData, UserDataAdmin)
admin.site.register(ACL, ACLAdmin)
admin.site.register(ColorList, ColorListAdmin)
admin.site.register(Message, MessageAdmin)
admin.site.register(Code, CodeAdmin)
admin.site.register(Connection, ConnectionAdmin)
