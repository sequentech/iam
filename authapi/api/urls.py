# This file is part of authapi.
# Copyright (C) 2014-2016  Agora Voting SL <agora@agoravoting.com>

# authapi is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License.

# authapi  is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.

# You should have received a copy of the GNU Affero General Public License
# along with authapi.  If not, see <http://www.gnu.org/licenses/>.

from django.conf.urls import url, include
from django.conf import settings
from api import views
from authmethods import views as authmethods_views

urlpatterns = [
    url(r'^acl/$', views.acl, name='acl'),
    url(r'^acl/(?P<username>\w+)/(?P<object_type>\w+)/(?P<perm>\w+)/$', views.acl, name='acl'),
    url(r'^acl/(?P<username>\w+)/(?P<object_type>\w+)/(?P<perm>\w+)/(?P<object_id>\w+)/$', views.acl, name='acl'),
    url(r'^acl/mine/$', views.aclmine, name='aclmine'),

    url(r'^auth-event/$', views.authevent, name='authevent'),
    url(r'^auth-event/(?P<pk>\d+)/$', views.authevent, name='authevent'),
    url(r'^auth-event/(?P<pk>\d+)/callback/$', views.callback, name='callback'),
    url(r'^auth-event/(?P<pk>\d+)/csv-stats/$', views.csv_stats, name='csv_stats'),
    url(r'^auth-event/(?P<pk>\d+)/activity/$', views.activity, name='activity'),
    url(r'^auth-event/(?P<pk>\d+)/census/$', views.census, name='census'),
    url(r'^auth-event/(?P<pk>\d+)/census/delete/$', views.census_delete, name='census_delete'),
    url(r'^auth-event/(?P<pk>\d+)/census/activate/$', views.census_activate, name='census_activate'),
    url(r'^auth-event/(?P<pk>\d+)/census/deactivate/$', views.census_deactivate, name='census_deactivate'),
    url(r'^auth-event/(?P<pk>\d+)/ping/$', views.ping, name='ping'),
    url(r'^auth-event/(?P<pk>\d+)/ballot-box/$', views.ballot_box, name='ballot_box'),
    url(r'^auth-event/(?P<pk>\d+)/ballot-box/(?P<ballot_box_pk>\d+)/delete/$', views.ballot_box, name='ballot_box'),
    url(r'^auth-event/(?P<pk>\d+)/register/$', views.register, name='register'),
    url(r'^auth-event/(?P<pk>\d+)/authenticate/$', views.authenticate, name='authenticate'),
    url(r'^auth-event/(?P<pk>\d+)/successful_login/(?P<uid>\w+)$', views.successful_login, name='successful_login'),
    url(r'^auth-event/(?P<pk>\d+)/resend_auth_code/$', views.resend_auth_code, name='resend_auth_code'),
    url(r'^auth-event/(?P<pk>\d+)/census/send_auth/$', views.census_send_auth, name='census_send_auth'),
    url(r'^auth-event/(?P<pk>\d+)/(?P<status>(notstarted|started|stopped))/$', views.ae_status, name='ae_status'),
    url(r'^auth-event/module/$', views.authevent_module, name='authevent_module'),
    url(r'^auth-event/module/(?P<name>[-\w]+)/$', views.authevent_module, name='authevent_module'),

    url(r'^auth-event/(?P<pk>\d+)/census/img/(?P<uid>\w+)/$', views.get_img, name='get_img'),

    url(r'^get-perms/', views.getperms, name='getperms'),

    url(r'^user/$', views.user, name='user'),
    url(r'^user/(?P<pk>\d+)/$', views.user, name='user'),
    url(r'^user/auth-event/$', views.user_auth_event, name='user_auth_event'),
    url(r'^user/reset-pwd/$', views.reset_pwd, name='reset_pwd'),
    url(r'^user/extra/$', views.user_extra, name='user_extra'),
    url(r'^user/draft/$', views.draft, name='draft'),
    url(r'^user/deregister/$', views.deregister, name='deregister'),

    url(r'^authmethod/(.*)/', authmethods_views.view),

    url(r'^legal/(?P<pk>\d+)/$', views.legal, name='legal'),
]


if settings.ENABLE_CAPTCHA:
    urlpatterns += [
        url(r'^captcha/', include('captcha.urls')),
    ]

for plugin in settings.PLUGINS:
    urlpatterns += [
        url(r'^%s/' % plugin, include('%s.urls' % plugin)),
    ]
