from django.conf.urls import patterns, url, include
from django.conf import settings

urlpatterns = patterns('',
    url(r'^acl/$', 'api.views.acl', name='acl'),
    url(r'^acl/(?P<username>\w+)/(?P<object_type>\w+)/(?P<perm>\w+)/$', 'api.views.acl', name='acl'),
    url(r'^acl/(?P<username>\w+)/(?P<object_type>\w+)/(?P<perm>\w+)/(?P<object_id>\w+)/$', 'api.views.acl', name='acl'),
    url(r'^acl/mine/$', 'api.views.aclmine', name='aclmine'),

    url(r'^auth-event/$', 'api.views.authevent', name='authevent'),
    url(r'^auth-event/(?P<pk>\d+)/$', 'api.views.authevent', name='authevent'),
    url(r'^auth-event/(?P<pk>\d+)/census/$', 'api.views.census', name='census'),
    url(r'^auth-event/(?P<pk>\d+)/ping/$', 'api.views.ping', name='ping'),
    url(r'^auth-event/(?P<pk>\d+)/register/$', 'api.views.register', name='register'),
    url(r'^auth-event/(?P<pk>\d+)/authenticate/$', 'api.views.authenticate', name='authenticate'),
    url(r'^auth-event/(?P<pk>\d+)/census/send_auth/$', 'api.views.census_send_auth', name='census_send_auth'),
    url(r'^auth-event/(?P<pk>\d+)/(?P<status>(notstarted|started|stopped))/$', 'api.views.ae_status', name='ae_status'),
    url(r'^auth-event/module/$', 'api.views.authevent_module', name='authevent_module'),
    url(r'^auth-event/module/(?P<name>[-\w]+)/$', 'api.views.authevent_module', name='authevent_module'),

    url(r'^get-perms/', 'api.views.getperms', name='getperms'),
    url(r'^test/', 'api.views.test', name='test'),

    url(r'^user/$', 'api.views.user', name='user'),
    url(r'^user/(?P<pk>\d+)/$', 'api.views.user', name='user'),
    url(r'^user/auth-event/$', 'api.views.user_auth_event', name='user_auth_event'),
)


if settings.ENABLE_CAPTCHA:
    urlpatterns += patterns('',
        url(r'^captcha/', include('captcha.urls')),
    )

for plugin in settings.PLUGINS:
    urlpatterns += patterns('',
        url(r'^%s/' % plugin, include('%s.urls' % plugin)),
    )
