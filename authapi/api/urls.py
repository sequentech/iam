from django.conf.urls import patterns, url

urlpatterns = patterns('',
    url(r'^authmethod/(.*)/', 'authmethods.views.view'),

    url(r'^test/', 'api.views.test', name='test'),
    url(r'^login/', 'api.views.login', name='login'),
    url(r'^get-perms/', 'api.views.getperms', name='getperms'),
    url(r'^auth-event/$', 'api.views.authevent', name='authevent'),
    url(r'^auth-event/module/$', 'api.views.authevent_module', name='authevent_module'),
    url(r'^auth-event/module/(?P<name>[-\w]+)/$', 'api.views.authevent_module', name='authevent_module'),
    url(r'^auth-event/(?P<pk>\d+)/$', 'api.views.authevent', name='authevent'),
    url(r'^acl/$', 'api.views.acl', name='acl'),
    url(r'^acl/(?P<username>\w+)/(?P<object_type>\w+)/(?P<perm>\w+)/(?P<object_id>\w+)?$', 'api.views.acl', name='acl'),
    url(r'^acl/mine/$', 'api.views.aclmine', name='aclmine'),
)
