from django.conf.urls import patterns, url

urlpatterns = patterns('',
    url(r'^authmethod/(.*)/', 'authmethods.views.view'),

    url(r'^test/', 'api.views.test', name='test'),
    url(r'^login/', 'api.views.login', name='login'),
    url(r'^get-perms/', 'api.views.getperms', name='getperms'),
    url(r'^auth-event/$', 'api.views.authevent', name='authevent'),
    url(r'^auth-event/(?P<pk>\d+)/$', 'api.views.authevent', name='authevent'),
    url(r'^acl/$', 'api.views.acl', name='acl'),
    url(r'^acl/(?P<userid>\d+)/(?P<object_type>\w+)/(?P<perm>\w+)/$', 'api.views.acl', name='acl'),
)
