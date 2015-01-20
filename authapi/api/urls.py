from django.conf.urls import patterns, url, include

urlpatterns = patterns('',
    url(r'^authmethod/(.*)/', 'authmethods.views.view'),

    url(r'^acl/$', 'api.views.acl', name='acl'),
    url(r'^acl/(?P<username>\w+)/(?P<object_type>\w+)/(?P<perm>\w+)/(?P<object_id>\w+)?$', 'api.views.acl', name='acl'),
    url(r'^acl/mine/$', 'api.views.aclmine', name='aclmine'),

    url(r'^auth-event/$', 'api.views.authevent', name='authevent'),
    url(r'^auth-event/(?P<pk>\d+)/$', 'api.views.authevent', name='authevent'),
    url(r'^auth-event/(?P<pk>\d+)/census/$', 'api.views.census', name='census'),
    url(r'^auth-event/(?P<pk>\d+)/login/$', 'api.views.login', name='login'),
    url(r'^auth-event/(?P<pk>\d+)/register/$', 'api.views.register', name='register'),
    url(r'^auth-event/(?P<pk>\d+)/validate/$', 'api.views.validate', name='validate'),
    url(r'^auth-event/module/$', 'api.views.authevent_module', name='authevent_module'),
    url(r'^auth-event/module/(?P<name>[-\w]+)/$', 'api.views.authevent_module', name='authevent_module'),

    url(r'^available-packs/$', 'api.views.available_packs', name='available_packs'),
    url(r'^available-payment-methods/$', 'api.views.available_payment_methods', name='available_payment_methods'),
    url(r'^captcha/', include('captcha.urls')),
    url(r'^get-perms/', 'api.views.getperms', name='getperms'),
    url(r'^test/', 'api.views.test', name='test'),

    url(r'^user/(?P<pk>\d+)/$', 'api.views.user', name='user'),
    url(r'^user/add-credits/$', 'api.views.creditsaction', name='creditsaction'),
)
