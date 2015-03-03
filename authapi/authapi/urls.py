from django.conf.urls import patterns, include, url
from django.contrib import admin
from django.conf import settings

urlpatterns = patterns('',
    url(r'^api/', include('api.urls')),
)

if settings.DEBUG:
    urlpatterns += patterns('',
      url(r'^admin/', include(admin.site.urls)),
    )
