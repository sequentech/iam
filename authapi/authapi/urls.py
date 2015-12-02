from django.conf.urls import include, url
from django.contrib import admin
from django.conf import settings

urlpatterns = [
    url(r'^api/', include('api.urls')),
]

if settings.DEBUG:
    urlpatterns += [
      url(r'^admin/', include(admin.site.urls)),
    ]
