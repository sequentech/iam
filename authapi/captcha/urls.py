from django.conf.urls import patterns, url
from .decorators import captcha_required
from api.views import test

urlpatterns = patterns('',
    url(r'^new/', 'captcha.views.new_captcha', name='new_captcha'),
    url(r'^test/', captcha_required(test), name='test_captcha'),
)

