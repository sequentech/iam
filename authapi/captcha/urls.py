from django.conf.urls import url
from .decorators import captcha_required
from api.views import test
from captcha import views

urlpatterns = [
    url(r'^new/', views.new_captcha, name='new_captcha'),
    url(r'^test/', captcha_required(test), name='test_captcha'),
]

