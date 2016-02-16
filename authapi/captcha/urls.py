from django.conf.urls import url
from .decorators import captcha_required
from captcha import views

urlpatterns = [
    url(r'^new/', views.new_captcha, name='new_captcha'),
]

