# Development

This is a simple django application so to modify this project you can
follow the django doc.

## Auth methods

The auth api supports multiple auth methods. An auth method can add custom
django views and should provide a login method.

### Adding a new auth method

Add a new auth method is simple. You only need to add a new python module
with a class in it.

The module should be inside the authapi/authmethods/ folder and this module
name should starts with an 'm\_', for example if we want to add a DNIe auth
method we can add the module authapi/authmethods/m\_dnie.py.

To register the new method you should call the register\_method function,
for example:

```python
from . import register_method
from utils import genhmac
from django.conf import settings

class DNIe:
    def login(self, data):
        d = {'status': 'ok'}
        username = data['username']
        dnidata = data['dnidata']

        verified = func_that_verify_the_dni(username, dnidata)

        if verified:
            d['auth-token'] = genhmac(settings.SHARED_SECRET, username)
            return d
        else:
            d = {'status': 'nok'}
            return d

register_method('dnie', DNIe)
```

### Custom views in custom auth method

You can add custom views to auth methods to make validations, user
creation, etc. for example:

```python
from django.conf.urls import patterns, url
from django.http import HttpResponse
from api.models import User
import json


def verifydni(request, dni):
    req = json.loads(request.body.decode('utf-8'))

    data = {'status': 'ok'}
    u = User(username=randomusername())
    u.save()
    u.userdata.metadata['dni'] = dni
    u.userdata.metadata['dni_verified'] = True
    u.userdata.metadata['dni_data'] = req['dnidata']
    u.save()

    # giving perms
    acl = ACL(user=u.userdata, perm='vote')
    acl.save()

    data['username'] = u.username

    jsondata = json.dumps(data)
    return HttpResponse(jsondata, content_type='application/json')


class DNIe:
    def login(self, data):
        ...

    views = patterns('',
        url(r'^verify/(\w+)$', verifydni),
    )

register_method('dnie', DNIe)
```

Whit this code the following url will exists:

 * /api/authmethod/dnie/verify/123456789X/
