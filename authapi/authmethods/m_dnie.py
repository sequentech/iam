# This file is part of authapi.
# Copyright (C) 2014-2016  Agora Voting SL <agora@agoravoting.com>

# authapi is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License.

# authapi  is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.

# You should have received a copy of the GNU Affero General Public License
# along with authapi.  If not, see <http://www.gnu.org/licenses/>.

import json
from . import register_method
from utils import genhmac
from django.shortcuts import get_object_or_404, redirect
from django.conf import settings
from django.contrib.auth.models import User
from django.conf.urls import url
from django.db.models import Q
from django.http import Http404

from authmethods.utils import check_pipeline, give_perms

from api.models import AuthEvent

from utils import json_response


def testview(request):
    req = request.GET
    data = {'status': 'ok', 'method': 'GET'}

    cert = request.META.get('HTTP_SSL_CLIENT_CERT', '')
    rawcert = request.META.get('HTTP_SSL_CLIENT_RAW_CERT', '')

    data['verify'] = request.META.get('HTTP_SSL_VERIFY', '')
    data['cert'] = cert
    data['raw-cert'] = rawcert
    data['s-dn'] = request.META.get('HTTP_SSL_CLIENT_S_DN', '')
    data['i-dn'] = request.META.get('HTTP_SSL_CLIENT_I_DN', '')

    if cert:
        import OpenSSL.crypto as c
        cert = cert.replace('\t', '')
        parsed = c.load_certificate(c.FILETYPE_PEM, cert)
        data['parsed'] = dict((k.decode(), v.decode()) for k, v in parsed.get_subject().get_components())

    return json_response(data)


def dnie_auth(request, authid):
    ae = get_object_or_404(AuthEvent, pk=authid)
    if ae.auth_method != 'dnie':
        raise Http404

    req = request.GET
    data = {'status': 'ok', 'method': 'GET'}

    cert = request.META.get('HTTP_SSL_CLIENT_CERT', '')
    rawcert = request.META.get('HTTP_SSL_CLIENT_RAW_CERT', '')

    data['verify'] = request.META.get('HTTP_SSL_VERIFY', '')
    data['cert'] = cert
    data['raw-cert'] = rawcert
    data['s-dn'] = request.META.get('HTTP_SSL_CLIENT_S_DN', '')
    data['i-dn'] = request.META.get('HTTP_SSL_CLIENT_I_DN', '')

    if cert:
        import OpenSSL.crypto as c
        cert = cert.replace('\t', '')
        parsed = c.load_certificate(c.FILETYPE_PEM, cert)
        data['parsed'] = dict((k.decode(), v.decode()) for k, v in parsed.get_subject().get_components())

    # if the user doesn't exists, then we should give the perms

    #dni = X
    #ud = UserData.objects.filter(metadata__icontains=dni, event=ae)
    #if not ud:
    #    u = create_user(r, ae, True, request.user)
    #    u.userdata.metadata['dni'] = dni
    #    give_perms(u, ae)
    #else:
    #    u = ud.user

    #msg = ':'.join((u.username, "AuthEvent", ae.id, "vote"))
    #khmac = genhmac(settings.SHARED_SECRET, msg)
    #head, path = khmac.split(";")[1]
    #array = path.split("/")
    #hash, msg = array[0], array[1]
    #baseurl = "https://agora.dev/#"
    #url = baseurl + "/%d/vote/%s/%s" % (ae.id, hash, msg)

    #return redirect(url)

    return json_response(data)


class DNIE:
    DESCRIPTION = 'Register using dnie. '
    CONFIG = {}
    PIPELINES = {
        'give_perms': [
            {'object_type': 'UserData', 'perms': ['edit',], 'object_id': 'UserDataId' },
            {'object_type': 'AuthEvent', 'perms': ['vote',], 'object_id': 'AuthEventId' }
        ],
        "register-pipeline": [],
        "authenticate-pipeline": []
    }
    USED_TYPE_FIELDS = ['dni']
    dni_definition = { "name": "dni", "type": "text", "required": True, "min": 2, "max": 200, "required_on_authentication": True }


    def authenticate_error(self):
        d = {'status': 'nok'}
        return d

    def authenticate(self, ae, request):
        d = {'status': 'ok'}
        return d

    def check_config(self, config):
        return ''

    def census(self, ae, request):
        req = json.loads(request.body.decode('utf-8'))
        validation = req.get('field-validation', 'enabled') == 'enabled'

        msg = ''
        current_dnis = []
        for r in req.get('census'):
            dni = r.get('dni')
            if isinstance(dni, str):
                dni = dni.strip()
            msg += check_field_type(self.dni_definition, dni)
            if validation:
                msg += check_field_type(self.dni_definition, email)
                msg += check_field_value(self.dni_definition, email)
            msg += check_fields_in_request(r, ae, 'census', validation=validation)
            if validation:
                msg += exist_user(r, ae)
                if dni in current_dnis:
                    msg += "DNI %s repeat in this census." % dni
                current_dnis.append(dni)
            else:
                if msg:
                    msg = ''
                    continue
                exist = exist_user(r, ae)
                if exist and not exist.count('None'):
                    continue
                used = r.get('status', 'registered') == 'used'
                u = create_user(r, ae, used, request.user)
                give_perms(u, ae)
        if msg and validation:
            data = {'status': 'nok', 'msg': msg}
            return data

        if validation:
            for r in req.get('census'):
                used = r.get('status', 'registered') == 'used'
                u = create_user(r, ae, used, request.user)
                give_perms(u, ae)
        return {'status': 'ok'}


    views = [
        url(r'^testcert$', testview),
        url(r'^auth/(\d+)$', dnie_auth),
    ]


register_method('dnie', DNIE)
