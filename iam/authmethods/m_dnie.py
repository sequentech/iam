# This file is part of iam.
# Copyright (C) 2014-2020  Sequent Tech Inc <legal@sequentech.io>

# iam is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License.

# iam  is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.

# You should have received a copy of the GNU Affero General Public License
# along with iam.  If not, see <http://www.gnu.org/licenses/>.

import json
import logging
from . import register_method
from django.shortcuts import get_object_or_404, redirect
from django.conf.urls import url
from django.http import Http404

from authmethods.utils import (
    check_pipeline,
    give_perms,
    stack_trace_str
)

from api.models import AuthEvent

from utils import json_response

from contracts.base import check_contract, JsonTypeEncoder
from contracts import CheckException

LOGGER = logging.getLogger('iam')

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
    #baseurl = "https://sequent.dev/#"
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
    MANDATORY_FIELDS = dict(
        types=['dni'],
        names=[]
    )
    dni_definition = { "name": "dni", "type": "text", "required": True, "min": 2, "max": 200, "required_on_authentication": True }

    CONFIG_CONTRACT = [
      {
        'check': 'isinstance',
        'type': dict
      },
      {
          'check': 'index-check-list',
          'index': 'msg_i18n',
          'optional': True,
          'check-list': [
              {
                  'check': 'isinstance',
                  'type': dict
              },
              {   # keys are strings
                  'check': 'lambda',
                  'lambda': lambda d: all([isinstance(k, str) for k in d.keys()])
              },
              {   # values are strings
                  'check': 'lambda',
                  'lambda': lambda d: all([isinstance(k, str) and len(k) > 0 and len(k) <= 200 for k in d.values()])
              },
          ]
      },
      {
          'check': 'index-check-list',
          'index': 'subject_i18n',
          'optional': True,
          'check-list': [
              {
                  'check': 'isinstance',
                  'type': dict
              },
              {   # keys are strings
                  'check': 'lambda',
                  'lambda': lambda d: all([isinstance(k, str) for k in d.keys()])
              },
              {   # values are strings
                  'check': 'lambda',
                  'lambda': lambda d: all([isinstance(k, str) and len(k) > 0 and len(k) <= 1024 for k in d.values()])
              },
          ]
      },
      {
        'check': 'index-check-list',
        'index': 'html_message_i18n',
        'optional': True,
        'check-list': [
            {
                'check': 'isinstance',
                'type': dict
            },
            {   # keys are strings
                'check': 'lambda',
                'lambda': lambda d: all([isinstance(k, str) for k in d.keys()])
            },
            {   # values are strings
                'check': 'lambda',
                'lambda': lambda d: all([isinstance(k, str) and len(k) > 0 and len(k) <= 5000 for k in d.values()])
            },
        ]
      }
    ]

    def error(
            self, msg, auth_event=None, error_codename=None, internal_error=None
        ):
        data = {'status': 'nok', 'msg': msg, 'error_codename': error_codename}
        LOGGER.error(\
            "DNIE.error\n"\
            f"internal_error '{internal_error}'\n"\
            f"error_codename '{error_codename}'\n"\
            f"returning error '{data}'\n"\
            f"auth_event '{auth_event}'\n"\
            f"Stack trace: \n{stack_trace_str()}"
        )
        return data

    def authenticate_error(self):
        d = {'status': 'nok'}
        return d

    def authenticate(self, ae, request):
        d = {'status': 'ok'}
        return d

    def check_config(self, config, data):
        """ Check config when create auth-event. """
        if config is None:
            return ''
        try:
            check_contract(self.CONFIG_CONTRACT, config)
            LOGGER.debug(\
                "Dnie.check_config success\n"\
                "config '%r'\n"\
                "returns ''\n"\
                "Stack trace: \n%s",\
                config, stack_trace_str())
            return ''
        except CheckException as e:
            LOGGER.error(\
                "Dnie.check_config error\n"\
                "error '%r'\n"\
                "config '%r'\n"\
                "Stack trace: \n%s",\
                e.data, config, stack_trace_str())
            return json.dumps(e.data, cls=JsonTypeEncoder)

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
