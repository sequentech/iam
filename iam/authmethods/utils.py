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

import hashlib
import json
import re
import os
import binascii
import logging
import urllib
from datetime import timedelta, datetime
from django.conf import settings
from django.contrib.auth.models import User, AnonymousUser
from django.contrib.auth.signals import user_logged_in
from django.utils import timezone
from django.db.models import Q

from .models import ColorList, Message, Code
from api.models import ACL
from captcha.models import Captcha
from captcha.decorators import valid_captcha
from contracts import CheckException, JSONContractEncoder
from utils import (
    ErrorCodes,
    json_response, 
    get_client_ip, 
    constant_time_compare,
    permission_required,
    generate_access_token_hmac,
    stack_trace_str,
    generate_code,
    send_codes,
    get_or_create_code,
    template_replace_data
)
from pipelines.base import execute_pipeline, PipeReturnvalue

LOGGER = logging.getLogger('iam')

EMAIL_RX = re.compile(
    r"(^[-!#$%&'*+/=?^_`{}|~0-9A-Z]+(\.[-!#$%&'*+/=?^_`{}|~0-9A-Z]+)*"  # dot-atom
    # quoted-string, see also http://tools.ietf.org/html/rfc2822#section-3.2.5
    r'|^"([\001-\010\013\014\016-\037!#-\[\]-\177]|\\[\001-\011\013\014\016-\177])*"'
    r')@((?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)$)'  # domain
    r'|\[(25[0-5]|2[0-4]\d|[0-1]?\d?\d)(\.(25[0-5]|2[0-4]\d|[0-1]?\d?\d)){3}\]$', re.IGNORECASE)  # literal form, ipv4 address (SMTP 4.1.3)

LETTER_RX = re.compile("[A-Z]", re.IGNORECASE)

DNI_ALLOWED_CHARS = "1234567890QWERTYUIOPASDFGHJKLZXCVBNM"
DNI_RE = re.compile(r"^([0-9]{1,8}[A-Z]|[LMXYZ][0-9]{1,7}[A-Z])$")

RET_PIPE_CONTINUE = 0


def error(message="", status=400, field=None, error_codename=None):
    ''' Returns an error message '''
    return json_response(status=400, message=message, field=field, error_codename=error_codename)


def random_username():
    # 30 hex digits random username
    username = binascii.b2a_hex(os.urandom(14)).decode('utf-8')
    try:
        User.objects.get(username=username)
        return random_username()
    except User.DoesNotExist:
        return username

def reset_voter_to_preregistration(user):
    '''
    Reset the voter to pre-registration status. Any extra_field set as fill_if_empty_on_registration True will be unset for the voter.
    '''
    changed = False
    for extra_field in user.userdata.event.extra_fields:
        if not extra_field.get('fill_if_empty_on_registration', False):
            continue
        name = extra_field['name']
        if (
            extra_field['type'] == 'email' and 
            type(user.email) == str and 
            len(user.email) > 0
        ):
            user.email = ''
            user.save()
        elif (
            extra_field['type'] == 'tlf' and
            type(user.userdata.tlf) == str and
            len(user.userdata.tlf) > 0
        ):
            changed = True
            user.userdata.tlf = ''
        elif name in user.userdata.metadata:
            changed = True
            del user.userdata.metadata[name]

    if changed:
        user.userdata.save()

def email_constraint(val):
    ''' check that the input is an email string '''
    if not isinstance(val, str):
        return False
    # Convert to punycode to allow tilde characters:
    # https://en.wikipedia.org/wiki/Punycode
    val = val.encode("idna").decode("ascii")
    return EMAIL_RX.match(val)

def date_constraint(val):
    ''' check that the input is a valid date YYYY-MM-DD '''

    try:
        datetime.strptime(val, '%Y-%m-%d')
    except:
        return False

    return True

# Pipeline
def check_tlf_whitelisted(data):
    ''' If tlf is whitelisted, accept '''
    if data.get('whitelisted', False) == True:
        return RET_PIPE_CONTINUE

    tlf = data['tlf']
    try:
        item = ColorList.objects.get(key=ColorList.KEY_TLF, value=tlf, auth_event_id=data['auth_event'].id)
        if item.action == ColorList.ACTION_WHITELIST:
            data['whitelisted'] = True
        else:
            data["tlf_blacklisted"] = True
    except:
        data["tlf_blacklisted"] = False
    return RET_PIPE_CONTINUE


def check_ip_whitelisted(data):
    '''
    If ip is whitelisted, then do not blacklist by ip in the following checkers
    '''
    if data.get('whitelisted', False) == True:
        return RET_PIPE_CONTINUE

    ip_addr = data['ip_addr']
    try:
        item = ColorList.objects.filter(key=ColorList.KEY_IP, value=ip_addr[:15],
                                        auth_event_id=data['auth_event'].id)
        for item in items:
            if item.action == ColorList.ACTION_WHITELIST:
                data['whitelisted'] = True
                break
    except:
        pass
    return RET_PIPE_CONTINUE


def check_tlf_blacklisted(data):
    ''' check if tlf is blacklisted '''
    if data.get('whitelisted', False) == True:
        return RET_PIPE_CONTINUE

    # optimization: if we have already gone through the whitelisting checking
    # we don't have do new queries
    if 'tlf_blacklisted' in data:
        if data['tlf_blacklisted']:
            return error("Blacklisted", error_codename="blacklisted")
        return RET_PIPE_CONTINUE

    tlf = data['tlf']
    try:
        item = ColorList.objects.filter(key=ColorList.KEY_TLF, value=tlf,
                action=ColorList.ACTION_BLACKLIST, auth_event_id=data['auth_event'].id)[0]
        return error("Blacklisted", error_codename="blacklisted")
    except:
        pass
    return RET_PIPE_CONTINUE


def check_ip_blacklisted(data):
    ''' check if tlf is blacklisted '''
    if data.get('whitelisted', False) == True:
        return RET_PIPE_CONTINUE

    # optimization: if we have already gone through the whitelisting checking
    # we don't have do new queries
    if 'ip_blacklisted' in data:
        if data['ip_blacklisted'] is True:
            return error("Blacklisted", error_codename="blacklisted")
        return RET_PIPE_CONTINUE

    ip_addr = data['ip_addr']
    try:
        item = ColorList.objects.filter(key=ColorList.KEY_IP, value=ip_addr[:15],
                action=ColorList.ACTION_BLACKLIST,
                auth_event_id=data['auth_event'].id)[0]
        return error("Blacklisted", error_codename="blacklisted")
    except:
        pass
    return RET_PIPE_CONTINUE


def check_tlf_total_max(data, **kwargs):
    '''
    if tlf has been sent >= MAX_SMS_LIMIT (in a period time) failed-sms
    in total->blacklist, error
    '''
    total_max = kwargs.get('max')
    period = kwargs.get('period', None)
    if data.get('whitelisted', False) == True:
        return RET_PIPE_CONTINUE

    ip_addr = data['ip_addr']
    tlf = data['tlf']
    if period:
        time_threshold = timezone.now() - timedelta(seconds=period)
        item = Message.objects.filter(tlf=tlf, created__gt=time_threshold,
                                      auth_event_id=data['auth_event'].id)
    else:
        item = Message.objects.filter(tlf=tlf, auth_event_id=data['auth_event'].id)

    if len(item) >= total_max:
        c1 = ColorList(action=ColorList.ACTION_BLACKLIST,
                       key=ColorList.KEY_IP, value=ip_addr[:15],
                       auth_event_id=data['auth_event'].id)
        c1.save()
        c2 = ColorList(action=ColorList.ACTION_BLACKLIST,
                       key=ColorList.KEY_TLF, value=tlf,
                       auth_event_id=data['auth_event'].id)
        c2.save()
        return error("Blacklisted", error_codename="blacklisted")
    return RET_PIPE_CONTINUE


def check_ip_total_max(data, **kwargs):
    '''
    if the ip has been sent more than <total_max> messages that have not been
    authenticated, blacklist it
    '''
    total_max = kwargs.get('max')
    period = kwargs.get('period', None)
    if data.get('whitelisted', False) == True:
        LOGGER.debug(
          "check_ip_total_max: whitelisted\n"\
          "returns 'RET_PIPE_CONTINUE'\n"\
          "data '%r'\n" \
          "kwargs '%r'\n",
          data,
          kwargs
        )
        return RET_PIPE_CONTINUE

    ip_addr = data['ip_addr']
    if period:
        time_threshold = timezone.now() - timedelta(seconds=period)
        item = Message.objects.filter(
            ip=ip_addr[:15],
            created__gt=time_threshold,
            auth_event_id=data['auth_event'].id)
    else:
        item = Message.objects.filter(
            ip=ip_addr[:15],
            auth_event_id=data['auth_event'].id)

    if len(item) >= total_max:
        cl = ColorList(
          action=ColorList.ACTION_BLACKLIST,
          key=ColorList.KEY_IP,
          value=ip_addr[:15],
          auth_event_id=data['auth_event'].id
        )
        cl.save()
        LOGGER.debug(
          "check_ip_total_max: blacklisted\n"\
          "returns 'Error Blacklisted' because len(item) >= total_max\n"\
          "data '%r'\n" \
          "kwargs '%r'\n" \
          "len(item) '%r'\n" \
          "total_max '%r'\n" \
          "ip_addr '%r'\n" \
          "cl.id '%r'\n",
          data,
          kwargs,
          len(item),
          total_max,
          ip_addr[:15],
          cl.id
        )
        return error("Blacklisted", error_codename="blacklisted")
    
    LOGGER.debug(
      "check_ip_total_max: ok\n"\
      "returns 'RET_PIPE_CONTINUE' because len(item) < total_max\n"\
      "data '%r'\n" \
      "kwargs '%r'\n" \
      "len(item) '%r'\n" \
      "total_max '%r'\n" \
      "ip_addr '%r'\n",
      data,
      kwargs,
      len(item),
      total_max,
      ip_addr[:15],
    )
    return RET_PIPE_CONTINUE


def check_sms_code(data, **kwargs):
    time_thr = timezone.now() - timedelta(seconds=kwargs.get('timestamp'))
    try:
        u = User.objects.get(userdata__tlf=data['tlf'], userdata__event=data['auth_event'])
        code = Code.objects.get(user=u.pk, code=data['code'],
                created__gt=time_thr, auth_event_id=data['auth_event'].id)
    except:
        return error('Invalid code.', error_codename='check_sms_code')
    return RET_PIPE_CONTINUE


def check_whitelisted(data, **kwargs):
    field = kwargs.get('field')
    if field == 'tlf':
        check = check_tlf_whitelisted(data)
    elif field == 'ip':
        check = check_ip_whitelisted(data)
    return check


def check_blacklisted(data, **kwargs):
    field = kwargs.get('field')
    if field == 'tlf':
        check = check_tlf_blacklisted(data)
    elif field == 'ip':
        check = check_ip_blacklisted(data)
    return check


def check_total_max(data, **kwargs):
    field = kwargs.get('field', None)
    check = 0

    if field == 'tlf':
        check = check_tlf_total_max(data, **kwargs)
    if check != 0:
        return check

    if field == 'ip':
        check = check_ip_total_max(data, **kwargs)
    return check

def check_total_connection(data, **kwargs):
    conn = Connection.objects.filter(tlf=req.get('tlf'),
                                     auth_event_id=data['auth_event'].id).count()
    if conn >= kwargs.get('times'):
        return error('Exceeded the level os attempts',
                error_codename='check_total_connection')
    conn = Connection(ip=data['ip'], tlf=data['tlf'])
    conn.save()
    return RET_PIPE_CONTINUE

def normalize_dni(dni):
    '''
    Normalizes dnis, using uppercase, removing characters not allowed and
    left-side zeros
    '''
    dni2 = ''.join([i for i in dni.upper() if i in DNI_ALLOWED_CHARS])
    last_char = ""
    dni3 = ""
    for c in dni2:
      if (last_char == "" or last_char not in '1234567890XY') and c == '0':
        continue
      dni3 += c
      last_char = c
    return dni3

def encode_dni(dni):
    '''
    Mark dnis with DNI prefix, and passports with PASS prefix.
    '''
    if DNI_RE.match(dni):
      return "DNI" + dni
    elif dni.startswith("PASS") or dni.startswith("DNI"):
      return dni
    else:
      return "PASS" + dni

def dni_constraint(val):
    ''' check that the input is a valid dni '''
    if not isinstance(val, str):
        return False

    # Allow Passports
    if val.startswith("PASS") and len(val) < 30:
        return False

    # remove the "DNI" prefix
    val = val[3:]

    if LETTER_RX.match(val[0]):
        nie_letter = val[0]
        val = val[1:]
        if nie_letter == 'Y':
            val = "1" + val
        elif nie_letter == 'Z':
            val = "2" + val

    mod_letters = 'TRWAGMYFPDXBNJZSQVHLCKE'
    digits = val[:-1]
    letter = val[-1].upper()
    expected = mod_letters[int(digits) % 23]
    return letter == expected

def get_match_fields(auth_event):
    reg_match_fields = []
    if auth_event.extra_fields is not None:
        reg_match_fields = [
            field for field in auth_event.extra_fields
            if (
                "match_census_on_registration" in field and 
                field['match_census_on_registration']
            )
        ]
    return reg_match_fields

def get_fill_empty_fields(auth_event):
    reg_fill_empty_fields = []
    if auth_event.extra_fields is not None:
        reg_fill_empty_fields = [
            f for f in auth_event.extra_fields
            if (
                "fill_if_empty_on_registration" in f and
                f['fill_if_empty_on_registration']
            )
        ]
    return reg_fill_empty_fields

class MissingFieldError(Exception):
    def __init__(self, field_name):
        self.field_name = field_name

def get_user_match_query(auth_event, user_data, base_query):
    query = base_query
    match_fields = get_match_fields(auth_event)
    use_matching = len(match_fields) > 0
    for field in match_fields:
        field_name = field.get('name')
        field_type = field.get('type')
        
        if field_name not in user_data:
            raise MissingFieldError(field_name)

        field_data = user_data.get(field_name)

        if field_type == 'email':
            query = query & Q(email__iexact=field_data)
        elif field_type == 'tlf':
            query = query & Q(userdata__tlf=field_data)
        elif field_type == 'bool':
            query = query & Q(
                userdata__metadata__contains={field_name: True}
            )
        else:
            query = query & Q(
                userdata__metadata__contains={field_name: field_data}
            )
    return query, use_matching

def get_fill_if_empty_query(auth_event, user_data, base_query):
    query = base_query
    fill_if_empty_fields = get_fill_empty_fields(auth_event)
    for field in fill_if_empty_fields:
        field_name = field.get('name')
        field_type = field.get('type')
        
        if field_name not in user_data or (
            isinstance(user_data[field_name], str) and 
            len(user_data[field_name]) == 0
        ):
            raise MissingFieldError(field_name)

        if field_type == 'email':
            query = query & Q(email='')
        elif field_type == 'tlf':
            query = query & (Q(userdata__tlf='') | Q(userdata__tlf=None))
        else:
            query = query & Q(
                userdata__metadata__contains={field_name: ''}
            )
    return query, fill_if_empty_fields

def fill_empty_fields(fill_if_empty_fields, existing_user, new_user_data):
    for field in fill_if_empty_fields:
        field_name = field.get('name')
        field_type = field.get('type')
        if field_name not in new_user_data:
            raise MissingFieldError(field_name)
        
        field_data = new_user_data[field_name]
        save_user = False
        save_userdata = False
        if field_type == 'email':
            existing_user.email = field_data
            save_user = True
        elif field_type == 'tlf':
            existing_user.userdata.tlf = field_data
            save_userdata = True
        else:
            existing_user.userdata.metadata[field_name] = new_user_data.get(field_name)
            save_userdata = True
        
        if save_user:
            existing_user.save()
        if save_userdata:
            existing_user.userdata.save()

def canonize_extra_field(extra, req):
    field_name = extra.get('name')
    field_value = req.get(field_name)
    field_type = extra.get('type')

    if field_type == 'tlf':
        req[field_name] = get_cannonical_tlf(field_value)
    elif field_type == 'dni':
        if isinstance(field_value, str):
            req[field_name] = encode_dni(normalize_dni(field_value))
    elif field_type == 'email':
        if isinstance(field_value, str):
            req[field_name] = field_value.strip().replace(' ', '').lower()
    elif field_type == 'bool':
        if isinstance(field_value, str):
            req[field_name] = field_value.lower().strip() not in ["", "false"]

def check_pipeline(request, ae, step='register', default_pipeline=None):
    req = json.loads(request.body.decode('utf-8'))

    if ae.extra_fields:
        for extra_field in ae.extra_fields:
            canonize_extra_field(extra_field, req)

    data = {
        'ip_addr': get_client_ip(request),
        'tlf': req.get('tlf', None),
        'code': req.get('code', None),
        'auth_event': ae
    }

    pipeline = ae.auth_method_config.get('pipeline').get('%s-pipeline' % step)
    if pipeline is None:
        if default_pipeline is None:
            return error(message="no pipeline", status=400, error_codename="no-pipeline")
        pipeline = default_pipeline


    for pipe in pipeline:
        check = getattr(eval(pipe[0]), '__call__')(data, **pipe[1])
        if check:
            data.update(json.loads(check.content.decode('utf-8')))
            data['status'] = check.status_code
            if data.get('auth_event'):
                data.pop('auth_event')
            if data.get('code'):
                data.pop('code')
            return data
    return RET_PIPE_CONTINUE

# Checkers census, register and authentication
def check_field_type(definition, field, step='register'):
    """ Checked the type of field. For example, if type is int, we can't use a str. """
    msg = ''
    if field is not None:
        if isinstance(field, str):
            if definition.get('type') == 'int' or definition.get('type') == 'bool':
                msg += "Field %s type incorrect, value %s" % (definition.get('name'), field)
            if definition.get('type') == 'image':
                if len(field) > settings.MAX_IMAGE_SIZE:
                    msg += "Field %s incorrect image size" % definition.get('name')
            elif len(field) > settings.MAX_GLOBAL_STR:
                msg += "Field %s incorrect len" % definition.get('name')
        elif isinstance(field, bool):
            if definition.get('type') != 'bool':
                msg += "Field %s type incorrect, value %s" % (definition.get('name'), field)
        elif isinstance(field, int):
            if definition.get('type') != 'int':
                msg += "Field %s type incorrect, value %s" % (definition.get('name'), field)
        elif isinstance(field, dict):
            if definition.get('type') != 'dict':
                msg += "Field %s type incorrect, value %s" % (definition.get('name'), field)
            if len(json.dumps(field)) > settings.MAX_GLOBAL_STR*10:
                msg += "Field %s incorrect len" % definition.get('name')
    return msg


def check_field_value(definition, field, req=None, ae=None, step='register'):
    """ Checked the value of field, checked regex, min., max or pipe checkers. """
    msg = ''
    if step == 'authenticate' and not definition.get('required_on_authentication'):
        return msg
    if step == 'resend-auth':
        if not definition.get('required_on_authentication'):
            return msg
        elif definition.get('type') == 'code':
            return msg
        elif definition.get('type') == 'otp-code':
            return msg
    if step == 'authenticate-otl':
        if not definition.get('match_against_census_on_otl_authentication'):
            return msg
    if step == 'census' and definition.get('type') == 'captcha':
        return msg
    if field is None:
        if (
            definition.get('required') and
            (
                definition.get('type') not in ['password', 'otp-code'] or
                step != 'census-query'
            )
        ):
            msg += "Field %s is required" % definition.get('name')
    else:
        if isinstance(field, str):
            if definition.get('min') and len(field) < definition.get('min'):
                msg += "Field %s min incorrect, value %s" % (definition.get('name'), field)
            if definition.get('max') and len(field) > definition.get('max'):
                msg += "Field %s max incorrect, value %s" % (definition.get('name'), field)
        elif isinstance(field, int):
            if definition.get('min') and field < definition.get('min'):
                msg += "Field %s min incorrect, value %s" % (definition.get('name'), field)
            if definition.get('max') and field > definition.get('max'):
                msg += "Field %s max incorrect, value %s" % (definition.get('name'), field)
        if definition.get('type') == 'email':
            if not email_constraint(field):
                msg += "Field email regex incorrect, value %s" % field
        if definition.get('type') == 'dni':
            if not dni_constraint(field):
                msg += "Field dni regex incorrect, value %s" % field
        if definition.get('regex'):
            a = re.compile(definition.get('regex'))
            if not a.match(str(field)):
                msg += "Field %s regex incorrect, value %s" % (definition.get('name'), field)
        if definition.get('type') == 'date':
            if not date_constraint(field):
                msg += "Field date incorrect, value %s" % field
        if definition.get(step + '-pipeline'):
            pipedata = dict(request=req)
            name = step + '-pipeline'
            # TODO: return error instead msg
            try:
                ret = execute_pipeline(definition[name], name, pipedata, definition['name'], ae)
                if ret != PipeReturnvalue.CONTINUE:
                    #key = "stopped-field-" + name
                    #return error(key, error_codename=key)
                    msg += key
            except CheckException as e:
                #return error(
                #    JSONContractEncoder().encode(e.data['context']),
                #    error_codename=e.data['key'])
                msg += JSONContractEncoder().encode(e.data['context'])
            except Exception as e:
                #return error(
                #    "unknown-exception: " + str(e),
                #    error_codename="unknown-exception")
                msg += "unknown-exception: " + str(e)
            #active = pipedata['active']
    return msg


def check_captcha(code, answer):
    if not code or not answer or not isinstance(code, str):
        return 'Invalid captcha'
    captcha = {'captcha_code': code, 'captcha_answer': answer}
    if not valid_captcha(captcha):
        return 'Invalid captcha'
    return ''

def check_fields_in_request(
    request_data,
    auth_event,
    step='register',
    validation=True
):
    '''
    Checked fields in extra_fields are correct, checked the type of field and
    the value if validation is True.
    '''
    error_messages = ''

    if auth_event.extra_fields:
        if len(request_data) > settings.MAX_EXTRA_FIELDS * 2:
            return "Number of fields is bigger than allowed fields."
        for extra in auth_event.extra_fields:
            canonize_extra_field(extra, request_data)
            error_messages += check_field_type(
                extra,
                request_data.get(extra.get('name')),
                step
            )
            canonize_extra_field(extra, request_data)
            if validation:
                error_messages += check_field_value(
                    extra, 
                    request_data.get(extra.get('name')),
                    request_data, 
                    auth_event, 
                    step
                )
                if (
                    not error_messages and
                    extra.get('type') == 'captcha' and
                    step != 'census'
                ):
                    if (
                        step == 'register' and extra.get('required')
                    ) or (
                        step == 'authenticate' and 
                        extra.get('required_on_authentication')
                    ):
                        error_messages += check_captcha(
                            request_data.get('captcha_code'),
                            request_data.get(extra.get('name'))
                        )
    return error_messages


def have_captcha(ae, step='register'):
    if ae.extra_fields:
        for extra in ae.extra_fields:
            if extra.get('type') == 'captcha':
                if step == 'authenticate' and extra.get('required_on_authentication') == False:
                    return False
                return True
    return False

def exists_unique_user(unique_users, user_data, auth_event):
    for extra in auth_event.extra_fields:
        if (
            'unique' not in extra.keys() or 
            not extra.get('unique') or
            extra.get('name') not in user_data
        ):
            continue
        
        key_name = extra.get('name')
        if user_data[key_name] in unique_users.get(key_name, dict()):
            return True, "%r %r repeat." % (key_name, user_data[key_name])
    return False, ""

def add_unique_user(unique_users, user_data, auth_event):
    for extra in auth_event.extra_fields:
        if (
            'unique' not in extra.keys() or 
            not extra.get('unique') or
            extra.get('name') not in user_data
        ):
            continue
        
        key_name = extra.get('name')
        key_value = user_data[key_name]
        if key_name not in unique_users:
            unique_users[key_name] = dict()    
        unique_users[key_name][key_value] = True

def exist_user(user_data, auth_event, get_repeated=False, ignore_user=None):
    msg = ''

    if not auth_event.extra_fields:
        return ''
    # check that the unique:True extra fields are actually unique
    base_q = Q(userdata__event=auth_event, is_active=True)
    for extra in auth_event.extra_fields:
        if 'unique' not in extra.keys() or not extra.get('unique'):
            continue
        reg_name = extra['name']
        req_field_data = user_data.get(reg_name, None)
        if not req_field_data or not reg_name:
            continue
        if reg_name == 'username':
            extra_q = Q(username=req_field_data)
        elif reg_name == 'tlf':
            tlf = get_cannonical_tlf(req_field_data)
            extra_q = Q(userdata__tlf=tlf)
        elif reg_name == 'email':
            extra_q = Q(email=req_field_data)
        else:
            extra_q = Q(userdata__metadata__contains={reg_name: req_field_data}) 
        q = base_q & extra_q
        repeated_list = User.objects.filter(q)
        if ignore_user:
            repeated_list = repeated_list.exclude(id=ignore_user.id)
        if repeated_list.count() > 0:
            msg += "%s %s repeat." % (reg_name, req_field_data)
            user = repeated_list[0]

    if not msg:
        return ''

    if get_repeated:
        return {'msg': msg, 'user': user}

    return msg

def get_cannonical_tlf(tlf):
    from authmethods.sms_provider import SMSProvider
    con = SMSProvider.get_instance()
    return con.get_canonical_format(tlf)


def edit_user(user, req, auth_event):
    if auth_event.extra_fields:
        for extra in auth_event.extra_fields:
            if extra.get('name') not in req:
                continue
            if extra.get('type') == 'email':
                user.email = req.get(extra.get('name'))
                req.pop(extra.get('name'))
            elif extra.get('type') == 'tlf':
                user.userdata.tlf = get_cannonical_tlf(req[extra.get('name')])
                req.pop(extra.get('name'))
            elif extra.get('type') == 'password':
                user.set_password(req.get(extra.get('name')))
                req.pop(extra.get('name'))
            elif extra.get('type') == 'image':
                img = req.get(extra.get('name'))
                fname = user.username.decode()
                path = os.path.join(settings.IMAGE_STORE_PATH, fname)
                head, img2 = img.split('base64,')
                with open(path, "w") as f:
                    #f.write(decodestring(img.encode()))
                    f.write(img)
                req[extra.get('name')] = fname
    user.save()

    if auth_event.children_election_info is not None:
        user.userdata.children_event_id_list = req.get('children_event_id_list')

    user.userdata.metadata = req
    user.userdata.save()
    return user


def generate_username(req, ae):
    '''
    Generates username by:
    a) if any user field is marked as userid_field, then the username will be:
      sha256(userid_field1:userid_field2:..:auth_event_id:shared_secret)
    b) in any other case, use a random username
    '''
    userid_fields = []
    if not ae.extra_fields:
        return random_username()

    for extra in ae.extra_fields:
        if 'userid_field' in extra.keys() and extra.get('userid_field'):
            val = req.get(extra.get('name', ""))
            if not isinstance(val, str):
                val = ""
            userid_fields.append(val)

    if len(userid_fields) == 0:
        return random_username()

    userid_fields.append(str(ae.id))
    userid_fields.append(settings.SHARED_SECRET.decode("utf-8"))
    return hashlib.sha256(":".join(userid_fields).encode('utf-8')).hexdigest()

def get_trimmed_user_req(req, ae):
    '''
    Returns the request without images or passwords, used to log the action when
    adding someone to census
    '''
    metadata = req.copy()
    if 'password' in metadata:
        metadata.pop('password')

    if ae.extra_fields:
        for extra in ae.extra_fields:
            if (
                extra.get('type') in ['password', 'image'] and
                extra.get('name') in metadata
            ):
                metadata.pop(extra.get('name'))

    return metadata

def get_trimmed_user(user, ae):
    '''
    Returns the request without images or passwords, used to log the action
    when deleting someone from census
    '''
    metadata = user.userdata.metadata.copy()

    if ae.extra_fields:
        for extra in ae.extra_fields:
            if (
                extra.get('type') in ['password', 'image'] and
                extra.get('name') in metadata
            ):
                metadata.pop(extra.get('name'))

    if user.email:
        metadata['email'] = user.email
    if user.userdata.tlf:
        metadata['tlf'] = user.userdata.tlf

    metadata['_username'] = user.username
    metadata['_id'] = user.id

    return metadata

def get_user_code(user, timeout_seconds=None):
    '''
    Retrieves from the database the current valid user code for a given user and
    optionally a timeout period. The timeout period (timeout_seconds) is 
    optional and only used if it's not None.
    '''
    filter_kwargs = dict(
        user=user.userdata,
        is_enabled=True
    )
    if timeout_seconds is not None:
        filter_kwargs['created__gt'] = (
            timezone.now() - timedelta(seconds=timeout_seconds)
        )

    return Code\
        .objects\
        .filter(**filter_kwargs)\
        .order_by('-created')\
        .first()

def disable_previous_user_codes(user, auth_event):
    # do not disable previous codes if using fixed codes
    if auth_event.auth_method_config.get('config', {}).get('fixed-code', False):
        return
    Code\
        .objects\
        .filter(
            user=user.userdata,
            is_enabled=True
        )\
        .update(
            is_enabled=False
        )

def create_user(req, auth_event, active, creator, user=None, password=None):
    from api.models import Action
    if not user:
        user = generate_username(req, auth_event)

    new_user = User(username=user)
    new_user.is_active = active
    if password:
        new_user.set_password(password)
    new_user.save()

    new_user.userdata.event = auth_event
    new_user.userdata.save()

    is_anon = creator is None or isinstance(creator, AnonymousUser)

    action = Action(
        executer=new_user if is_anon else creator,
        receiver=new_user,
        action_name='user:register' if is_anon else 'user:added-to-census',
        event=auth_event,
        metadata=get_trimmed_user_req(req, auth_event)
    )
    action.save()

    return edit_user(new_user, req, auth_event)

def parse_otp_code_field(extra_fields, otp_field):
    '''
    Processes and validates an OTP Code field, throwing an exception if it's
    invalid
    '''
    # check that there's no field called "code" because any otp will be received
    # under that key name so it's not allowed
    for extra_field in extra_fields:
        if extra_field.get('name') == 'code':
            error = "parse_otp_field: extra_field with name 'code' not allowed"
            LOGGER.error(f"{error}\n%sStack trace:\n{stack_trace_str()}")
            return error, None

    # get the source_field
    if (
        'source_field' not in otp_field or
        not isinstance(otp_field['source_field'], str)
    ):
        error = "parse_otp_field: Source field missing"
        LOGGER.error(f"{error}\n%sStack trace:\n{stack_trace_str()}")
        return error, None
    source_field_name = otp_field['source_field']
    source_field = None
    for extra_field in extra_fields:
        if extra_field['name'] == source_field_name:
            source_field = extra_field
            break
    if source_field is None:
        error = f"parse_otp_field: Source field '{source_field_name}' not found"
        LOGGER.error(f"{error}\n%sStack trace:\n{stack_trace_str()}")
        return error, None
    # check source_field is 'email' or 'tlf', as it's the only ones currently
    # supported
    if source_field['type'] not in ['email', 'tlf']:
        error = f"parse_otp_field: Source field '{source_field_name}' has invalid type"
        LOGGER.error(f"{error}\n%sStack trace:\n{stack_trace_str()}")
        return error, None
    # parse templates
    if (
        'templates' not in otp_field or
        not isinstance(otp_field['templates'], dict) or
        'message_body' not in otp_field['templates'] or
        not isinstance(otp_field['templates']['message_body'], str)
    ):
        error = f"parse_otp_field: invalid templates in field '{otp_field}'"
        LOGGER.error(f"{error}\n%sStack trace:\n{stack_trace_str()}")
        return error, None
    if (
        source_field['type'] == 'email' and
        (
            'message_subject' not in otp_field['templates'] or
            not isinstance(otp_field['templates']['message_subject'], str)
        )
    ):
        error = f"parse_otp_field: invalid templates in field '{otp_field}'"
        LOGGER.error(f"{error}\n%sStack trace:\n{stack_trace_str()}")
        return error, None

    ret_value = dict(
        otp_field=otp_field,
        source_field=source_field,
        source_field_type=source_field['type'],
        expiration_seconds=settings.SMS_OTP_EXPIRE_SECONDS
    )
    return None, ret_value

def post_verify_fields_on_auth(user, req, auth_event, mode="auth"):
    '''
    Verifies fields that cannot be verified during the user orm query on the 
    database. Currently this is only password fields.

    Returns the otp_field_code if any, so that it can be reused as the user
    code to check in authentication methods like email, email-otp, sms, sms-otp.
    '''
    otp_field_code = None
    if auth_event.extra_fields:
        for field in auth_event.extra_fields:
            if not field.get('required_on_authentication'):
                continue

            field_name = field.get('name')
            type_field = field.get('type')
            # Raise exception if a required_on_authentication field is not
            # provided. It will be catched by parent as an error. The exception
            # is the otp-code fields, that do not need to be provided in
            # resend-auth mode
            if (
                field_name not in req and
                mode != "resend-auth" and
                type_field != 'otp-code'
            ):
                raise Exception(f"field_name {field_name} missing")

            field_value = req.get(field_name, '')
            if type_field == 'password':
                if not user.check_password(field_value):
                    raise Exception("Invalid Password")

            # we do not verify otp-code in mode 'resend-auth', since the
            # whole point is to send the auth-code before being able to verify
            # it
            elif type_field == 'otp-code' and mode == 'auth':
                # ensure the otp-code field is valid
                otp_field_error, _otp_field = parse_otp_code_field(
                    auth_event.extra_fields,
                    field
                )
                if otp_field_error is not None:
                    LOGGER.error(
                        f"post_verify_fields_on_auth::OTPCode error\n" +
                        "Error running parse_otp_code_field\n" +
                        f"authevent '{auth_event}'\n" +
                        f"request '{req}'\n" +
                        f"field name '{field_name}'\n" +
                        f"Stack trace: \n{stack_trace_str()}"
                    )
                    raise Exception('Error running parse_otp_code_field')

                # get the field value, because in otp-code it's always under the
                # key 'code'
                field_value = req.get('code', None)
                if not isinstance(field_value, str):
                    LOGGER.error(
                        f"post_verify_fields_on_auth::OTPCode error\n" +
                        "Error: code is not a string\n" +
                        f"authevent '{auth_event}'\n" +
                        f"request '{req}'\n" +
                        f"field name '{field_name}'\n" +
                        f"Stack trace: \n{stack_trace_str()}"
                    )
                    raise Exception('Error: code is not a string')

                timeout = settings.SMS_OTP_EXPIRE_SECONDS
                if otp_field_code is None:
                    otp_field_code = get_user_code(user, timeout)

                if not otp_field_code:
                    LOGGER.error(
                        "post_verify_fields_on_auth::OTPCode error\n" +
                        f"Code not found on db for user '{user.userdata}'\n" +
                        f"and time between now and '{timeout}' seconds earlier\n" +
                        f"authevent '{auth_event}'\n" +
                        f"request '{req}'\n" +
                        f"field name '{field_name}'\n" +
                        f"Stack trace: \n{stack_trace_str()}"
                    )
                    raise Exception(f"Code not found on db for user '{user.userdata}'")

                if not constant_time_compare(
                    field_value.upper(),
                    otp_field_code.code
                ):
                    LOGGER.error(
                        f"post_verify_fields_on_auth::OTPCode error\n" +
                        f"Code mismatch for user '{user.userdata}'\n" +
                        f"Code received '{req.get('code').upper()}'\n" +
                        f"and latest code in the db for the user '{otp_field_code.code}'\n" +
                        f"authevent '{auth_event}'\n" +
                        f"request '{req}'\n" +
                        f"field name '{field_name}'\n" +
                        f"Stack trace: \n{stack_trace_str()}"
                    )
                    raise Exception(f"Code mismatch for user '{user.userdata}'")

    # disable the user code if any
    if otp_field_code is not None:
        disable_previous_user_codes(user, auth_event)

    return otp_field_code

def generate_auth_code(auth_event, request, logger_name):
    request_data = json.loads(request.body.decode('utf-8'))
    if (
        'username' not in request_data or
        not isinstance(request_data['username'], str)
    ):
        LOGGER.error(
            f"{logger_name}.generate_auth_code error\n" +
            "error: invalid username" +
            f"authevent '{auth_event}'\n" +
            f"request '{request_data}'\n" +
            f"Stack trace: \n{stack_trace_str()}"
        )
        raise Exception()

    username = request_data['username']
    try:
        base_query = get_base_auth_query(
            auth_event,
            ignore_generated_code=True
        )
        query = base_query & Q(username=username)
        user = User.objects.get(query)
    except Exception as _error:
        LOGGER.error(
            f"{logger_name}.generate_auth_code error\n" +
            f"error: username '{username}' not found\n" +
            f"authevent '{auth_event}'\n" +
            f"request '{request_data}'\n" +
            f"Stack trace: \n{stack_trace_str()}"
        )
        raise Exception()

    if not verify_num_successful_logins(auth_event, logger_name, user, request_data):
        LOGGER.error(
            f"{logger_name}.generate_auth_code error\n" +
            "error: voter has voted enough times already\n" +
            f"authevent '{auth_event}'\n" +
            f"request '{request_data}'\n" +
            f"Stack trace: \n{stack_trace_str()}"
        )
        raise Exception()

    code = generate_code(user.userdata)
    user.userdata.use_generated_auth_code=True
    user.userdata.save()
    return (
        dict(
            code=code.code,
            created=code.created.isoformat()
        ),
        user
    )

def authenticate_otl(
    auth_event,
    request,
    logger_name
):
    '''
    Implements the authenticate_otl call for an authentication method.
    '''
    from authmethods.models import OneTimeLink
    from api.models import Action
    request_data = json.loads(request.body.decode('utf-8'))

    def ret_error(log_error_message, error_message, error_codename):
        LOGGER.error(
            f"{logger_name}.authenticate_otl error\n"\
            f"{log_error_message}\n"\
            f"{error_message}\n"\
            f"authevent '{auth_event}'\n"\
            f"request '{request_data}'\n"\
            f"Stack trace: \n{stack_trace_str()}"
        )
        return dict(
            status='nok',
            msg=error_message,
            error_codename=error_codename
        )

    if auth_event.parent is not None:
        return ret_error(
            log_error_message='you can only do authenticate_otl to parent elections',
            error_message="Incorrect data",
            error_codename="invalid_credentials"
        )

    if auth_event.support_otl_enabled is not True:
        return ret_error(
            log_error_message='election without OTL enabled',
            error_message="Incorrect data",
            error_codename="invalid_credentials"
        )

    if auth_event.inside_authenticate_otl_period is not True:
        return ret_error(
            log_error_message='election outside OTL period',
            error_message="Incorrect data",
            error_codename="invalid_credentials"
        )

    error_message = ''

    error_message += check_fields_in_request(
        request_data,
        auth_event, 
        'authenticate-otl'
    )
    if error_message:
        return ret_error(
            log_error_message=error_message,
            error_message="Incorrect data",
            error_codename="invalid_credentials"
        )

    otl_secret = request_data.get('__otl_secret')
    if '__otl_secret' not in request_data:
        return ret_error(
            log_error_message=error_message,
            error_message="Incorrect data",
            error_codename="invalid_credentials"
        )

    try:
        otl = OneTimeLink\
            .objects\
            .filter(
                secret=otl_secret,
                used=None,
                is_enabled=True,
                auth_event_id=auth_event.id
            )\
            .order_by('-created')\
            .first()
        query = get_base_auth_query(auth_event)
        query = query & Q(userdata=otl.user)
        query = get_required_fields_on_auth(
            request_data,
            auth_event,
            query,
            selector='match_against_census_on_otl_authentication'
        )
        user = User.objects.get(query)
    except:
        return ret_error(
            log_error_message="user not found with given characteristics",
            error_message="Incorrect data",
            error_codename="invalid_credentials"
        )

    code = get_or_create_code(user)
    otl.used = timezone.now()
    otl.is_enabled = False
    otl.save()

    action = Action(
        executer=user,
        receiver=user,
        action_name='user:authenticate-otl',
        event=auth_event,
        metadata=get_trimmed_user_req(request_data, auth_event)
    )
    action.save()

    LOGGER.info(
        f"{logger_name}.authenticate_otl.\n"\
        f"Returning auth-code={code} for user.id='{user.id}'\n"\
        f"client ip '{get_client_ip(request)}'\n"\
        f"authevent '{auth_event}'\n"\
        f"request '{request_data}'\n"\
        f"Stack trace: \n{stack_trace_str()}"
    )
    return dict(status='ok', code=code, username=user.username)

def resend_auth_code(
    auth_event,
    request,
    logger_name,
    default_pipelines=None
):
    import plugins
    '''
    Implements the resend_auth_code call for an authentication method. It uses
    either:
     - tlf field if it is an sms-otp auth_method
     - email field if it is an email-otp auth_method
     - otp-code extra field in any other case
    '''
    request_data = json.loads(request.body.decode('utf-8'))

    def ret_error(log_error_message, error_message, error_codename):
        LOGGER.error(
            f"{logger_name}.resend_auth_code error\n"\
            f"{log_error_message}\n"\
            f"{error_message}\n"\
            f"authevent '{auth_event}'\n"\
            f"request '{request_data}'\n"\
            f"Stack trace: \n{stack_trace_str()}"
        )
        return dict(
            status='nok',
            msg=error_message,
            error_codename=error_codename
        )

    error_message = ''

    # check the auth_event is valid for resend_auth_code
    parsed_otp_fields = []
    for extra_field in auth_event.extra_fields:
        if extra_field['type'] != 'otp-code':
            continue
        otp_field_error, otp_field = parse_otp_code_field(
            auth_event.extra_fields,
            extra_field
        )
        if otp_field_error is not None:
            error_message += f'parse_otp_code_field error: {otp_field_error}'
            return ret_error(
                log_error_message=error_message,
                error_message="Incorrect data",
                error_codename="invalid_credentials"
            )
        parsed_otp_fields.append(otp_field)

    if (
        auth_event.auth_method not in ['sms', 'email', 'sms-otp', 'email-otp'] and
        len(parsed_otp_fields) == 0
    ):
        error_message += 'otp-code in extra_fields missing'
        return ret_error(
            log_error_message=error_message,
            error_message="Incorrect data",
            error_codename="invalid_credentials"
        )

    if auth_event.parent is not None:
        error_message += 'you can only authenticate to parent elections'
        return ret_error(
            log_error_message=error_message,
            error_message="Incorrect data",
            error_codename="invalid_credentials"
        )

    error_message += check_fields_in_request(request_data, auth_event, 'resend-auth')
    if error_message:
        return ret_error(
            log_error_message=error_message,
            error_message="Incorrect data",
            error_codename="invalid_credentials"
        )

    try:
        query = get_base_auth_query(auth_event)
        query = get_required_fields_on_auth(request_data, auth_event, query)
        user = User.objects.get(query)
        post_verify_fields_on_auth(user, request_data, auth_event, mode="resend-auth")
    except:
        return ret_error(
            log_error_message="user not found with given characteristics",
            error_message="Incorrect data",
            error_codename="invalid_credentials"
        )

    error_message = check_pipeline(
        request,
        auth_event,
        step='resend-auth',
        default_pipeline=default_pipelines.get('resend-auth-pipeline', [])
    )

    if error_message:
        return ret_error(
            log_error_message=f"check_pipeline error '{error_message}'",
            error_message="Incorrect data",
            error_codename="invalid_credentials"
        )

    result = plugins.call("extend_send_otp", auth_event, 1)
    if result:
        return ret_error(
            log_error_message=f"extend_send_otp plugin error",
            error_message="Incorrect data",
            error_codename="invalid_credentials"
        )

    send_codes.apply_async(
        args=[
            [user.id,],
            get_client_ip(request)
        ],
        # since the auth_event might have been patched, we need to pass the
        # potentially patched auth_method and config
        kwargs={
            "auth_method": auth_event.auth_method,
            "config": auth_event.auth_method_config.get('config')
        }
    )
    LOGGER.info(
        f"{logger_name}.resend_auth_code.\n"\
        f"Sending codes to user id '{user.id}'\n"\
        f"client ip '{get_client_ip(request)}'\n"\
        f"authevent '{auth_event}'\n"\
        f"request '{request_data}'\n"\
        f"Stack trace: \n{stack_trace_str()}"
    )
    return dict(status='ok', user=user)

def get_required_fields_on_auth(
    request_data,
    auth_event,
    query,
    selector='required_on_authentication'
):
    '''
    Modifies a Q query adding required_on_authentication fields with the values
    from the http request, used to filter users
    '''
    if auth_event.extra_fields:
        for field in auth_event.extra_fields:
            if not field.get(selector):
                continue
            
            # Raise exception if a required field is not provided.
            # It will be catched by parent as an error.
            typee = field.get('type')
            if (
                field.get('name') not in request_data and
                typee not in ['password', 'otp-code']
            ):
                raise Exception()

            value = request_data.get(field.get('name'), '')
            if typee == 'email':
                query = query & Q(email__iexact=value)
            elif typee == 'tlf':
                query = query & Q(userdata__tlf=value)
            elif typee in ['password', 'otp-code']:
                # we verify this later im post_verify_fields_on_auth
                continue
            else:
                if typee == 'text' and field.get('name') == 'username':
                    query = query & Q(username=value)
                else:
                    query = query & Q(
                        userdata__metadata__contains={field.get('name'): value}
                    )

    return query

def give_perms(u, ae):
    pipe = ae.auth_method_config.get('pipeline')
    if not pipe:
        return 'Bad config'
    give_perms = pipe.get('give_perms', [])
    for perms in give_perms:
        obj = perms.get('object_type')
        obj_id = perms.get('object_id', 0)
        if obj_id == 'UserDataId':
            obj_id = u.pk
        elif obj_id == 'AuthEventId':
            obj_id = ae.pk
        for perm in perms.get('perms'):
            acl, created = ACL.objects.get_or_create(
                user=u.userdata, 
                object_type=obj, 
                perm=perm, 
                object_id=obj_id
            )
            acl.save()
    return ''

def verify_children_election_info(
    auth_event,
    user,
    perms,
    children_election_info=None
):
    '''
    Verify that the requesting user has permissions to edit all
    the referred children events (and that they do, in fact, exist)
    and the correct configuration.
    '''
    from api.models import AuthEvent

    # Cannot have nested parents or no children_election_info
    if children_election_info is None:
        children_election_info = auth_event.children_election_info

    # verify the children do exist and the requesting user have the 
    # appropiate permissions and configuration
    if children_election_info is not None:
        for event_id in children_election_info['natural_order']:
            children_event = AuthEvent.objects.get(
                Q(pk=event_id) &
                (
                    Q(parent=auth_event) | Q(parent__parent=auth_event)
                )
            )
            assert children_event.auth_method == auth_event.auth_method
            permission_required(user, 'AuthEvent', perms, event_id)


def verify_valid_children_elections(auth_event, census_element):
    '''
    Verify that the requesting census element is referring as children
    elections only to elections who indeed are children of the parent
    '''
    from api.models import children_event_id_list_validator
    assert 'children_event_id_list' in census_element
    children_event_id_list_validator(census_element['children_event_id_list'])

    for event_id in census_element['children_event_id_list']:
        assert event_id in auth_event.children_election_info['natural_order']

def return_auth_data(logger_name, req_json, request, user, auth_event=None):
    '''
    used at the end of the authentication process to return the required
    authentication data, which can be:
    - redirect to url
    - auth-token
    - username
    - multiple auth-tokens and the list of available children authevents in
      which the user can participate, including info about those where he 
      already registered a successful authentication event.
    '''
    from api.models import AuthEvent
    # register the django-way the latest login of this user
    user_logged_in.send(sender=user.__class__, request=request, user=user)
    user.save()


    # this is the data that will be returned
    data = {'status': 'ok'}

    # return the username, ensuring it's a string
    username = user.username
    if isinstance(username, bytes):
        username = user.username.decode('utf-8')
    data['username'] = username

    if auth_event is None:
        auth_event = user.userdata.event

    is_admin = user.userdata.event_id == settings.ADMIN_AUTH_ID

    # generate the user auth-token
    if 'Ping' != logger_name or is_admin:
        data['auth-token'] = generate_access_token_hmac(settings.SHARED_SECRET, user.username, auth_event.get_refresh_token_duration_secs())

    if auth_event.children_election_info is None:
        msg = ':'.join((user.username, 'AuthEvent', str(auth_event.id), 'vote'))
        data['vote-permission-token'] = generate_access_token_hmac(settings.SHARED_SECRET, msg, auth_event.get_access_token_duration_secs())
    else:
        def get_child_info(event_id):
            auth_event = AuthEvent.objects.get(pk=event_id)

            num_successful_logins = user\
                .userdata\
                .successful_logins\
                .filter(is_active=True, auth_event=auth_event)\
                .count()

            max_num_successful_logins = auth_event.num_successful_logins_allowed
            if event_id not in user.userdata.children_event_id_list:
                max_num_successful_logins = -1

            if (
                auth_event.num_successful_logins_allowed == 0 or
                num_successful_logins < auth_event.num_successful_logins_allowed
            ) and (
                event_id in user.userdata.children_event_id_list
            ):

                msg = ':'.join((user.username, 'AuthEvent', str(event_id), 'vote'))
                access_token = generate_access_token_hmac(settings.SHARED_SECRET, msg, auth_event.get_access_token_duration_secs())
            else:
                access_token = None
            
            return {
                'auth-event-id': event_id,
                'vote-permission-token': access_token,
                'num-successful-logins-allowed': max_num_successful_logins,
                'num-successful-logins': num_successful_logins
            }

        data['vote-children-info'] = [
            get_child_info(child_event_id)
            for child_event_id in auth_event.children_election_info["natural_order"]
        ]
             

    # add redirection
    auth_action = auth_event.auth_method_config['config']['authentication-action']
    if auth_action['mode'] == 'go-to-url':
        data['redirect-to-url'] = get_redirect_to_url(auth_event, data)

    LOGGER.debug(\
        "%s.authenticate success\n"\
        "returns '%r'\n"\
        "authevent '%r'\n"\
        "request '%r'\n"\
        "Stack trace: \n%s",\
        logger_name, data, auth_event, req_json, stack_trace_str())
    return data

def get_redirect_to_url(auth_event, data):
    '''
    Return the redirect-to-url, with templated vars replaced
    '''

    auth_action = auth_event.auth_method_config['config']['authentication-action']
    if auth_event.children_election_info is None:
        vote_children_info = []
    else:
        def map_child_info(child_info):
            mapped = child_info.copy()
            mapped['can-vote'] = (mapped['vote-permission-token'] is not None)
            del mapped['vote-permission-token']
            return mapped

        vote_children_info = [
            map_child_info(child_event_info)
            for child_event_info in data['vote-children-info']
        ]

    # encode to json, then url encode it for safety too
    vote_children_info = urllib.parse.quote(json.dumps(vote_children_info))

    url = template_replace_data(
        auth_action['mode-config']['url'],
        dict(vote_children_info=vote_children_info)
    )
    return url

def verify_num_successful_logins(auth_event, logger_name, user, req_json):
    '''
    During authentication, verify that the user has not voted more
    times than allowed. Only verified for non-parent elections, as
    it is verified in return_auth_data() for parent elections.
    '''
    if auth_event.children_election_info is None:
        successful_logins_count = user.userdata.successful_logins\
            .filter(is_active=True, auth_event=auth_event).count()
        if (auth_event.num_successful_logins_allowed > 0 and
            successful_logins_count >= auth_event.num_successful_logins_allowed):
            LOGGER.error(
                "%s.authenticate error\n"\
                "Maximum number of revotes already reached for user '%r'\n"\
                "revotes for user '%r'\n"\
                "maximum allowed '%r'\n"\
                "authevent '%r'\n"\
                "request '%r'\n"\
                "Stack trace: \n%s",
                logger_name,
                user.userdata,
                successful_logins_count,
                auth_event.num_successful_logins_allowed,
                auth_event, req_json, stack_trace_str()
            )
            return False
    return True

def get_base_auth_query(auth_event, ignore_generated_code=False):
    '''
    returns the base authentication query for the given auth_event
    '''
    q = Q(
        userdata__event=auth_event,
        is_active=True
    )

    if not ignore_generated_code:
        q = q & Q(
            userdata__use_generated_auth_code=False
        )
    
    if auth_event.children_election_info is not None:
        q = q | Q(
            userdata__event_id__in=auth_event.children_election_info['natural_order'],
            is_active=True
        )
    return q

def populate_fields_from_source_claims(req, id_token_dict, auth_event, provider_id):
    '''
    once verified id_token_dict, this function populates req with data from the
    verified claims contained in id_token_dict
    '''
    if not auth_event.extra_fields:
        return req

    for extra_field in auth_event.extra_fields:
        if "source_claim" not in extra_field:
            continue

        source_claim = extra_field["source_claim"]

        if source_claim is None:
            continue

        # If source_claim is a dict, get the source_claim for the provider_id
        if isinstance(source_claim, dict):
            if provider_id in source_claim:
                source_claim = source_claim[provider_id]
            else:
                # Skip if provider_id not found in source_claim map
                continue

        if source_claim not in id_token_dict:
            continue

        field_name = extra_field["name"]
        req[field_name] = id_token_dict[source_claim]

    return req
