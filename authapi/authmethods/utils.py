# This file is part of authapi.
# Copyright (C) 2014-2020  Agora Voting SL <contact@nvotes.com>

# authapi is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License.

# authapi  is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.

# You should have received a copy of the GNU Affero General Public License
# along with authapi.  If not, see <http://www.gnu.org/licenses/>.

import hashlib
import json
import re
import os
import copy
import binascii
import logging
from base64 import decodestring
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
    json_response, 
    get_client_ip, 
    is_valid_url, 
    constant_time_compare,
    permission_required,
    genhmac,
    stack_trace_str
)
from pipelines.base import execute_pipeline, PipeReturnvalue

LOGGER = logging.getLogger('authapi')

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


def email_constraint(val):
    ''' check that the input is an email string '''
    if not isinstance(val, str):
        return False
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
      if (last_char is "" or last_char not in '1234567890XY') and c == '0':
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



def canonize_extra_field(extra, req):
    field_name = extra.get('name')
    field_value = req.get(field_name)
    field_type = extra.get('type')

    if field_type == 'tlf':
        req[field_name] = get_cannonical_tlf(field_value)
    elif field_type == 'dni':
        if isinstance(field_value, str):
            req[field_name] = encode_dni(normalize_dni(field_value))
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
    if step == 'census' and definition.get('type') == 'captcha':
        return msg
    if field is None:
        if definition.get('required'):
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

def check_fields_in_request(req, ae, step='register', validation=True):
    """ Checked fields in extra_fields are correct, checked the type of field and the value if
    validation is True. """
    msg = ''

    if ae.extra_fields:
        if len(req) > settings.MAX_EXTRA_FIELDS * 2:
            return "Number of fields is bigger than allowed fields."
        for extra in ae.extra_fields:
            canonize_extra_field(extra, req)
            msg += check_field_type(extra, req.get(extra.get('name')), step)
            canonize_extra_field(extra, req)
            if validation:
                msg += check_field_value(extra, req.get(extra.get('name')), req, ae, step)
                if not msg and extra.get('type') == 'captcha' and step != 'census':
                    if (step == 'register' and extra.get('required')) or\
                            (step == 'authenticate' and extra.get('required_on_authentication')):
                        msg += check_captcha(req.get('captcha_code'), req.get(extra.get('name')))
    return msg


def have_captcha(ae, step='register'):
    if ae.extra_fields:
        for extra in ae.extra_fields:
            if extra.get('type') == 'captcha':
                if step == 'authenticate' and extra.get('required_on_authentication') == False:
                    return False
                return True
    return False


def exist_user(req, ae, get_repeated=False):
    msg = ''
    if req.get('email'):
        try:
            user = User.objects.get(email=req.get('email'), userdata__event=ae)
            msg += "Email %s repeat." % req.get('email')
        except:
            pass
    if req.get('tlf'):
        try:
            tlf = get_cannonical_tlf(req['tlf'])
            user = User.objects.get(userdata__tlf=tlf, userdata__event=ae)
            msg += "Tel %s repeat." % req.get('tlf')
        except:
            pass
    if req.get('username'):
        try:
            user = User.objects.get(username=r.get('username'), userdata__event=ae)
            msg += "Username %s repeat." % req.get('username')
        except:
            pass

    if not msg:
        if not ae.extra_fields:
            return ''
        # check that the unique:True extra fields are actually unique
        base_q = Q(userdata__event=ae, is_active=True)
        for extra in ae.extra_fields:
            if 'unique' in extra.keys() and extra.get('unique'):
                reg_name = extra['name']
                req_field_data = req.get(reg_name)
                if reg_name and req_field_data:
                    q = base_q & Q(userdata__metadata__contains={reg_name: req_field_data})
                    repeated_list = User.objects.filter(q)
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


def edit_user(user, req, ae):
    if ae.auth_method == 'user-and-password':
        req.pop('username')
        req.pop('password')
    elif ae.auth_method == 'email-and-password':
        req.pop('email')
        req.pop('password')

    if req.get('email'):
        user.email = req.get('email')
        req.pop('email')
    if req.get('tlf'):
        user.userdata.tlf = get_cannonical_tlf(req['tlf'])
        req.pop('tlf')

    if ae.extra_fields:
        for extra in ae.extra_fields:
            if extra.get('type') == 'email' and req.get(extra.get('name')):
                user.email = req.get(extra.get('name'))
                req.pop(extra.get('name'))
            elif extra.get('type') == 'tlf' and req.get(extra.get('name')):
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

    if ae.children_election_info is not None:
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
            if extra.get('type') in ['password', 'image']:
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
            if extra.get('type') in ['password', 'image']:
                metadata.pop(extra.get('name'))

    if user.email:
        metadata['email'] = user.email
    if user.userdata.tlf:
        metadata['tlf'] = user.userdata.tlf

    metadata['_username'] = user.username
    metadata['_id'] = user.id

    return metadata


def create_user(req, ae, active, creator, user=None, password=None):
    from api.models import Action
    if not user:
        user = generate_username(req, ae)

    u = User(username=user)
    u.is_active = active
    if password:
        u.set_password(password)
    u.save()

    u.userdata.event = ae
    u.userdata.save()

    is_anon = creator is None or isinstance(creator, AnonymousUser)

    action = Action(
        executer=u if is_anon else creator,
        receiver=u,
        action_name='user:register' if is_anon else 'user:added-to-census',
        event=ae,
        metadata=get_trimmed_user_req(req, ae))
    action.save()

    return edit_user(u, req, ae)

def check_metadata(req, user):
    meta = user.userdata.metadata
    extra = user.userdata.event.extra_fields
    if not extra:
        return ""

    for field in extra:
        if field.get('required_on_authentication'):
            name = field.get('name')
            typee = field.get('type')

            user_value = meta.get(name)
            if (typee == 'email'):
                user_value = user.email
            elif (typee == 'tlf'):
                user_value = user.userdata.tlf

            if not constant_time_compare(user_value, req.get(name)):
                return "Incorrect authentication."
    return ""

def post_verify_fields_on_auth(user, req, auth_event):
    '''
    Verifies fields that cannot be verified during the user orm query on the 
    database. Currently this is only password fields.
    '''
    if auth_event.extra_fields:
        for field in auth_event.extra_fields:
            if not field.get('required_on_authentication'):
                continue
            
            # Raise exception if a required field is not provided.
            # It will be catched by parent as an error.
            if field.get('name') not in req:
                raise Exception()

            value = req.get(field.get('name'), '')
            typee = field.get('type')
            if typee == 'password':
                user.check_password(value)


def get_required_fields_on_auth(req, ae, q):
    '''
    Modifies a Q query adding required_on_authentication fields with the values
    from the http request, used to filter users
    '''
    if ae.extra_fields:
        for field in ae.extra_fields:
            if not field.get('required_on_authentication'):
                continue
            
            # Raise exception if a required field is not provided.
            # It will be catched by parent as an error.
            if field.get('name') not in req:
                raise Exception()

            value = req.get(field.get('name'), '')
            typee = field.get('type')
            if typee == 'email':
                q = q & Q(email=value)
            elif typee == 'tlf':
                q = q & Q(userdata__tlf=value)
            elif typee == 'password':
                # we verify this later im post_verify_fields_on_auth
                continue
            else:
                q = q & Q(userdata__metadata__contains={field.get('name'): value})

    return q

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

    # generate the user auth-token
    data['auth-token'] = genhmac(settings.SHARED_SECRET, user.username)
    if auth_event is None:
        auth_event = user.userdata.event

    if auth_event.children_election_info is None:
        msg = ':'.join((user.username, 'AuthEvent', str(auth_event.id), 'vote'))
        data['vote-permission-token'] = genhmac(settings.SHARED_SECRET, msg)
    else:
        def get_child_info(event_id):
            auth_event = AuthEvent.objects.get(pk=event_id)

            num_successful_logins = user\
                .userdata\
                .successful_logins\
                .filter(is_active=True, auth_event=auth_event)\
                .count()

            if (auth_event.num_successful_logins_allowed == 0 or\
                num_successful_logins < auth_event.num_successful_logins_allowed) and\
                event_id in user.userdata.children_event_id_list:

                msg = ':'.join((user.username, 'AuthEvent', str(event_id), 'vote'))
                auth_token = genhmac(settings.SHARED_SECRET, msg)
            else:
                auth_token = None
            
            return {
                'auth-event-id': event_id,
                'vote-permission-token': auth_token,
                'num-successful-logins-allowed': auth_event.num_successful_logins_allowed,
                'num-successful-logins': num_successful_logins
            }

        data['vote-children-info'] = [
            get_child_info(child_event_id)
            for child_event_id in auth_event.children_election_info["natural_order"]
        ]
             

    # add redirection
    auth_action = auth_event.auth_method_config['config']['authentication-action']
    if auth_action['mode'] == 'go-to-url':
        data['redirect-to-url'] = auth_action['mode-config']['url']

    LOGGER.debug(\
        "%s.authenticate success\n"\
        "returns '%r'\n"\
        "authevent '%r'\n"\
        "request '%r'\n"\
        "Stack trace: \n%s",\
        logger_name, data, auth_event, req_json, stack_trace_str())
    return data

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

def get_base_auth_query(auth_event):
    '''
    returns the base authenticatio query for the given auth_event
    '''
    q = Q(
        userdata__event=auth_event,
        is_active=True
    )
    
    if auth_event.children_election_info is not None:
        q = q | Q(
            userdata__event_id__in=auth_event.children_election_info['natural_order'],
            is_active=True
        )
    return q