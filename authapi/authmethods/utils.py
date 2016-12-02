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
import re
import os
import binascii
from base64 import decodestring
from datetime import timedelta
from django.conf import settings
from django.contrib.auth.models import User
from django.utils import timezone
from django.db.models import Q

from .models import ColorList, Message, Code
from api.models import ACL
from captcha.models import Captcha
from captcha.decorators import valid_captcha
from contracts import CheckException, JSONContractEncoder
from utils import json_response, get_client_ip, is_valid_url
from pipelines.base import execute_pipeline, PipeReturnvalue


EMAIL_RX = re.compile(
    r"(^[-!#$%&'*+/=?^_`{}|~0-9A-Z]+(\.[-!#$%&'*+/=?^_`{}|~0-9A-Z]+)*"  # dot-atom
    # quoted-string, see also http://tools.ietf.org/html/rfc2822#section-3.2.5
    r'|^"([\001-\010\013\014\016-\037!#-\[\]-\177]|\\[\001-\011\013\014\016-\177])*"'
    r')@((?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)$)'  # domain
    r'|\[(25[0-5]|2[0-4]\d|[0-1]?\d?\d)(\.(25[0-5]|2[0-4]\d|[0-1]?\d?\d)){3}\]$', re.IGNORECASE)  # literal form, ipv4 address (SMTP 4.1.3)

DNI_RX = re.compile("[A-Z]?[0-9]{7,8}[A-Z]", re.IGNORECASE)
LETTER_RX = re.compile("[A-Z]", re.IGNORECASE)
RET_PIPE_CONTINUE = 0


def error(message="", status=400, field=None, error_codename=None):
    ''' Returns an error message '''
    return json_response(status=400, message=message, field=field, error_codename=error_codename)


def random_username():
    # 30 hex digits random username
    username = binascii.b2a_hex(os.urandom(14))
    try:
        User.objects.get(username=username)
        return random_username()
    except User.DoesNotExist:
        return username;


def email_constraint(val):
    ''' check that the input is an email string '''
    if not isinstance(val, str):
        return False
    return EMAIL_RX.match(val)


def dni_constraint(val):
    ''' check that the input is a valid dni '''
    if not isinstance(val, str):
        return False

    val2 = val.upper()
    if not DNI_RX.match(val2):
        return False

    if LETTER_RX.match(val2[0]):
        nie_letter = val2[0]
        val2 = val2[1:]
        if nie_letter == 'Y':
            val2 = "1" + val2
        elif nie_letter == 'Z':
            val2 = "2" + val2

    mod_letters = 'TRWAGMYFPDXBNJZSQVHLCKE'
    digits = val2[:-1]
    letter = val2[-1].upper()

    expected = mod_letters[int(digits) % 23]

    return letter == expected

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
        item = ColorList.objects.filter(key=ColorList.KEY_IP, value=ip_addr,
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
        item = ColorList.objects.filter(key=ColorList.KEY_IP, value=ip_addr,
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
                       key=ColorList.KEY_IP, value=ip_addr,
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
        return RET_PIPE_CONTINUE

    ip_addr = data['ip_addr']
    if period:
        time_threshold = timezone.now() - timedelta(seconds=period)
        item = Message.objects.filter(
            ip=ip_addr,
            created__gt=time_threshold,
            auth_event_id=data['auth_event'].id)
    else:
        item = Message.objects.filter(
            ip=ip_addr,
            auth_event_id=data['auth_event'].id)

    if len(item) >= total_max:
        cl = ColorList(action=ColorList.ACTION_BLACKLIST,
                       key=ColorList.KEY_IP, value=ip_addr,
                       auth_event_id=data['auth_event'].id)
        cl.save()
        return error("Blacklisted", error_codename="blacklisted")
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


def check_pipeline(request, ae, step='register', default_pipeline=None):
    req = json.loads(request.body.decode('utf-8'))
    if req.get('tlf'):
        req['tlf'] = get_cannonical_tlf(req['tlf'])
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
            msg += check_field_type(extra, req.get(extra.get('name')), step)
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
    if ae.auth_method == 'email':
        user.email = req.get('email')
        req.pop('email')
    elif ae.auth_method == 'sms':
        if req['tlf']:
            user.userdata.tlf = get_cannonical_tlf(req['tlf'])
        else:
            user.userdata.tlf = req['tlf']
        req.pop('tlf')
    if ae.extra_fields:
        for extra in ae.extra_fields:
            if extra.get('type') == 'email':
                user.email = req.get(extra.get('name'))
                req.pop(extra.get('name'))
            elif extra.get('type') == 'tlf':
                if req[extra.get('name')]:
                    user.userdata.tlf = get_cannonical_tlf(req[extra.get('name')])
                else:
                    user.userdata.tlf = req[extra.get('name')]
                req.pop(extra.get('name'))
            elif extra.get('type') == 'password':
                user.set_password(req.get(extra.get('name')))
                req.pop(extra.get('name'))
            if extra.get('type') == 'image':
                img = req.get(extra.get('name'))
                fname = user.username.decode()
                path = os.path.join(settings.IMAGE_STORE_PATH, fname)
                head, img2 = img.split('base64,')
                with open(path, "w") as f:
                    #f.write(decodestring(img.encode()))
                    f.write(img)
                req[extra.get('name')] = fname
    user.save()
    user.userdata.metadata = req
    user.userdata.save()
    return user


def create_user(req, ae, active=False):
    user = random_username()
    u = User(username=user)
    u.is_active = active
    u.save()
    u.userdata.event = ae
    u.userdata.save()
    return edit_user(u, req, ae)


def check_metadata(req, user):
    meta = user.userdata.metadata
    if type(meta) == str:
        meta = json.loads(meta)
    extra = user.userdata.event.extra_fields
    if not extra:
        return ""

    for field in extra:
        if field.get('required_on_authentication'):
            name = field.get('name')
            typee = field.get('type')
            if (typee == 'email'):
                if user.email != req.get(name):
                    return "Incorrect authentication."
            elif (typee == 'tlf'):
                if user.userdata.tlf != req.get(name):
                    return "Incorrect authentication."
            else:
                if meta.get(name) != req.get(name):
                    return "Incorrect authentication."
    return ""


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
            acl, created = ACL.objects.get_or_create(user=u.userdata, object_type=obj, perm=perm, object_id=obj_id)
            acl.save()
    return ''
