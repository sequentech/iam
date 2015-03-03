import json
import re
import os
import binascii
from datetime import timedelta
from django.conf import settings
from django.contrib.auth.models import User
from django.http import HttpResponse
from django.utils import timezone
from .models import ColorList, Message, Code
from api.models import ACL
from captcha.models import Captcha
from captcha.decorators import valid_captcha


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
    '''
    Returns an error message
    '''
    data = dict(message=message, field=field, error_codename=error_codename)
    jsondata = json.dumps(data)
    return HttpResponse(jsondata, status=status, content_type='application/json')


def random_username():
    # 30 hex digits random username
    username = binascii.b2a_hex(os.urandom(14))
    try:
        User.objects.get(username=username)
        return random_username()
    except User.DoesNotExist:
        return username;


def get_client_ip(request):
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip


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
    period = kwargs.get('period')
    if data.get('whitelisted', False) == True:
        return RET_PIPE_CONTINUE

    ip_addr = data['ip_addr']
    tlf = data['tlf']
    if period:
        time_threshold = timezone.now() - timedelta(seconds=period)
        # Fix
        item = Message.objects.filter(tlf=tlf, created__lt=time_threshold,
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
    if data.get('whitelisted', False) == True:
        return RET_PIPE_CONTINUE

    ip_addr = data['ip_addr']
    item = Message.objects.filter(ip=ip_addr, auth_event_id=data['auth_event'].id)
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
    check = check_tlf_total_max(data, **kwargs)
    if check != 0:
        return check
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


def check_pipeline(request, ae, step='register'):
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
    msg = ''
    if field is not None:
        if isinstance(field, str):
            if definition.get('type') == 'int' or definition.get('type') == 'bool':
                msg += "Field %s type incorrect, value %s" % (definition.get('name'), field)
            if len(field) > settings.MAX_GLOBAL_STR:
                msg += "Field %s incorrect len" % definition.get('name')
        elif isinstance(field, bool):
            if definition.get('type') != 'bool':
                msg += "Field %s type incorrect, value %s" % (definition.get('name'), field)
        elif isinstance(field, int):
            if definition.get('type') != 'int':
                msg += "Field %s type incorrect, value %s" % (definition.get('name'), field)
    return msg


def check_field_value(definition, field, step='register'):
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
        if definition.get('name') == 'dni':
            if not dni_constraint(field):
                msg += "Field dni regex incorrect, value %s" % field
        if definition.get('regex'):
            a = re.compile(definition.get('regex'))
            if not a.match(string):
                msg += "Field %s regex incorrect, value %s" % (definition.get('name'), field)
    return msg


def check_captcha(code, answer):
    if not code or not answer or not isinstance(code, str):
        return 'Invalid captcha'
    captcha = {'captcha_code': code, 'captcha_answer': answer}
    if not valid_captcha(captcha):
        return 'Invalid captcha'
    return ''


def check_fields_in_request(req, ae, step='register', validation=True):
    msg = ''
    if ae.extra_fields:
        if len(req) > settings.MAX_EXTRA_FIELDS * 2:
            return "Number of fields is bigger than allowed fields."
        for extra in ae.extra_fields:
            msg += check_field_type(extra, req.get(extra.get('name')), step)
            if validation:
                msg += check_field_value(extra, req.get(extra.get('name')), step)
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


def metadata_repeat(req, user, uniques):
    for unique in uniques:
        metadata = json.loads(user.userdata.metadata)
        if metadata.get(unique.get('name')) == req.get(unique.get('name')):
            return "%s %s repeat." % (unique.get('name'), req.get(unique.get('name')))
    return ''


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
        uniques = []
        for extra in ae.extra_fields:
            if 'unique' in extra.keys() and extra.get('unique'):
                uniques.append(extra)
        for user in User.objects.filter(userdata__event=ae):
            msg += metadata_repeat(req, user, uniques)
            if msg:
                break
    if not msg:
        return ''
    if get_repeated:
        return {'msg': msg, 'user': user}
    else:
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
    user.save()
    user.userdata.metadata = json.dumps(req)
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
    meta = json.loads(user.userdata.metadata)
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
    if u.is_active: # Active users don't give perms. Avoid will send code
        return ''
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
            acl = ACL(user=u.userdata, object_type=obj, perm=perm, object_id=obj_id)
            acl.save()
    return ''
