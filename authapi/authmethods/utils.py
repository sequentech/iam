import json
import re
import os
import binascii
from datetime import timedelta
from django.contrib.auth.models import User
from django.http import HttpResponse
from django.utils import timezone
from .models import ColorList, Message, Code
from api.models import ACL


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
        item = ColorList.objects.get(key=ColorList.KEY_TLF, value=tlf)
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
        item = ColorList.objects.filter(key=ColorList.KEY_IP, value=ip_addr)
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
                action=ColorList.ACTION_BLACKLIST)[0]
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
                action=ColorList.ACTION_BLACKLIST)[0]
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
        item = Message.objects.filter(tlf=tlf, created__lt=time_threshold)
    else:
        item = Message.objects.filter(tlf=tlf)
    if len(item) >= total_max:
        c1 = ColorList(action=ColorList.ACTION_BLACKLIST,
                       key=ColorList.KEY_IP, value=ip_addr)
        c1.save()
        c2 = ColorList(action=ColorList.ACTION_BLACKLIST,
                       key=ColorList.KEY_TLF, value=tlf)
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
    item = Message.objects.filter(ip=ip_addr)
    if len(item) >= total_max:
        cl = ColorList(action=ColorList.ACTION_BLACKLIST,
                       key=ColorList.KEY_IP, value=ip_addr)
        cl.save()
        return error("Blacklisted", error_codename="blacklisted")
    return RET_PIPE_CONTINUE


def check_sms_code(req, ae, **kwargs):
    time_thr = timezone.now() - timedelta(seconds=kwargs.get('timestamp'))
    try:
        u = User.objects.get(userdata__tlf=req.get('tlf'), userdata__event=ae)
        code = Code.objects.get(user=u.pk, code=req.get('code'),
                created__gt=time_thr)
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
    conn = Connection.objects.filter(tlf=req.get('tlf')).count()
    if conn >= kwargs.get('times'):
        return error('Exceeded the level os attempts',
                error_codename='check_total_connection')
    conn = Connection(ip=data['ip'], tlf=data['tlf'])
    conn.save()
    return RET_PIPE_CONTINUE


def check_pipeline(request, ae, step='register'):
    req = json.loads(request.body.decode('utf-8'))
    data = {'ip_addr': get_client_ip(request), 'tlf': req.get('tlf')}

    pipeline = ae.auth_method_config.get('pipeline').get('%s-pipeline' % step)
    for pipe in pipeline:
        if pipe[0] == 'check_sms_code':
            check = getattr(eval(pipe[0]), '__call__')(req, ae, **pipe[1])
        else:
            check = getattr(eval(pipe[0]), '__call__')(data, **pipe[1])
        if check:
            data.update(json.loads(check.content.decode('utf-8')))
            data['status'] = check.status_code
            return data
    return RET_PIPE_CONTINUE


# Checkers census, register and authentication
def check_value(definition, field, step='register'):
    msg = ''
    if step == 'authenticate' and not definition.get('required_on_authentication'):
        return msg
    if field is None:
        if definition.get('required') and definition.get('type') != 'captcha':
            msg += "Field %s is required" % definition.get('name')
    else:
        if isinstance(field, str):
            if definition.get('type') == 'int' or definition.get('type') == 'bool':
                msg += "Field %s type incorrect, value %s" % (definition.get('name'), field)
            if definition.get('min') and len(field) < definition.get('min'):
                msg += "Field %s min incorrect, value %s" % (definition.get('name'), field)
            if definition.get('max') and len(field) > definition.get('max'):
                msg += "Field %s max incorrect, value %s" % (definition.get('name'), field)
        elif isinstance(field, bool):
            if definition.get('type') != 'bool':
                msg += "Field %s type incorrect, value %s" % (definition.get('name'), field)
        elif isinstance(field, int):
            if definition.get('type') != 'int':
                msg += "Field %s type incorrect, value %s" % (definition.get('name'), field)
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


def check_fields_in_request(req, ae, step='register'):
    msg = ''
    if ae.extra_fields:
        for extra in ae.extra_fields:
            msg += check_value(extra, req.get(extra.get('name')), step)
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
            return "%s %s repeat." %(unique['name'], req[unique['name']])
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
            user = User.objects.get(userdata__tlf=req.get('tlf'), userdata__event=ae)
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


def create_user(req, ae, active=False):
    user = random_username()
    u = User(username=user)
    u.is_active = active

    if req.get('email'):
        u.email = req.get('email')
        req.pop('email')
    u.save()

    if req.get('tlf'):
        u.userdata.tlf = req.get('tlf')
        req.pop('tlf')

    u.userdata.event = ae
    u.userdata.metadata = json.dumps(req)
    u.userdata.save()
    return u


def edit_user(user, req):
    if req.get('email'):
        user.email = req.get('email')
        req.pop('email')
        user.save()

    if req.get('tlf'):
        user.userdata.tlf = req.get('tlf')
        req.pop('tlf')

    user.userdata.metadata = json.dumps(req)
    user.userdata.save()
    return user


def check_metadata(req, user):
    meta = json.loads(user.userdata.metadata)
    extra = user.userdata.event.extra_fields
    if not extra:
        return ""

    for field in extra:
        if field.get('required_on_authentication'):
            name = field.get('name')
            if (name == 'email'):
                if user.email != req.get(name):
                    return "Incorrent authentication."
            elif (name == 'tlf'):
                if user.userdata.tlf != req.get(name):
                    return "Incorrent authentication."
            else:
                if meta.get(name) != req.get(name):
                    return "Incorrent authentication."
    return ""


def give_perms(u, ae):
    if u.is_active: # Active users don't give perms. Avoid will send code
        return ''
    config = ae.auth_method_config.get('config')
    if not config:
        return 'Bad config'
    give_perms = config.get('give_perms')
    if give_perms:
        obj = give_perms.get('object_type')
        obj_id = give_perms.get('object_id', 0)
        for perm in give_perms.get('perms'):
            acl = ACL(user=u.userdata, object_type=obj, perm=perm, object_id=obj_id)
            acl.save()
    acl = ACL(user=u.userdata, object_type='UserData', perm='edit', object_id=u.pk)
    acl.save()
    acl = ACL(user=u.userdata, object_type='AuthEvent', perm='vote', object_id=ae.pk)
    acl.save()
    return ''
