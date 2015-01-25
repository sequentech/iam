import json
import re
import os
import binascii
from datetime import timedelta
from django.contrib.auth.models import User
from django.http import HttpResponse
from django.utils import timezone
from .models import ColorList, Message


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


def check_tlf_whitelisted(data):
    ''' If tlf is whitelisted, accept '''
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


# Checkers census, register and authentication
def check_value(definition, field, step='register'):
    msg = ''
    if definition == 'email':
        definition = { "name": "email", "type": "text", "required": True, "min": 4, "max": 255, "required_on_authentication": True }
    elif definition == 'code':
        definition = { "name": "code", "type": "text", "required": True, "min": 6, "max": 255, "required_on_authentication": True }
    elif definition == 'tlf':
        definition = { "name": "tlf", "type": "text", "required": True, "min": 4, "max": 20, "required_on_authentication": True }

    if step == 'authentication' and not definition.get('required_on_authentication'):
        return msg
    if field is None:
        if definition.get('required'):
            msg += "Field %s is required" % definition.get('name')
    else:
        if isinstance(field, str):
            if definition.get('type') == 'int':
                msg += "Field %s type incorrect, value %s" % (definition.get('name'), field)
            if definition.get('min') and len(field) < definition.get('min'):
                msg += "Field %s min incorrect, value %s" % (definition.get('name'), field)
            if definition.get('max') and len(field) > definition.get('max'):
                msg += "Field %s max incorrect, value %s" % (definition.get('name'), field)
        elif isinstance(field, int):
            if definition.get('type') != 'int':
                msg += "Field %s type incorrect, value %s" % (definition.get('name'), field)
            if definition.get('min') and field < definition.get('min'):
                msg += "Field %s min incorrect, value %s" % (definition.get('name'), field)
            if definition.get('max') and field > definition.get('max'):
                msg += "Field %s max incorrect, value %s" % (definition.get('name'), field)
        if definition.get('name') == 'email':
            if not email_constraint(field):
                msg += "Field email regex incorrect, value %s" % field
        if definition.get('name') == 'dni':
            if not dni_constraint(field):
                msg += "Field dni regex incorrect, value %s" % field
        elif definition.get('regex'):
            a = re.compile(definition.get('regex'))
            if not a.match(string):
                msg += "Field %s regex incorrect, value %s" % (definition.get('name'), field)
    return msg


def check_fields_in_request(req, ae, step='register'):
    msg = ''
    if ae.auth_method == 'email':
        msg += check_value('email', req.get('email'))
    elif ae.auth_method == 'sms':
        msg += check_value('tlf', req.get('tlf'))
    if step == 'authentication':
        msg += check_value('code', req.get('code'))
    if ae.extra_fields:
        for extra in ae.extra_fields:
            msg += check_value(extra, req.get(extra.get('name')))
    return msg


def check_census(req, ae):
    msg = ''
    for r in req:
        msg += check_fields_in_request(r, ae)
    return msg


def is_user_repeat(req, ae):
    msg = ''
    if ae.auth_method == 'email':
        if len(User.objects.filter(email=req.get('email'), userdata__event=ae)):
            msg += "Email %s repeat." % req.get('email')
    elif ae.auth_method == 'sms':
        if len(User.objects.filter(userdata__tlf=req.get('tlf'), userdata__event=ae)):
            msg += "Tlf %s repeat." % req.get('tlf')
    return msg


def create_user(req, ae):
    user = random_username()
    u = User(username=user)
    u.is_active = False

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
