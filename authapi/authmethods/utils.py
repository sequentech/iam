import json
import re
from django.contrib.auth.models import User
from django.http import HttpResponse
from random import choice
from string import ascii_lowercase, digits
from uuid import uuid4

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
    username = uuid4()
    try:
        User.objects.get(username=username)
        return random_username()
    except User.DoesNotExist:
        return username;


def random_code(length=16, chars=ascii_lowercase+digits):
    return ''.join([choice(chars) for i in range(length)])
    return code;


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


def check_tlf_total_max(data, total_max=7):
    '''
    if tlf has been sent >= MAX_SMS_LIMIT failed-sms in total->blacklist, error
    '''
    if data.get('whitelisted', False) == True:
        return RET_PIPE_CONTINUE

    ip_addr = data['ip_addr']
    tlf = data['tlf']
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


def check_ip_total_max(data, total_max=7):
    '''
    if the ip has been sent more than <total_max> messages that have not been
    authenticated, blacklist it
    '''
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
