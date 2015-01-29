#!/usr/bin/env python3
import hmac
import datetime
import json
import time
import six
from authmethods import METHODS
from djcelery import celery
from django.core.mail import send_mail, EmailMessage
from django.core.paginator import Paginator
from django.conf import settings
from string import ascii_lowercase, digits, ascii_letters
from random import choice


def paginate(request, queryset, serialize_method=None, elements_name='elements'):
    '''
    Function to paginate a queryset using the request params
    ?page=1&n=10
    '''

    index = request.GET.get('page', 1)
    elements = request.GET.get('n', 10)

    try:
        pageindex = int(index)
    except:
        pageindex = 1

    try:
        elements = int(elements)
    except:
        elements = 10

    if elements > 30:
        elements = 30

    p = Paginator(queryset, elements)
    page = p.page(pageindex)

    d = {
        elements_name: page.object_list,
        'page': pageindex,
        'total_count': p.count,
        'page_range': p.page_range,
        'start_index': page.start_index(),
        'end_index': page.end_index(),
        'has_next': page.has_next(),
        'has_previous': page.has_previous(),
    }

    if serialize_method:
        d[elements_name] = []
        for i in page.object_list:
            d[elements_name].append(getattr(i, serialize_method)())
    return d


def genhmac(key, msg):
    timestamp = int(datetime.datetime.now().timestamp())
    msg = "%s:%s" % (msg, str(timestamp))

    h = hmac.new(key, msg.encode('utf-8'), "sha256")
    return 'khmac:///sha-256;' + h.hexdigest() + '/' + msg


def verifyhmac(key, msg, seconds=300):
    at = HMACToken(msg)
    digest = at.digest if at.digest != 'sha-256' else 'sha256'
    h = hmac.new(key, at.msg.encode('utf-8'), digest)
    valid = hmac.compare_digest(h.hexdigest(), at.hash)

    t = at.timestamp
    n = datetime.datetime.now()
    d = datetime.datetime.fromtimestamp(int(t))
    d = d + datetime.timedelta(seconds=seconds)

    valid = valid and d > n
    return valid


class HMACToken:
    def __init__(self, token):
        self.token = token
        l = len('khmac:///')
        self.head = token[0:l]
        msg = token[l:]
        self.digest, msg = msg.split(';')
        self.hash, msg = msg.split('/')
        self.msg = msg
        self.timestamp = self.msg.split(':')[-1]


class AuthToken(HMACToken):
    def __init__(self, token):
        super(AuthToken, self).__init__(token)
        self.userid, self.timestamp = self.msg.split(':')


def constant_time_compare(val1, val2):
    """
    Returns True if the two strings are equal, False otherwise.
    The time taken is independent of the number of characters that match.
    For the sake of simplicity, this function executes in constant time only
    when the two strings have the same length. It short-circuits when they
    have different lengths. Since Django only uses it to compare hashes of
    known expected length, this is acceptable.
    """
    if len(val1) != len(val2):
        return False
    result = 0
    if six.PY3 and isinstance(val1, bytes) and isinstance(val2, bytes):
        for x, y in zip(val1, val2):
            result |= x ^ y
    else:
        for x, y in zip(val1, val2):
            result |= ord(x) ^ ord(y)
    return result == 0


def random_code(length=16, chars=ascii_lowercase+digits):
    return ''.join([choice(chars) for i in range(length)])
    return code;


def generate_code(userdata):
    from authmethods.models import Code
    if userdata.event.auth_method == 'email':
        code = random_code(64, ascii_letters+digits)
    elif userdata.event.auth_method == 'sms':
        code = random_code(8, ascii_letters+digits)
    c = Code(user=userdata, code=code)
    c.save()
    return code


@celery.task
def send_email(email):
    email.send()


@celery.task
def send_sms_code(receiver, msg, conf):
    from authmethods.sms_provider import SMSProvider
    con = SMSProvider.get_instance(conf)
    con.send_sms(receiver=receiver, content=msg, is_audio=False)

def send_code(user, templ=None):
    '''
    Sends the code for authentication in the related auth event, to the user
    in a message sent via sms or email, depending on the authentication method
    of the auth event.

    The template will be automatically completed with the base template in
    settings.

    NOTE: You are responsible of not calling this on a stopped auth event
    '''
    from authmethods.models import Message
    auth_method = user.userdata.event.auth_method
    conf = user.userdata.event.auth_method_config.get('config')
    event_id = user.userdata.event.id

    code = generate_code(user.userdata)

    if auth_method == "sms":
        receiver = user.userdata.tlf
        url = settings.SMS_AUTH_CODE_URL % dict(authid=event_id, code=code, email=user.email)
    else: # email
        receiver = user.email
        url = settings.EMAIL_AUTH_CODE_URL % dict(authid=event_id, code=code, email=user.email)

    if receiver is None:
        return "Receiver is none"

    if auth_method == "sms":
        if templ is None:
            templ = conf.get('sms-message')
        base_msg = settings.SMS_BASE_TEMPLATE
    else: # email
        if templ is None:
            templ = conf.get('msg')
        base_msg = settings.EMAIL_BASE_TEMPLATE
    raw_msg = templ % dict(event_id=event_id, code=code, url=url)
    msg = base_msg % raw_msg

    if auth_method == "sms":
        send_sms_code(receiver, msg, conf)
        m = Message(tlf=receiver)
        m.save()
    else: # email
        from api.models import ACL
        acl = ACL.objects.filter(object_type='AuthEvent', perm='edit',
                object_id=event_id).first()
        email = EmailMessage(
            conf.get('subject'),
            msg,
            settings.DEFAULT_FROM_EMAIL,
            [receiver],
            headers = {'Reply-To': acl.user.user.email}
        )
        send_email(email)

# CHECKERS AUTHEVENT
VALID_FIELDS = ('name', 'help', 'type', 'required', 'regex', 'min', 'max',
    'required_on_authentication')
REQUIRED_FIELDS = ('name', 'type', 'required_on_authentication')
VALID_PIPELINES = ('check_whitelisted', 'check_blacklisted',
        'check_total_max', 'check_total_connection')

def check_colorlist(fields):
    msg = ''
    for field in fields:
        if field in ('field'):
            if field == 'field':
                if not fields[field] in ('tlf', 'ip'):
                    msg += "Invalid pipeline field: bad %s.\n" % field
        else:
            msg += "Invalid pipeline field: %s not possible.\n" % field
    return msg

def check_whitelisted(fields):
    return check_colorlist(fields)

def check_blacklisted(fields):
    return check_colorlist(fields)

def check_total_max(fields):
    msg = ''
    for field in fields:
        if field in ('field', 'max', 'period'):
            if field == 'field':
                if not fields[field] in ('tlf', 'ip'):
                    msg += "Invalid pipeline field: bad %s.\n" % field
            elif field == 'period':
                if not isinstance(fields[field], int):
                    msg += "Invalid pipeline field: bad %s.\n" % field
            elif field == 'max':
                if not isinstance(fields[field], int):
                    msg += "Invalid pipeline field: bad %s.\n" % field
        else:
            msg += "Invalid pipeline field: %s not possible.\n" % field
    return msg

def check_total_connection(fields):
    msg = ''
    for field in fields:
        if field in ('times'):
            if field == 'times':
                if not isinstance(fields[field], int):
                    msg += "Invalid pipeline field: bad %s.\n" % field
        else:
            msg += "Invalid pipeline field: %s not possible.\n" % field
    return msg

def check_sms_code(fields):
    msg = ''
    for field in fields:
        if field in ('timestamp'):
            if field == 'timestamp':
                if not isinstance(fields[field], int):
                    msg += "Invalid pipeline field: bad %s.\n" % field
        else:
            msg += "Invalid pipeline field: %s not possible.\n" % field
    return msg

def check_fields(key, value):
    msg = ''
    if key == 'name' or key == 'help':
        if len(value) > 255:
            msg += "Invalid extra_fields: bad %s.\n" % key
    elif key == 'type':
        if not value in ('text', 'password', 'int', 'bool', 'regex'):
            msg += "Invalid extra_fields: bad %s.\n" % key
    elif key == 'required' or key == 'required_on_authentication':
        if not isinstance(value, bool):
            msg += "Invalid extra_fields: bad %s.\n" % key
    elif key == 'regex':
        pass
    elif key == 'min' or key == 'max':
        if not isinstance(value, int):
            msg += "Invalid extra_fields: bad %s.\n" % key
    return msg

def check_authmethod(method):
    if method in METHODS.keys():
        return ''
    else:
        return "Invalid authmethods\n"

def check_config(config, method):
    msg = ''
    if method == 'email':
        for c in config:
            if not c in ('subject', 'msg'):
                msg += "Invalid config: %s not possible.\n" % c
    elif method == 'sms':
        for c in config:
            if c != "sms-message":
                msg += "Invalid config: %s not possible.\n" % c
    else:
        msg += "Invalid method in check_conf"
    return msg

def check_pipeline(pipe):
    msg = ''
    for p in pipe:
        if not p in ('register-pipeline', 'authenticate-pipeline'):
            msg += "Invalid pipeline: %s not possible.\n" % p
        for func in pipe[p]:
            if func[0] in VALID_PIPELINES:
                msg += getattr(eval(func[0]), '__call__')(func[1])
            else:
                msg += "Invalid pipeline functions: %s not possible.\n" % func
    return msg

def check_extra_fields(fields):
    msg = ''
    if len(fields) > 15:
        return "Maximum number of fields reached"
    for field in fields:
        for required in REQUIRED_FIELDS:
            if not required in field.keys():
                msg += "Required field %s.\n" % required
        for key in field.keys():
            if key in VALID_FIELDS:
                msg += check_fields(key, field.get(key))
            else:
                msg += "Invalid extra_field: %s not possible.\n" % key
    return msg
