#!/usr/bin/env python3
import hmac
import datetime
import json
import time
import six
from djcelery import celery
from django.contrib.auth.models import User
from django.core.exceptions import PermissionDenied
from django.core.mail import send_mail, EmailMessage
from django.core.paginator import Paginator
from django.conf import settings
from django.http import HttpResponse
from enum import Enum, unique
from string import ascii_lowercase, digits, ascii_letters
from random import choice


@unique
class ErrorCodes(Enum):
    BAD_REQUEST = 1
    INVALID_REQUEST = 2
    INVALID_CODE = 3
    INVALID_PERMS = 4
    GENERAL_ERROR = 5
    MAX_CONNECTION = 6
    BLACKLIST = 7


def json_response(data=None, status=200, message="", field=None, error_codename=None):
    ''' Returns a json response '''
    if status != 200:
        if not error_codename:
            error_codename = ErrorCodes.GENERAL_ERROR
        data = dict(message=message, field=field, error_codename=error_codename.name)
    jsondata = json.dumps(data)
    return HttpResponse(jsondata, status=status, content_type='application/json')


def permission_required(user, object_type, permission, object_id=0):
    if user.is_superuser:
        return
    if object_id and user.userdata.has_perms(object_type, permission, 0):
        return
    if not user.userdata.has_perms(object_type, permission, object_id):
        raise PermissionDenied('Permission required: ' + permission)


def paginate(request, queryset, serialize_method=None, elements_name='elements'):
    '''
    Function to paginate a queryset using the request params
    ?page=1&n=10
    '''

    index = request.GET.get('page', 1)
    elements = request.GET.get('n', 10)
    order = request.GET.get('order', None)
    if order:
        queryset = queryset.order_by(order)

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


def verifyhmac(key, msg, seconds=300, at=None):
    if at is None:
        at = HMACToken(msg)
    digest = at.digest if at.digest != 'sha-256' else 'sha256'
    h = hmac.new(key, at.msg.encode('utf-8'), digest)
    valid = hmac.compare_digest(h.hexdigest(), at.hash)

    valid = valid and at.check_expiration(seconds)
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
        self.userid, self.timestamp = self.msg.split(':')
        self.timestamp = self.msg.split(':')[-1]

    def check_expiration(self, seconds=300):
        t = self.timestamp
        n = datetime.datetime.now()
        d = datetime.datetime.fromtimestamp(int(t))
        d = d + datetime.timedelta(seconds=seconds)
        return d > n

    def get_userid(self):
        '''
        Note! Can only be used if it's an auth token, with userid
        '''
        userid, _ = self.msg.split(':')
        return userid



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

def generate_code(userdata, size=settings.SIZE_CODE):
    """ Generate necessary codes for different authmethods. """
    from authmethods.models import Code
    code = random_code(size, "ABCDEFGHJKLMNPQRSTUVWXYZ23456789")
    c = Code(user=userdata, code=code, auth_event_id=userdata.event.id)
    c.save()
    return code


def send_email(email):
    try:
        email.send(fail_silently=True)
    except:
        pass


@celery.task
def send_mail(subject, msg, receiver):
    email = EmailMessage(
        subject,
        msg,
        settings.DEFAULT_FROM_EMAIL,
        [receiver]
    )
    send_email(email)


def send_sms_code(receiver, msg, conf):
    from authmethods.sms_provider import SMSProvider
    con = SMSProvider.get_instance()
    con.send_sms(receiver=receiver, content=msg, is_audio=False)


def send_code(user, config=None):
    '''
    Sends the code for authentication in the related auth event, to the user
    in a message sent via sms or email, depending on the authentication method
    of the auth event.

    The message will be automatically completed with the base message in
    settings.

    NOTE: You are responsible of not calling this on a stopped auth event
    '''
    from authmethods.models import Message
    auth_method = user.userdata.event.auth_method
    conf = user.userdata.event.auth_method_config.get('config')
    event_id = user.userdata.event.id

    # if blank tlf or email
    if auth_method == "sms" and not user.userdata.tlf:
        return
    elif auth_method == "email" and not user.email:
        return

    code = generate_code(user.userdata)

    if auth_method == "sms":
        receiver = user.userdata.tlf
        url = settings.SMS_AUTH_CODE_URL % dict(authid=event_id, code=code, email=user.email)
    else: # email
        receiver = user.email
        url = settings.EMAIL_AUTH_CODE_URL % dict(authid=event_id, code=code, email=user.email)

    if receiver is None:
        return "Receiver is none"

    if config is None:
        msg = conf.get('msg')
        subject = conf.get('subject')
    else:
        msg = config.get('msg')
        subject = config.get('subject')

    if auth_method == "sms":
        base_msg = settings.SMS_BASE_TEMPLATE
    else: # email
        base_msg = settings.EMAIL_BASE_TEMPLATE
    raw_msg = msg % dict(event_id=event_id, code=code, url=url)
    msg = base_msg % raw_msg

    if auth_method == "sms":
        send_sms_code(receiver, msg, conf)
        m = Message(tlf=receiver, auth_event_id=event_id)
        m.save()
    else: # email
        from api.models import ACL
        acl = ACL.objects.filter(object_type='AuthEvent', perm='edit',
                object_id=event_id).first()
        email = EmailMessage(
            subject,
            msg,
            settings.DEFAULT_FROM_EMAIL,
            [receiver],
            headers = {'Reply-To': acl.user.user.email}
        )
        send_email(email)


@celery.task
def send_codes(users, config=None):
    ''' Massive send_code with celery task.  '''
    user_objs = User.objects.filter(id__in=users)
    for user in user_objs:
        send_code(user, config)


# CHECKERS AUTHEVENT
VALID_FIELDS = ('name', 'help', 'type', 'required', 'regex', 'min', 'max',
    'required_on_authentication', 'unique')
REQUIRED_FIELDS = ('name', 'type', 'required_on_authentication')
VALID_PIPELINES = ('check_whitelisted', 'check_blacklisted',
        'check_total_max', 'check_total_connection')
VALID_TYPE_FIELDS = ('text', 'password', 'int', 'bool', 'regex', 'email', 'tlf',
        'captcha', 'textarea')

def check_authmethod(method):
    """ Check if method exists in method list. """
    from authmethods import METHODS
    if method in METHODS.keys():
        return ''
    else:
        return "Invalid authmethod\n"

def check_colorlist(fields):
    """
    Check if pipeline colorlist is correct for add to auth_method_config.
    """
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
    """
    Check if pipeline total max petitions is correct for add to
    auth_method_config.
    """
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
    """
    Check if pipeline total connections is correct for add to
    auth_method_config.
    """
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
    """ Check if sms code pipeline is correct for add to auth_method_config. """
    msg = ''
    for field in fields:
        if field in ('timestamp'):
            if field == 'timestamp':
                if not isinstance(fields[field], int):
                    msg += "Invalid pipeline field: bad %s.\n" % field
        else:
            msg += "Invalid pipeline field: %s not possible.\n" % field
    return msg

def check_pipeline(pipe):
    """
    Check pipeline when create auth-event. This function call to other function
    for checker if all pipeline is correct for add to auth_method_config.
    """
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

def check_fields(key, value):
    """ Check fields in extra_fields when create auth-event. """
    from sys import maxsize
    msg = ''
    if key == 'name' or key == 'help':
        if len(value) > settings.MAX_SIZE_NAME_EXTRA_FIELD or len(value) < 1:
            msg += "Invalid extra_fields: bad %s.\n" % key
    elif key == 'type':
        if not value in VALID_TYPE_FIELDS:
            msg += "Invalid extra_fields: bad %s.\n" % key
    elif key in ('required', 'required_on_authentication', 'unique'):
        if not isinstance(value, bool):
            msg += "Invalid extra_fields: bad %s.\n" % key
    elif key == 'regex':
        pass
    elif key == 'min' or key == 'max':
        if not isinstance(value, int):
            msg += "Invalid extra_fields: bad %s.\n" % key
        else:
            if value >= maxsize or value <= -maxsize :
                msg += "Invalid extra_fields: bad %s.\n" % key
    return msg

def check_extra_fields(fields, used_type_fields=[]):
    """ Check extra_fields when create auth-event. """
    msg = ''
    if len(fields) > settings.MAX_EXTRA_FIELDS:
        return "Maximum number of fields reached"
    used_fields = ['status']
    used_type_fields = used_type_fields
    for field in fields:
        if field.get('name') in used_fields:
            msg += "Two fields with same name: %s.\n" % field.get('name')
        used_fields.append(field.get('name'))
        if field.get('type') in used_type_fields:
            msg += "Type %s not allowed.\n" % field.get('type')
        for required in REQUIRED_FIELDS:
            if not required in field.keys():
                msg += "Required field %s.\n" % required
        for key in field.keys():
            if key in VALID_FIELDS:
                msg += check_fields(key, field.get(key))
            else:
                msg += "Invalid extra_field: %s not possible.\n" % key
    return msg
