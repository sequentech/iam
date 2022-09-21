#!/usr/bin/env python3

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

import hmac
import datetime
from django.utils import timezone
import dateutil.parser
import json
import types
import time
import six
import re
from logging import getLogger
import inspect
import traceback

from celery import shared_task
from django.core.validators import URLValidator
from django.core.exceptions import ValidationError
from django.contrib.auth.models import User
from django.core.exceptions import PermissionDenied
from django.core.mail import send_mail, EmailMessage, EmailMultiAlternatives
from django.core.paginator import Paginator
from django.conf import settings
from django.http import HttpResponse
from django.utils import timezone
from enum import IntEnum, unique
from string import ascii_lowercase, digits, ascii_letters
from random import choice
from pipelines import PipeReturnvalue
from pipelines.base import check_pipeline_conf
from contracts import CheckException, JSONContractEncoder
from time import sleep
import plugins

RE_SPLIT_FILTER = re.compile('(__lt|__gt|__equals|__in)')
RE_SPLIT_SORT = re.compile('__sort')
RE_INT = re.compile('^\d+$')
RE_BOOL = re.compile('^(true|false)$')
LOGGER = getLogger('iam.notify')


def stack_trace_str():
  frame = inspect.currentframe()
  stack_trace = traceback.format_stack(frame)
  return "\n".join(stack_trace[:-1]) + "\n" + traceback.format_exc()


@unique
class ErrorCodes(IntEnum):
    BAD_REQUEST = 1
    INVALID_REQUEST = 2
    INVALID_CODE = 3
    INVALID_PERMS = 4
    GENERAL_ERROR = 5
    MAX_CONNECTION = 6
    BLACKLIST = 7

def reproducible_json_dumps(s):
    return json.dumps(s, indent=4, ensure_ascii=False, sort_keys=True, separators=(',', ': '))

def parse_json_request(request):
    '''
    Returns the request body as a parsed json object
    '''
    return json.loads(request.body.decode('utf-8'))

def json_response(data=None, status=200, message="", field=None, error_codename=None):
    ''' Returns a json response '''
    if status != 200:
        if not error_codename:
            error_codename = ErrorCodes.GENERAL_ERROR
        if isinstance(error_codename, ErrorCodes):
            error_codename = error_codename.value
        error_data = dict(
            message=message,
            field=field, 
            error_codename=error_codename
        )
        if data is not None:
            error_data['data'] = data
        jsondata = json.dumps(error_data)
    else:
        jsondata = json.dumps(data)
    return HttpResponse(jsondata, status=status, content_type='application/json')


def permission_required(user, object_type, permission, object_id=0, return_bool=False):
    if user.is_superuser:
        return True

    if type(permission) is str:
        permissions = [permission]
    elif type(permission) is list:
        permissions = permission
    else:
        raise Exception("invalid permission type")

    if object_id:
        for perm in permissions:
            if user.userdata.has_perms(object_type, permission, 0):
                return True

    found = False
    for perm in permissions:
        if user.userdata.has_perms(object_type, perm, object_id):
            found = True

    if not found:
        if return_bool:
            return False
        else:
            raise PermissionDenied('Permission required: ' + str(permissions))

    if return_bool:
        return True

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
        if pageindex < 1:
            pageindex = 1
    except:
        pageindex = 1

    try:
        elements = int(elements)
    except:
        elements = 10

    if elements > 200:
        elements = 200

    p = Paginator(queryset, elements)
    page = p.page(pageindex)

    def serialize(obj):
      if serialize_method is None:
          return obj
      elif isinstance(serialize_method, str):
          return getattr(obj, serialize_method)()
      elif isinstance(serialize_method, types.FunctionType):
          return serialize_method(obj)

    return {
        elements_name: [serialize(obj) for obj in page.object_list],
        'page': pageindex,
        'total_count': p.count,
        'page_range': list(p.page_range),
        'start_index': page.start_index(),
        'end_index': page.end_index(),
        'has_next': page.has_next(),
        'has_previous': page.has_previous(),
    }

def genhmac(key, msg):
    timestamp = int(timezone.now().timestamp())
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
        tails = token[l:]
        self.digest, data = tails.split(';', 1)
        self.hash, self.msg = data.split('/', 1)
        msg_split = self.msg.split(':')
        self.timestamp = msg_split[-1]
        if len(msg_split) >= 5:
            self.userid = ':'.join(msg_split[0:-4])
            self.other_values = msg_split[-4:-1]
        else:
            self.userid = msg_split[0]
            self.other_values = msg_split[1:-1]

    def check_expiration(self, seconds=300):
        t = self.timestamp
        n = timezone.now()
        d = datetime.datetime.fromtimestamp(
            int(t),
            tz=timezone.get_current_timezone()
        )
        d = d + datetime.timedelta(seconds=seconds)
        return d > n

    def get_userid(self):
        '''
        Note! Can only be used if it's an auth token, with userid
        '''
        return self.userid

    def get_other_values(self):
        '''
        Removed the userid and the timestamp, returns the list of string objects
        in the message, that are separated by ':'
        '''
        return self.other_values


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
    # Generates codes from [2-9]. Numbers 1 and 0 are not included because they
    # can be mistaken with i and o.
    code_str = random_code(size, "2346789")
    code_object = Code(
        user=userdata,
        code=code_str,
        auth_event_id=userdata.event.id
    )
    code_object.save()
    return code_object

def verify_admin_generated_auth_code(
    auth_event,
    req_data,
    log_prefix
):
    '''
    Checks if the authentication data is for an user that got an authentication
    code generated by an admin user, and if so, authenticate this user
    '''
    if (
        '__username' not in req_data or
        not isinstance(req_data['__username'], str) or
        'code' not in req_data or
        not isinstance(req_data['code'], str)
    ):
        return False, None
    
    from authmethods.utils import (
        get_base_auth_query,
        disable_previous_user_codes,
        get_user_code
    )
    from django.db.models import Q
    
    username = req_data['__username']
    base_query = get_base_auth_query(
        auth_event,
        ignore_generated_code=True
    )
    query = base_query & Q(
        userdata__use_generated_auth_code=True,
        username=username
    )
    try:
        user = User.objects.get(query)
    except:
        return False, None

    code = get_user_code(user)

    if not code:       
        LOGGER.error(
            "%s.verify_admin_generated_auth_code error\n" +
            "Code not found on db for user '%r'\n" +
            "and time between now and '%r' seconds earlier\n" +
            "authevent '%r'\n" +
            "request '%r'\n" +
            "Stack trace: \n%s",
            log_prefix,
            user.userdata,
            settings.SMS_OTP_EXPIRE_SECONDS,
            auth_event, 
            req_data, stack_trace_str()
        )
        return False, None

    disable_previous_user_codes(user)

    if not constant_time_compare(req_data['code'], code.code):  
        LOGGER.error(
            "%s.verify_admin_generated_auth_code error\n" +
            "Code mismatch for user '%r'\n" +
            "Code received '%r'\n" +
            "and latest code in the db for the user '%r'\n" +
            "authevent '%r'\n" +
            "request '%r'\n" +
            "Stack trace: \n%s",
            log_prefix,
            user.userdata, 
            req_data['code'].upper(),
            code.code,
            auth_event,
            req_data,
            stack_trace_str()
        )
        return False, None

    return True, user

# Separate code into groups of 4 digits with hyphens ("-")
def format_code(code):
    return '-'.join(code[i:i+4] for i in range(0, len(code), 4))

def email_to_str(email):
    return '''to: %s
subject: %s
body:
%s
''' % (', '.join(email.to), email.subject, email.body)


def send_email(email):
    try:
        email.send(fail_silently=False)
        LOGGER.info('Email sent: \n%s', email_to_str(email))
    except:
        LOGGER.error('Email NOT sent: \n%s', email_to_str(email))


@shared_task(name="io.send_mail")
def send_mail(subject, msg, receiver):
    email = EmailMessage(
        subject,
        msg,
        settings.DEFAULT_FROM_EMAIL,
        [receiver]
    )
    send_email(email)


def send_sms_message(receiver, msg):
    try:
        from authmethods.sms_provider import SMSProvider
        con = SMSProvider.get_instance()
        con.send_sms(receiver=receiver, content=msg, is_audio=False)
        LOGGER.info('SMS sent: \n%s: %s', receiver, msg)
    except Exception as error:
        LOGGER.error('SMS NOT sent: \n%s: %s, error message %s', receiver, msg, str(error.args))
        LOGGER.error(error)

def template_replace_data(templ, data):
    '''
    Replaces the data key values in the template. Used by send_code.
    We use plain old string replace for security reasons.

    Example:
      template_replace_data("__FOO__ != __BAR__", dict(foo="foo1", bar="bar1"))
      >>> "foo1 != bar1"
    '''
    ret = templ
    for key, value in data.items():
        ret = ret.replace("__%s__" % key.upper(), str(value))
    return ret

def send_email_code(
    user,
    email_address,
    ip_address,
    templates,
    code=None
):
    if email_address is None:
        LOGGER.error(
            f"send_email_code error\n" +
            f"Receiver is None for user '{user}'\n" +
            f"authevent '{auth_event}'\n" +
            f"Stack trace: \n{stack_trace_str()}"
        )
        return "Receiver is none"

    from authmethods.models import Message, MsgLog
    from api.models import ACL
    auth_event = user.userdata.event
    message_body = templates['message_body']
    message_subject= templates['message_subject']
    message_html = templates.get('message_html')

    base_home_url = settings.HOME_URL
    home_url = template_replace_data(
      base_home_url,
      dict(event_id=auth_event.id)
    )
    receiver = email_address
    base_auth_url = settings.EMAIL_AUTH_CODE_URL

    url = template_replace_data(
        base_auth_url,
        dict(
            event_id=auth_event.id,
            receiver=receiver
        )
    )

    # initialize template data dict
    template_dict = dict(
        event_id=auth_event.id,
        url=url,
        home_url=home_url
    )
    if code is not None:
        template_dict['code'] = format_code(code)
        template_dict['url2'] = url + '/' + code
    if user.userdata.event.extra_fields:
        for field in user.userdata.event.extra_fields:
            if (
                'name' in field and
                'slug' in field and
                field['name'] in user.userdata.metadata
            ):
                template_dict[field['slug']] = user.userdata.metadata[field['name']]

    # base_msg is the base template, allows the iam superadmin to configure
    # a prefix or suffix to all messages
    # email
    base_message_subject = settings.EMAIL_BASE_TITLE_TEMPLATE
    raw_message_subject = template_replace_data(
        base_message_subject,
        dict(title=message_subject)
    )
    message_subject = template_replace_data(
        raw_message_subject,
        template_dict
    )

    base_message_body = settings.EMAIL_BASE_TEMPLATE
    raw_message_body = template_replace_data(
        base_message_body,
        dict(message=message_body)
    )
    message_body = template_replace_data(
        raw_message_body,
        template_dict
    )

    message_html = message_html if settings.ALLOW_HTML_EMAILS else None

    if message_html:
        message_html = template_replace_data(
            message_html,
            template_dict
        )


    # store the message log in the DB
    db_message_log = MsgLog(
        authevent_id=auth_event.id,
        receiver=receiver,
        msg=dict(
            subject=message_subject,
            msg=message_body,
            html_message=message_html
        )
    )
    db_message_log.save()

    headers = dict()

    # obtain the authevent administrator to use his
    # email address as the email reply-to address
    acl = ACL.objects.filter(
        object_type='AuthEvent',
        perm__in=['edit', 'unarchive'],
        object_id=auth_event.id
    ).first()

    if acl:
        headers['Reply-To'] = acl.user.user.email

    email = EmailMultiAlternatives(
        message_subject,
        message_body,
        settings.DEFAULT_FROM_EMAIL,
        [receiver],
        headers=headers,
    )
    if message_html:
        email.attach_alternative(message_html, 'text/html')
    send_email(email)
    
    db_message = Message(
        tlf=receiver[:20],
        ip=ip_address[:15],
        auth_event_id=auth_event.id
    )
    db_message.save()

def send_sms_code(
    user,
    tlf_number,
    ip_address,
    templates,
    code=None
):
    if tlf_number is None:
        LOGGER.error(
            f"send_sms_code error\n" +
            f"Receiver is None for user '{user}'\n" +
            f"authevent '{auth_event}'\n" +
            f"Stack trace: \n{stack_trace_str()}"
        )
        return "Receiver is none"

    from authmethods.models import Message, MsgLog
    auth_event = user.userdata.event
    message_body = templates['message_body']

    base_home_url = settings.HOME_URL
    home_url = template_replace_data(
      base_home_url,
      dict(event_id=auth_event.id)
    )
    receiver = tlf_number
    base_auth_url = settings.SMS_AUTH_CODE_URL

    url = template_replace_data(
        base_auth_url,
        dict(
            event_id=auth_event.id,
            receiver=receiver
        )
    )

    # initialize template data dict
    template_dict = dict(
        event_id=auth_event.id,
        url=url,
        home_url=home_url
    )
    if code is not None:
        template_dict['code'] = format_code(code)
        template_dict['url2'] = url + '/' + code
    if user.userdata.event.extra_fields:
        for field in user.userdata.event.extra_fields:
            if (
                'name' in field and
                'slug' in field and
                field['name'] in user.userdata.metadata
            ):
                template_dict[field['slug']] = user.userdata.metadata[field['name']]

    # base_msg is the base template, allows the iam superadmin to configure
    # a prefix or suffix to all messages
    base_message_body = settings.SMS_BASE_TEMPLATE
    raw_message_body = template_replace_data(
        base_message_body,
        dict(message=message_body)
    )
    message_body = template_replace_data(
        raw_message_body,
        template_dict
    )

    # store the message log in the DB
    db_message_log = MsgLog(
        authevent_id=auth_event.id,
        receiver=receiver,
        msg=dict(subject=None, msg=message_body)
    )
    db_message_log.save()

    send_sms_message(receiver, message_body)
    db_message = Message(
        tlf=receiver[:20],
        ip=ip_address[:15],
        auth_event_id=auth_event.id
    )
    db_message.save()

def send_code(
    user,
    ip_address,
    config=None,
    auth_method_override=None,
    code=None
):
    '''
    Sends the code for authentication in the related auth event, to the user
    in a message sent via sms and/or email, depending on the authentication
    method of the auth event and the fields it has. If election authentication
    method is email-otp but it also has an tlf extra field, it will also send
    authentication through that method.

    The message will be automatically completed with the base message in
    settings.

    NOTE: You are responsible of not calling this on a stopped auth event. In
    any case, if the event is stopped, the authentication won't work.
    '''
    from authmethods.utils import parse_otp_code_field

    # List containing the multiple paths through which we will send the OTP
    # codes. Each path has a format similar to:
    # dict(
    #     receiver="+34666666666",
    #     method="sms",
    #     templates=dict(
    #         message="Your code is __CODE__"
    #     )
    # )
    sending_paths = []

    auth_event = user.userdata.event
    auth_method = auth_event.auth_method
    auth_config = auth_event.auth_method_config.get('config')

    is_fixed_code = type(auth_config) is dict and auth_config.get('fixed-code')
    if is_fixed_code and not code:
        from authmethods.models import Code
        last_code = Code.objects.filter(
            user=user.userdata,
            auth_event_id=user.userdata.event.id,
            is_enabled=True
        ).order_by('created').last()
        if last_code:
            code = last_code.code

    if not code:
        code = generate_code(user.userdata).code
    base_config = (
        auth_config
        if not config
        else config
    )

    # If the override is not set, then for sure add the sending path related
    # to the specific auth-method of the election, if any
    if (
        (
            (
                auth_method_override is None and
                auth_method in ['sms', 'sms-otp']
            ) or
            auth_method_override in ['sms', 'sms-otp']
        ) and
        user.userdata.tlf is not None and
        len(user.userdata.tlf) > 0
    ):
        sending_paths\
            .append(dict(
                receiver=user.userdata.tlf,
                method="sms",
                templates=dict(
                    message_body=base_config.get('msg'),
                    message_subject=base_config.get('subject')
                ),
            ))
    if (
        (
            (
                auth_method_override is None and
                auth_method in ['email', 'email-otp']
            ) or
            auth_method_override in ['email', 'email-otp']
        ) and
        user.email is not None and
        len(user.email) > 0
    ):
        sending_paths\
            .append(dict(
                receiver=user.email,
                method="email",
                templates=dict(
                    message_body=base_config.get('msg'),
                    message_html=base_config.get('html_message'),
                    message_subject=base_config.get('subject')
                )
            ))

    # add a sending path for each related otp-field for which the user has a
    # corresponding usable extra_field
    if auth_method_override is None:
        otp_fields = []
        for extra_field in auth_event.extra_fields:
            if extra_field['type'] != 'otp-code':
                continue
            otp_field_error, otp_field = parse_otp_code_field(
                auth_event.extra_fields,
                extra_field
            )
            if otp_field_error is not None:
                LOGGER.error(
                    f"send_code error\n" +
                    "Error running parse_otp_code_field\n" +
                    f"authevent '{auth_event}'\n" +
                    f"extra_field '{extra_field}'\n" +
                    f"Stack trace: \n{stack_trace_str()}"
                )
                return
            otp_fields.append(otp_field)

        for otp_field in otp_fields:
            field_type = otp_field['source_field_type']
            field_name = otp_field['source_field']['name']
            otp_base_config =(
                dict()
                if config is None
                else config
            )
            templates = {
                **otp_field['otp_field']['templates'],
                **otp_base_config
            }
            if field_type == 'tlf':
                if (
                    field_name == 'tlf' and
                    isinstance(user.userdata.tlf, str) and
                    len(user.userdata.tlf) > 0
                ):
                    tlf = user.userdata.tlf
                elif (
                    field_name in user.userdata.metadata and
                    isinstance(user.userdata.metadata[field_name], str) and
                    len(user.userdata.metadata[field_name]) > 0
                ):
                    tlf = user.userdata.metadata[field_name]
                else:
                    continue

                sending_paths\
                    .append(dict(
                        receiver=tlf,
                        method="sms",
                        templates=templates
                    ))
            elif field_type == 'email':
                if (
                    field_name == 'email' and
                    isinstance(user.email, str) and
                    len(user.email) > 0
                ):
                    email = user.email
                elif (
                    field_name in user.userdata.metadata and
                    isinstance(user.userdata.metadata[field_name], str) and
                    len(user.userdata.metadata[field_name]) > 0
                ):
                    email = user.userdata.metadata[field_name]
                else:
                    continue

                sending_paths\
                    .append(dict(
                        receiver=email,
                        method="email",
                        templates=templates
                    ))

    # iterate within all the sending paths, and send messages through them
    for sending_path in sending_paths:
        method = sending_path['method']
        if method == 'sms':
            send_sms_code(
                user=user,
                tlf_number=sending_path['receiver'],
                ip_address=ip_address,
                templates=sending_path['templates'],
                code=code
            )
        elif method == 'email':
            send_email_code(
                user=user,
                email_address=sending_path['receiver'],
                ip_address=ip_address,
                templates=sending_path['templates'],
                code=code
            )

def send_msg(data, msg, subject=''):
    if 'tlf' in data:
        from authmethods.models import Message
        auth_method = 'sms'
        receiver = data['tlf']
        send_sms_message(receiver, msg)
        m = Message(tlf=receiver, auth_event_id=0)
        m.save()
    elif 'email' in data:
        from api.models import ACL
        auth_method = 'email'
        receiver = data['email']
        email = EmailMessage(
            subject,
            msg,
            settings.DEFAULT_FROM_EMAIL,
            [receiver],
        )
        send_email(email)


def get_client_ip(request):
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip


@shared_task(name='api.io.send_codes')
def send_codes(
    users,
    ip,
    auth_method=None,
    config=None,
    sender_uid=None,
    eid=None
):
    from api.models import Action, AuthEvent

    # delay between send code calls
    delay = 0
    extend_info = plugins.call("extend_send_codes")
    if extend_info:
        for info in extend_info:
             delay = info


    sender = User.objects.get(pk=sender_uid) if sender_uid else None
    auth_event = AuthEvent.objects.get(pk=eid) if eid else None

    ''' Massive send_code with celery task.  '''
    user_objs = User.objects.filter(id__in=users)
    for user in user_objs:
        action = Action(
            executer=sender,
            receiver=user,
            action_name='user:send-auth',
            event=auth_event,
            metadata=dict()
        )
        action.save()
        send_code(user, ip, config, auth_method_override=auth_method)
        if delay > 0:
            sleep(delay)


# CHECKERS AUTHEVENT
VALID_FIELDS = (
  'name',
  'help',
  'type',
  'required',
  'autofill',
  'regex',
  'min',
  'max',
  'required_on_authentication',
  'unique',
  'private',
  'required_when_registered',
  'user_editable',
  'register-pipeline',
  'authenticate-pipeline',

  # match_census_on_registration can be True or False. It is used for
  # pre-registration. If true, when the user registers, this field is used for
  # whitelisting: the user will only succeed registering if there is already a
  # pre-registered user in the census that matches all the 
  # 'match_census_on_registration':True fields.
  'match_census_on_registration',

  # fill_if_empty_on_registration can be True or False. It is used for
  # pre-registration. If the pre-registered user on the census has this field
  # empty, then when the user will be able to set its value upon registration.
  'fill_if_empty_on_registration',

  # userid_field can be True or False. It is used to generate the username, used
  # to generate the hmac authentication token. If any field on the authevent
  # is marked with userid_field as True, the username won't be generated
  # randomly as it done usually, but instead it will be generated by:
  #
  # 1. Concatenating all the data from the userid_fields (in order of
  # appeareance of the fields in ae.extra_fields)
  # 2. Adding the shared_secret (field1:field2:field3...:shared_secret)
  # separated with the colon character: ':'
  # 3. The username will be the sha256 hash of the above
  #
  # Note that if a field is marked as userid_field, it should always have a
  # valid convertable-to-string value.
  'userid_field',

  # adds a list of css classes to the input field in the login/register screen
  'css_classes',

  # used by otp-code
  'templates',

  # user by otp-code
  'source_field'
)
REQUIRED_FIELDS = ('name', 'type', 'required_on_authentication')
VALID_PIPELINES = (
    'check_whitelisted',
    'check_blacklisted',
    'check_total_max',
    'check_total_connection',
    )
VALID_TYPE_FIELDS = (
    'text',
    'password',
    'int', 
    'bool',
    'regex',
    'email',
    'tlf',
    'captcha',
    'textarea',
    'dni',
    'dict',
    'image',
    'date',
    'otp-code'
)
REQUIRED_ADMIN_FIELDS = ('name', 'type')
VALID_ADMIN_FIELDS = VALID_FIELDS + (
    'description',
    'label',
    'step',
    'value',
    'placeholder'
)

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
        if not p in ('register-pipeline', 'authenticate-pipeline', 'resend-auth-pipeline'):
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
    elif key in ('required', 'required_on_authentication', 'unique', 'userid_field'):
        if not isinstance(value, bool):
            msg += "Invalid extra_fields: bad %s.\n" % key
    elif key == 'regex':
        if not isinstance(value, str):
            msg += "Invalid regex. bad %s.\n" % key
        try:
            re.compile(value)
        except:
            msg += "Invalid regex. bad %s.\n" % key
    elif key in ('register-pipeline', 'authenticate-pipeline'):
        try:
            ret = check_pipeline_conf(value, key)
            if ret != PipeReturnvalue.CONTINUE:
                msg += "stopped-field-" + key
        except CheckException as e:
            msg += JSONContractEncoder().encode(e.data)
        except Exception as e:
            msg += "unknown-exception: " + str(e)
    elif key == 'private' and not isinstance(value, bool):
        msg += "Invalid private: bad %s.\n" % key
    elif key == 'min' or key == 'max':
        if not isinstance(value, int):
            msg += "Invalid extra_fields: bad %s.\n" % key
        else:
            if value >= maxsize or value <= -maxsize :
                msg += "Invalid extra_fields: bad %s.\n" % key
    elif key == 'css_classes':
        if not isinstance(value, str):
            msg += "Invalid extra_fields: bad %s.\n" % key
        elif not re.match("[ 0-9a-zA-Z_-]+", value):
            msg += "Invalid extra_fields: bad %s.\n" % key
    return msg

def check_extra_fields(fields, mandatory_fields=dict(types=[], names=[])):
    """ Check extra_fields when create auth-event. """
    msg = ''
    if len(fields) > settings.MAX_EXTRA_FIELDS:
        return "Maximum number of fields reached\n"
    used_fields = ['status']
    found_used_type_fields = []
    found_used_name_fields = []
    mandatory_type_fields = mandatory_fields['types'][:]
    mandatory_name_fields = mandatory_fields['names'][:]
    for field in fields:
        fname = field.get('name')
        ftype = field.get('type')
        if fname in used_fields:
            msg += "Two fields with same name: %s.\n" % fname
        used_fields.append(fname)
        if ftype in mandatory_type_fields:
            found_used_type_fields.append(ftype)
        if fname in mandatory_name_fields:
            found_used_name_fields.append(fname)
        for required in REQUIRED_FIELDS:
            if not required in field.keys():
                msg += "Required field %s.\n" % required
        for key in field.keys():
            if key in VALID_FIELDS:
                msg += check_fields(key, field.get(key))
            else:
                msg += "Invalid extra_field: %s not possible.\n" % key
    if set(found_used_type_fields) != set(mandatory_type_fields):
        msg += "Not all mandatory type fields were found"
    if set(found_used_name_fields) != set(mandatory_name_fields):
        msg += "Not all mandatory type fields were found"
    return msg

def check_admin_field(key, value):
    """ Check fields in admin_field when create auth-event. """
    msg = ''
    return msg

def check_admin_fields(fields, mandatory_fields=[]):
    """ Check extra_fields when create auth-event. """
    msg = ''
    if fields is None:
       return msg
    if len(fields) > settings.MAX_ADMIN_FIELDS:
        return "Maximum number of fields reached\n"
    # create a copy of the list to not modify it
    used_fields = mandatory_fields['names'][:]
    for field in fields:
        fname = field.get('name')
        if fname in used_fields:
            msg += "Two admin fields with same name: %s.\n" % fname
        used_fields.append(fname)
        for required in REQUIRED_ADMIN_FIELDS:
            if not required in field.keys():
                msg += "Required field %s.\n" % required
        for key in field.keys():
            if key in VALID_ADMIN_FIELDS:
                msg += check_admin_field(key, field.get(key))
            else:
                msg += "Invalid admin_field: %s not possible.\n" % key
    return msg

def datetime_from_iso8601(when=None, tz=None):
    '''
    Parses a ISO-8601 string, returning a timezoned datetime
    '''
    _when = dateutil.parser.parse(when)
    if not _when.tzinfo:
        if tz is None:
            tz = timezone.get_current_timezone()
        _when = tz.localize(_when)
    return _when

def filter_query(filters, query, constraints, prefix, contraints_policy="ignore_invalid"):
    '''
    USeful for easy query filtering and sorting of a given query within the
    specified constraints.

    - 'query' should be a QuerySet
    - 'filters' should be a dictionary with the filters/sorting, usually
      user-provided.
    - 'constraints' specifies what filters are valid
    - 'prefix' is a way to filter keys in 'filters'
    - 'contraints_policy' can be either 'ignore_invalid' (invalid values will
      be discarded and not used) or 'strict' (an exception will be raised).

    If you want the result to be like this:

        query.filter(foo__bar__lt=56).order_by(['-creation_date'])

    'filters' should be:

        dict(q__foo__bar__lt=56, q__creation_date__sort='desc')

    if prefix is "q__", and constraints could be:

        dict(filters=dict(foo__bar=dict(lt=int)), order_by=['creation_date'])

    Limitations:
    - only one sort key is allowed
    - you cannot sort if your model contains a key called 'sort'
    '''
    def is_sort_key(key):
        '''
        checks if a key is sort key by looking at the prefix
        '''
        return key.endswith('__sort')

    def get_filter(key, value):
        '''
        returns the filter parsed
        '''
        noprefix = key[len(prefix):]
        return dict(
          full=noprefix,
          split=RE_SPLIT_FILTER.split(noprefix, 1),
          value=value
        )

    def get_sort(key, value):
        '''
        returns the sort parsed
        '''
        noprefix = key[len(prefix):]
        return dict(
          full=noprefix,
          key=noprefix[:-len('__sort')],
          value=value
        )

    def apply_contraint_policy(error):
        '''
        Either raises an exception or returns False, so that it can be used for
        filtering.
        '''
        if contraints_policy == 'strict':
            raise Exception(error)

        return False

    def check_filter(filter_val):
        '''
        Checks that a filter is valid, and if not, apply contraints_policy.

        Either raises an exception or returns False, so that it can be used for
        filtering.
        '''
        # check filter key is allowed
        if filter_val['split'][0] not in constraints['filters']:
            return apply_contraint_policy('invalid_filter')

        # check filter option is allowed. removing __ chars at the begining
        filter_key = constraints['filters'][filter_val['split'][0]]
        val_key = filter_val['split'][1][2:]
        if val_key not in filter_key:
            return apply_contraint_policy('invalid_filter')

        # check type
        if filter_key[val_key] == int:
            if not RE_INT.match(filter_val['value']):
                return apply_contraint_policy('invalid_filter')
            # parse value
            filter_val['value'] = int(filter_val['value'], 10)

        elif filter_key[val_key] == bool:
            if not RE_BOOL.match(filter_val['value']):
                return apply_contraint_policy('invalid_filter')
            # parse value
            filter_val['value'] = (filter_val['value'] == 'true')

        elif filter_key[val_key] == datetime.datetime:
            try:
                filter_val['value'] = datetime_from_iso8601(filter_val['value'])
            except ValueError as e:
                return apply_contraint_policy('invalid_filter')

        elif filter_key[val_key] == "StringList":
            try:
                assert(isinstance(filter_val['value'], str))
            except ValueError as e:
                return apply_contraint_policy('invalid_filter')

        return True

    def check_sort(sort_val):
        '''
        Checks that a sort is valid, and if not, apply contraints_policy.

        Either raises an exception or returns False, so that it can be used for
        filtering.
        '''
        if (sort_val['key'] not in constraints['order_by'] or
                not isinstance(sort_val['value'], str) or
                sort_val['value'] not in ['asc', 'desc']):
            return apply_contraint_policy('invalid_sort')
        return True

    def filter_tuple(filter_val):
        '''
        given a filter value, gets the pair of (key, value) needed to create
        the dict that will be used for filtering the query
        '''
        if filter_val['full'].endswith('__in'):
            filter_val['value'] = filter_val['value'].split("|")
        elif filter_val['full'].endswith('__equals'):
            filter_val['full'] = filter_val['full'][:-len('__equals')]

        return (filter_val['full'],filter_val['value'])

    filters_l = [
      get_filter(key, val) for key, val in filters.items()
      if key.startswith(prefix) and not is_sort_key(key)]

    # NOTE sort is limited to one element at most
    sort_l = [
        get_sort(key, val) for key, val in filters.items()
        if key.startswith(prefix) and is_sort_key(key)]
    if len(sort_l) > 1:
        apply_contraint_policy('invalid_sort')
    sort_l = sort_l[:1]

    # apply contraints_policy
    valid_filters = dict([
      filter_tuple(filter_val) for filter_val in filters_l
      if check_filter(filter_val)])
    valid_sort = [sort_val for sort_val in sort_l if check_sort(sort_val)]

    # filter
    ret_query = query
    if len(valid_filters) > 0:
        ret_query = ret_query.filter(**valid_filters)

    # sort
    if len(valid_sort) > 0:
        sort_el = valid_sort[0]
        if sort_el['value'] == 'asc':
            sort_str = sort_el['key']
        else:
            sort_str = '-' + sort_el['key']
        ret_query = ret_query.order_by(sort_str)
    elif 'default_ordery_by' in constraints:
        ret_query = ret_query.order_by(constraints['default_ordery_by'])

    return ret_query

def is_valid_url(url, *args, **kwargs):
    '''
    Validates an url, returning a boolean
    '''
    validator = URLValidator(*args, **kwargs)
    try:
        validator(url)
    except ValidationError as ve:
        return False

    return True
