#!/usr/bin/env python3
import hmac
import datetime
import time
import six
from djcelery import celery
from django.core.mail import send_mail
from django.core.paginator import Paginator


def paginate(request, queryset, serialize_method=None, elements_name='elements'):
    '''
    Function to paginate a queryset using the request params
    ?page=1&n=10
    '''

    index = request.GET.get('page', 1)
    elements = request.GET.get('n', 10)

    try:
        page = int(page)
    except:
        page = 1

    try:
        elements = int(elements)
    except:
        elements = 10

    if elements > 30:
        elements = 30

    p = Paginator(queryset, elements)
    page = p.page(index)

    d = {
        elements_name: page.object_list,
        'page': index,
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


@celery.task
def send_email(subject, msg, mail_from, mails_to):
    send_mail(subject, msg, mail_from, mails_to)


@celery.task
def send_sms_code(data, conf):
    from authmethods.sms_provider import SMSProvider
    con = SMSProvider.get_instance(conf)
    con.send_sms(receiver=data['tlf'], content=conf['sms-message'], is_audio="sss")
