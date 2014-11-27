#!/usr/bin/env python3


import hmac
import datetime
import time


def genhmac(key, msg):
    timestamp = int(datetime.datetime.now().timestamp())
    msg = "%s:%s" % (msg, str(timestamp))

    h = hmac.new(key, msg.encode('utf-8'), "sha256")
    return 'khmac:///sha256;' + h.hexdigest() + '/' + msg


def verifyhmac(key, msg, seconds=300):
    msg = msg[len('khmac:///'):]
    digest, msg = msg.split(';')
    orig_hmac, msg = msg.split('/')
    h = hmac.new(key, msg.encode('utf-8'), digest)
    valid = hmac.compare_digest(h.hexdigest(), orig_hmac)

    t = msg.split(':')[-1]
    n = datetime.datetime.now()
    d = datetime.datetime.fromtimestamp(int(t))
    d = d + datetime.timedelta(seconds=seconds)

    valid = valid and d > n
    return valid
