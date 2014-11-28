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
    at = HMACToken(msg)
    h = hmac.new(key, at.msg.encode('utf-8'), at.digest)
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
