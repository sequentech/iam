# -*- coding: utf-8 -*-
#
# This file is part of agora-election.
# Copyright (C) 2013  Eduardo Robles Elvira <edulix AT agoravoting DOT com>

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import requests
import logging
import xmltodict

class SMSProvider(object):
    '''
    Abstract class for a generic SMS provider
    '''
    provider_name = ""

    def __init__(self):
        pass

    def send_sms(self, dest, msg, is_audio=False):
        '''
        Sends sms to one or multiple destinations (if the dest is an array,
        untested)
        '''
        pass

    def get_credit(self):
        '''
        obtains the remaining credit. Note, each provider has it's own format
        for returning the "credit" concept.
        '''
        return 0

    @staticmethod
    def get_instance(config):
        '''
        Instance the SMS provider specified in the app config
        '''
        provider = config.get('SMS_PROVIDER', '')
        if provider == "altiria":
            return AltiriaSMSProvider(config)
        if provider == "esendex":
            return EsendexSMSProvider(config)
        if provider == "console":
            return ConsoleSMSProvider(config)
        else:
            raise Exception("invalid SMS_PROVIDER='%s' in app config" % provider)


class ConsoleSMSProvider(SMSProvider):
    provider_name = "console"

    def __init__(self, config):
        pass

    def send_sms(self, receiver, content, is_audio):
        logging.info("sending message '%(msg)s' to '%(dest)s' "
            "(is_audio=%(is_audio)s)" % dict(
                msg=content, dest=receiver, is_audio=str(is_audio)))


class AltiriaSMSProvider(SMSProvider):
    '''
    Altiria SMS Provider
    '''

    provider_name = "altiria"

    # credentials, read from app config
    domain_id = None
    login = None
    password = None
    url = None
    sender_id = None

    # header used in altiria requests
    headers = {
        'Content-type': 'application/x-www-form-urlencoded; charset=UTF-8',
        'Accept': 'text/plain'
    }

    def __init__(self, config):
        self.domain_id = config.get('SMS_DOMAIN_ID', '')
        self.login = config.get('SMS_LOGIN', '')
        self.password = config.get('SMS_PASSWORD', '')
        self.url = config.get('SMS_URL', '')
        self.sender_id = config.get('SMS_SENDER_ID', '')

    def send_sms(self, receiver, content, is_audio):

        data = {
            'cmd': 'sendsms',
            'domainId': self.domain_id,
            'login': self.login,
            'passwd': self.password,
            'dest': receiver,
            'msg': content,
            'senderId': self.sender_id
        }

        logging.debug("sending message.." + str(data))
        r = requests.post(self.url, data=data, headers=self.headers)

        ret = self.parse_response(r)
        logging.debug(ret)
        return ret

    def get_credit(self):
        data = {
            'cmd': 'getcredit',
            'domainId': self.domainId,
            'login': self.login,
            'passwd': self.password,

        }
        r = requests.post(self.url, data=data, headers=self.headers)

        ret = self.parse_response(r)
        logging.debug(ret)
        return ret

    def parse_response(self, response):
        '''
        parses responses in altiria format into dictionaries, one for each line
        '''
        if isinstance(response, str):
            data = response
        else:
            data = response.text
        # Convert 'OK dest:34634571634  \n' to  ['OK dest:34634571634']
        # split by stripped lines, stripping the lines removing empty ones
        nonEmpty = filter(lambda x: len(x.strip()) > 0, data.split("\n"))

        def partition(item):
            '''
            Partition "aa  : b" into ("aa", "b")
            '''
            a, b, c = item.partition(":")
            return (a.strip(), c.strip())

        def parse(l):
            '''
            Parse a line
            '''
            # ["aa:bb cc"] --> [("aa", "bb"), ("cc", "")]
            return map(partition, l.split(" "))

        lines = [dict(list(parse(line)) +  [('error', line.startswith('ERROR'))])
                for line in nonEmpty]

        result = {'response': response}
        result['lines'] = lines

        return result


class EsendexSMSProvider(SMSProvider):
    '''
    Esendex SMS Provider
    '''

    provider_name = "esendex"
    HTTP_OK = 200

    # credentials, read from app config
    # this corresponds to the  <accountreference>
    domain_id = None
    login = None
    password = None
    url = None
    # sets the <from> field
    sender_id = None

    # header used in altiria requests
    headers = {
        'Content-type': 'application/xml; charset=UTF-8',
        'Accept': 'text/xml'
    }

    # template xml
    msg_template = """<?xml version='1.0' encoding='UTF-8'?>
        <messages>
        <accountreference>%(accountreference)s</accountreference>
        <message>
        <type>%(msg_type)s</type>
        %(extra)s
        <to>%(to)s</to>
        <body>%(body)s</body>
        <from>%(sender)s</from>
        </message>
        </messages>"""

    def __init__(self, config):
        self.domain_id = config.get('SMS_DOMAIN_ID', '')
        self.login = config.get('SMS_LOGIN', '')
        self.password = config.get('SMS_PASSWORD', '')
        self.url = config.get('SMS_URL', '')
        self.sender_id = config.get('SMS_SENDER_ID', '')
        self.lang_code = config.get('SMS_VOICE_LANG_CODE', '')

        self.auth = (self.login, self.password)

    def send_sms(self, receiver, content, is_audio):
        if is_audio:
            msg_type = 'Voice'
            extra = "<lang>%s</lang>\n" % self.lang_code
        else:
            msg_type = 'SMS'
            extra = ""

        data = self.msg_template % dict(
            accountreference=self.domain_id,
            msg_type=msg_type,
            to=receiver,
            body=content,
            sender=self.sender_id,
            extra=extra)
        logging.debug("sending message.." + str(data))
        r = requests.post(self.url, data=data, headers=self.headers, auth=self.auth)

        ret = self.parse_response(r)
        logging.debug(ret)
        return ret

    def parse_response(self, response):
        '''
        parses responses in esendex format
        '''
        if response.status_code == self.HTTP_OK:
            ret = xmltodict.parse(response.text)
        else:
            ret = {
                'code': response.status_code,
                'error': response.text
            }

        return ret
