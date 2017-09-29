# -*- coding: utf-8 -*-
#
# This file is part of authapi.
# Copyright (C) 2014-2016  Agora Voting SL <agora@agoravoting.com>

# authapi is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License.

# authapi  is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.

# You should have received a copy of the GNU Affero General Public License
# along with authapi.  If not, see <http://www.gnu.org/licenses/>.

import re
import sys
import requests
import logging
import xmltodict
from django.conf import settings
from utils import stack_trace_str
from twilio.rest import Client

LOGGER = logging.getLogger('authapi')

class SMSProvider(object):
    '''
    Abstract class for a generic SMS provider
    '''
    provider_name = ""

    default_prefix = "+34"

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

    def get_canonical_format(self, tlf):
        """
        converts a tlf number to a cannonical format. This means in practice
        that "624571624", "+34624571624" and "0034624571624" will all be
        converted into "+34624571624". This is useful because otherwise, anyone
        could vote three times with the same tlf number. The default country
        prefix is configurable and this function can be overridden by each
        provider.
        """
        if not isinstance(tlf, str):
            return tlf

        # remove whitespace
        tlf = re.sub(r"\s", "", tlf)

        if tlf.startswith("00"):
          return "+" + tlf[2:]
        elif tlf.startswith("+"):
          return tlf
        else: # add default prefix
          return self.default_prefix + tlf

    @staticmethod
    def get_instance():
        '''
        Instance the SMS provider specified in the app config
        '''
        provider = settings.SMS_PROVIDER
        if provider == "twilio":
            return TwilioSMSProvider()
        if provider == "altiria":
            return AltiriaSMSProvider()
        if provider == "esendex":
            return EsendexSMSProvider()
        if provider == "console":
            return ConsoleSMSProvider()
        if provider == "test":
            return TestSMSProvider()
        else:
            raise Exception("invalid SMS_PROVIDER='%s' in app config" % provider)


class TestSMSProvider(SMSProvider):
    provider_name = "test"
    last_sms = ""
    sms_count = 0

    def __init__(self):
        pass

    def send_sms(self, receiver, content, is_audio):
        TestSMSProvider.sms_count += 1
        TestSMSProvider.last_sms = dict(
            content=content, 
            receiver=receiver, 
            is_audio=is_audio
        )
        LOGGER.info(\
            "TestSMSProvider.send_sms\n"\
            "sending message '%r'\n"\
            "to '%r'\n"\
            "is_audio '%r'\n"\
            "Stack trace: \n%s",\
            content, receiver, is_audio, stack_trace_str())
            
class ConsoleSMSProvider(SMSProvider):
    provider_name = "console"

    def __init__(self):
        pass

    def send_sms(self, receiver, content, is_audio):
        LOGGER.info(\
            "ConsoleSMSProvider.send_sms\n"\
            "sending message '%r'\n"\
            "to '%r'\n"\
            "is_audio '%r'\n"\
            "Stack trace: \n%s",\
            content, receiver, is_audio, stack_trace_str())


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

    def __init__(self):
        self.domain_id = settings.SMS_DOMAIN_ID
        self.login = settings.SMS_LOGIN
        self.password = settings.SMS_PASSWORD
        self.url = settings.SMS_URL
        self.sender_id = settings.SMS_SENDER_ID

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

        r = requests.post(self.url, data=data, headers=self.headers)

        ret = self.parse_response(r)
        LOGGER.info(\
            "AltiriaSMSProvider.send_sms\n"\
            "sending message '%r'\n"\
            "to '%r'\n"\
            "is_audio '%r'\n"\
            "data '%r'\n"\
            "r '%r'\n"\
            "ret '%r'\n"\
            "Stack trace: \n%s",\
            content, receiver, is_audio, data, r, ret, stack_trace_str())
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
        LOGGER.info(\
            "AltiriaSMSProvider.get_credit\n"\
            "data '%r'\n"\
            "r '%r'\n"\
            "ret '%r'\n"\
            "Stack trace: \n%s",\
            data, r, ret, stack_trace_str())
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

        LOGGER.debug(\
            "AltiriaSMSProvider.parse_response\n"\
            "data '%r'\n"\
            "nonEmpty '%r'\n"\
            "lines '%r'\n"\
            "result '%r'\n"\
            "Stack trace: \n%s",\
            data, nonEmpty, lines, result, stack_trace_str())
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

    # header used in esendex requests
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

    def __init__(self):
        self.domain_id = settings.SMS_DOMAIN_ID
        self.login = settings.SMS_LOGIN
        self.password = settings.SMS_PASSWORD
        self.url = settings.SMS_URL
        self.sender_id = settings.SMS_SENDER_ID
        self.lang_code = settings.SMS_VOICE_LANG_CODE

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
        r = requests.post(self.url, data=data, headers=self.headers, auth=self.auth)

        ret = self.parse_response(r)
        if 'error' in ret:
            LOGGER.error(\
                "EsendexSMSProvider.send_sms error\n"\
                "'error' in ret\n"\
                "message '%r'\n"\
                "to '%r'\n"\
                "is_audio '%r'\n"\
                "data '%r'\n"\
                "r '%r'\n"\
                "ret '%r'\n"\
                "Stack trace: \n%s",\
                content, receiver, is_audio, data, r, ret, stack_trace_str())
            raise Exception(
                'error sending:\n\tdata=%s\t\nret=\t%s' % (str(data), str(ret))
            )
        LOGGER.info(\
            "EsendexSMSProvider.send_sms\n"\
            "sending message '%r'\n"\
            "to '%r'\n"\
            "is_audio '%r'\n"\
            "data '%r'\n"\
            "r '%r'\n"\
            "ret '%r'\n"\
            "Stack trace: \n%s",\
            content, receiver, is_audio, data, r, ret, stack_trace_str())
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

        LOGGER.debug(\
            "EsendexSMSProvider.parse_response\n"\
            "response '%r'\n"\
            "ret '%r'\n"\
            "Stack trace: \n%s",\
            response, ret, stack_trace_str())
        return ret

class TwilioSMSProvider(SMSProvider):
    '''
    Esendex SMS Provider
    '''

    provider_name = "twilio"
    HTTP_OK = 200

    # credentials, read from app config
    # this corresponds to the  <accountreference>
    domain_id = None
    login = None
    password = None
    url = None
    # sets the <from> field
    sender_id = None
    client = None

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

    def __init__(self):
        self.domain_id = settings.SMS_DOMAIN_ID
        self.login = settings.SMS_LOGIN
        self.password = settings.SMS_PASSWORD
        self.url = settings.SMS_URL
        self.sender_id = settings.SMS_SENDER_ID
        self.sender_number = settings.SMS_SENDER_NUMBER
        self.lang_code = settings.SMS_VOICE_LANG_CODE
        self.no_alphanumeric_countrycodes = [
          '93',   # Afghanistan
          '213',  # Algeria
          '54',   # Argentina
          '994',  # Azerbaijan
          '880',  # Bangladesh
          '32',   # Belgium
          '55',   # Brazil
          '1',    # Canada
          '1345', # Cayman Islands
          '56',   # Chile
          '86',   # China
          '57',   # Colombia
          '242',  # Congo
          '243',  # Congo D.R.
          '506',  # Costa Rica
          '385',  # Croatia
          '53',   # Cuba
          '420',  # Czech Republic
          '246',  # Diego García
          '1809', # Dominican Republic
          '1829', # Dominican Republic
          '1849', # Dominican Republic
          '593',  # Ecuador
          '503',  # El Salvador
          '594',  # French Guiana
          '233',  # Ghana
          '1671', # Guam
          '502',  # Guatemala
          '36',   # Hungary
          '91',   # India
          '62',   # Indonesia
          '98',   # Iran
          '964',  # Iraq
          '962',  # Jordan
          '76',   # Kazakhstan
          '77',   # Kazakhstan
          '254',  # Kenya
          '965',  # Kuwait
          '996',  # Kyrgyzstan
          '856',  # Laos PDR
          '60',   # Malaysia
          '223',  # Mali
          '52',   # Mexico
          '337',  # Monaco
          '212',  # Morocco
          '258',  # Mozambique
          '95',   # Myanmar
          '264',  # Namibia
          '674',  # Nauru
          '977',  # Nepal
          '64',   # New Zealand
          '505',  # Nicaragua
          '968',  # Oman
          '92',   # Pakistan
          '507',  # Panama
          '970',  # Palestinian Territory
          '51',   # Peru
          '63',   # Philippines
          '1787', # Puerto Rico
          '1939', # Puerto Rico
          '974',  # Qatar
          '40',   # Romania
          '7',    # Russia
          '966',  # Saudi Arabia
          '27',   # South Africa
          '94',   # Sri Lanka
          '963',  # Syria
          '886',  # Taiwan
          '216',  # Tunisia
          '90',   # Turkey
          '971',  # United Arab Emirates
          '1',    # United States
          '598',  # Uruguay
          '58',   # Venezuela
          '84'    # Vietnam
        ]
        # if there is a match bewteen the receiver and this regex, we can't use
        # alphanumeric sender ids
        self.regex_blacklist = "^(\+|00)(" + "|".join(self.no_alphanumeric_countrycodes) + ")[0-9]+$"
        # regex used to check whether sender id is alphanumeric
        self.regex_senderid = "^(\+|00)[0-9]+$"

        self.auth = (self.login, self.password)
        self.client = Client(self.login, self.password)

    def send_sms(self, receiver, content, is_audio):
        try:
            msg_type = 'SMS'
            extra = ""
            if (None == re.match(self.regex_blacklist, receiver) or\
                None != re.match(self.regex_senderid, self.sender_id)):
                from_ = self.sender_id
            else:
                from_ = self.sender_number

            data = self.msg_template % dict(
                accountreference=self.domain_id,
                msg_type=msg_type,
                to=receiver,
                body=content,
                sender=from_,
                extra=extra)
            p = self.client.messages.create(\
                    to=receiver,\
                    from_=from_,\
                    body=content)
        except:
            q = sys.exc_info()[0]
            if hasattr(q, "msg"):
                print("Unexpected error:", q.msg)
            LOGGER.error(\
                "TwilioSMSProvider.send_sms error\n"\
                "message '%r'\n"\
                "to '%r'\n"\
                "from '%r'\n"\
                "is_audio '%r'\n"\
                "data '%r'\n"\
                "error '%r'\n"\
                "Stack trace: \n%s",\
                content, receiver, from_, is_audio, data, q.__dict__, stack_trace_str())
            raise Exception(\
                'error sending:\n\tdata=%s\t\nerror=\t%s' % (str(data), str(q.__dict__)))

        LOGGER.info(\
            "TwilioSMSProvider.send_sms\n"\
            "sending message '%r'\n"\
            "to '%r'\n"\
            "from '%r'\n"\
            "is_audio '%r'\n"\
            "data '%r'\n"\
            "value '%r'\n"\
            "Stack trace: \n%s",\
            content, receiver, from_, is_audio, data, p.__dict__, stack_trace_str())
