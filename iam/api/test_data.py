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

import copy
from django.conf import settings


pwd_auth = {'username': 'john', 'password': 'smith'}

pwd_auth_email = {'email': 'john2@sequentech.io', 'password': 'smith'}

auth_event1 = {
    "auth_method": "sms",
    "census": "close",
    "config": {"msg": "Enter in __URL__ and put this code __CODE__"},
    "extra_fields": [
        {
            "name": "name",
            "help": "put the name that appear in your dni",
            "type": "text",
            "required": True,
            "min": 2,
            "max": 64,
            "required_on_authentication": True
        },
        {
            "name": "email",
            "type": "email",
            "required": True,
            "min": 4,
            "max": 255,
            "required_on_authentication": True
        },
        {
            "name": "dni",
            "help": "put the dni without dash",
            "type": "dni",
            "required": True,
            "min": 5,
            "max": 12,
            "required_on_authentication": True
        },
        {
            "name": "tlf",
            "type": "tlf", 
            "required": True,
            "min": 4,
            "max": 20,
            "required_on_authentication": True
        }
    ]
}

auth_event2 = {
    "auth_method": "sms",
    "census": "open",
    "config": {"msg": "Enter in __URL__ and put this code __CODE__"},
    "extra_fields": [
        {
            "name": "name",
            "help": "put the name that appear in your dni",
            "type": "text",
            "required": False,
            "min": 2,
            "max": 64,
            "required_on_authentication": False
        },
        {
            "name": "age",
            "help": "put the age",
            "type": "int",
            "required": False,
            "min": 18,
            "max": 150,
            "required_on_authentication": False
        },
        {
            "name": "email",
            "type": "email",
            "required": True,
            "min": 4,
            "max": 255,
            "required_on_authentication": True
        },
        {
            "name": "dni",
            "help": "put the dni without dash",
            "type": "dni",
            "required": True,
            "min": 5,
            "max": 12,
            "required_on_authentication": True
        },
        {
            "name": "tlf",
            "type": "tlf", 
            "required": True,
            "min": 4,
            "max": 20,
            "required_on_authentication": True
        }
    ]
}

auth_event3 = {
    "auth_method": "email",
    "census": "open",
    "config": {
        "authentication-action": {"mode": ""},
        "subject": "Confirm your email",
        "msg": "Click __URL__ and put this code __CODE__"
    },
    "extra_fields": [
        {
            "name": "email",
            "type": "email",
            "required": True,
            "unique": True,
            "min": 4,
            "max": 255,
            "required_on_authentication": True
        }
    ]
}

auth_event4 = {
    "auth_method": "user-and-password",
    "census": "open",
    "config": {
        "authentication-action": {"mode": ""}
    },
    "extra_fields": [
        {
            "name": "username",
            "type": "text",
            "required": True,
            "unique": True,
            "min": 3, 
            "max": 200, 
            "required_on_authentication": True
        },
        {
            "name": "password",
            "type": "password",
            "required": True,
            "min": 3,
            "max": 200,
            "required_on_authentication": True
        }
    ]
}

auth_event5 = {
    "auth_method": "user-and-password",
    "census": "open",
    "config": {},
    "extra_fields": [
        {
            "name": "username",
            "type": "text",
            "required": True,
            "min": 3, 
            "max": 200, 
            "required_on_authentication": True
        },
        {
            "name": "password",
            "type": "password",
            "required": True,
            "min": 3,
            "max": 200,
            "required_on_authentication": True
        },
        {
            "name": "name",
            "type": "text",
            "required": True,
            "min": 2,
            "max": 64,
            "required_on_authentication": True
        },
    ]
}

# extra-fields pipeline
auth_event6 = {
    "auth_method": "email",
    "census": "open",
    "config": {
        "authentication-action": {"mode": ""},
        "subject": "Confirm your email",
        "msg": "Click __URL__ and put this code __CODE__"
    },
    "extra_fields": [
        {
            "name": "email",
            "type": "email",
            "required": True,
            "min": 4,
            "max": 255,
            "required_on_authentication": True
        },
        {
            "name": "dni",
            "help": "put the dni without dash",
            "type": "dni",
            "required": True,
            "min": 5,
            "max": 12,
            "required_on_authentication": True,
            "register-pipeline": [
                ["CanonizeDni", {}],
                ["DniChecker", {}]
            ],
            "authenticate-pipeline": [
                ["CanonizeDni", {}]
            ]
        }
    ]
}
auth_event7 = copy.deepcopy(auth_event6)
auth_event7['extra_fields'][0]['register-pipeline'] = [
                ["ExternalAPICheckAndSave", {
                    "mode": "lugo",
                    "mode-config": {
                        "baseurl": "http://foo/conecta/services",
                        "user": "foo",
                        "password": "bar"
                    }
                }]
            ]


# extra-fields pipeline for email
# email and match_field must match with a pre-registered user
# the user must fill 'fill_field' upon registration
auth_event8 = {
    "auth_method": "email",
    "census": "open",
    "config": {
        "authentication-action": {"mode": ""},
        "subject": "Confirm your email",
        "msg": "Click __URL__ and put this code __CODE__"
    },
    "extra_fields": [
            {
                "name": "match_field",
                "match_census_on_registration": True,
                "help": "match census on registration",
                "type": "text",
                "required": True,
                "min": 0,
                "max": 24,
                "required_on_authentication": False
            },
            {
                "name": "fill_field",
                "fill_if_empty_on_registration": True,
                "help": "fill if empty on registration",
                "type": "text",
                "min": 0,
                "max": 24,
                "required_on_authentication": False
            },
            {
                "name": "email",
                "type": "email",
                "required": True,
                "unique": True,
                "min": 4,
                "max": 255,
                "required_on_authentication": True,
                "match_census_on_registration": True
            }
    ]
}


# extra-fields pipeline for email
# match_field must match with a pre-registered user
# the user must fill the email field upon registration
auth_event9 = {
    "auth_method": "email",
    "census": "open",
    "config": {
        "authentication-action": {"mode": ""},
        "subject": "Confirm your email",
        "msg": "Click __URL__ and put this code __CODE__"
    },
    "extra_fields": [
        {
            "name": "email",
            "type": "email",
            "required": True,
            "unique": True,
            "min": 4,
            "max": 255,
            "fill_if_empty_on_registration": True,
            "required_on_authentication": True
        },
        {
            "name": "match_field",
            "match_census_on_registration": True,
            "help": "match census on registration",
            "type": "text",
            "required": True,
            "unique": True,
            "min": 0,
            "max": 24,
            "required_on_authentication": False
        }
    ]
}

# extra-fields pipeline for sms
# sms and match_field must match with a pre-registered user
# the user must fill 'fill_field' upon registration
auth_event10 = {
    "auth_method": "sms",
    "census": "open",
    "config": {"msg": "Enter in __URL__ and put this code __CODE__"},
    "extra_fields": [
            {
                "name": "match_field",
                "match_census_on_registration": True,
                "help": "match census on registration",
                "type": "text",
                "required": True,
                "min": 0,
                "max": 24,
                "required_on_authentication": False
            },
            {
                "name": "fill_field",
                "fill_if_empty_on_registration": True,
                "help": "fill if empty on registration",
                "type": "text",
                "min": 0,
                "max": 24,
                "required_on_authentication": False
            },
            {
                "name": "tlf",
                "type": "tlf", 
                "required": True,
                "min": 4,
                "max": 20,
                "match_census_on_registration": True,
                "required_on_authentication": True
            }
    ]
}


# extra-fields pipeline for sms
# match_field must match with a pre-registered user
# the user must fill the tlf field upon registration
auth_event11 = {
    "auth_method": "sms",
    "census": "open",
    "config": {"msg": "Enter in __URL__ and put this code __CODE__"},
    "extra_fields": [
        {
            "name": "match_field",
            "match_census_on_registration": True,
            "help": "match census on registration",
            "type": "text",
            "required": True,
            "min": 0,
            "max": 24,
            "required_on_authentication": False
        },
        {
            "name": "tlf",
            "type": "tlf", 
            "required": True,
            "min": 4,
            "max": 20,
            "required_on_authentication": True
        }
    ]
}

# extra-fields pipeline for email
# used to test slug names
auth_event12 = {
    "auth_method": "email",
    "census": "open",
    "config": {
        "authentication-action": {"mode": ""},
        "subject": "Confirm your email",
        "msg": "Click __URL__ and put this code __CODE__"
    },
    "extra_fields": [
        {
            "name": "email",
            "type": "email",
            "required": True,
            "unique": True,
            "min": 4,
            "max": 255,
            "required_on_authentication": True
        },
        {
            "name": "nº de _socio 你好",
            "slug": "NO_DE__SOCIO",
            "match_census_on_registration": False,
            "help": "something",
            "type": "text",
            "required": True,
            "min": 0,
            "max": 24,
            "required_on_authentication": False
        }
    ]
}

# extra-fields pipeline for email
# used to test slug names
auth_event13 = {
    "auth_method": "email",
    "census": "open",
    "config": {
        "authentication-action": {"mode": ""},
        "subject": "Confirm your email",
        "msg": "Click __URL__ and put this code __CODE__"
    },
    "extra_fields": [
        {
            "name": "email",
            "type": "email",
            "required": True,
            "min": 4,
            "max": 255,
            "required_on_authentication": True
        },
        {
            "name": "nº de _socio 你好",
            "match_census_on_registration": False,
            "help": "something",
            "type": "text",
            "required": True,
            "min": 0,
            "max": 24,
            "required_on_authentication": False
        }
    ]
}

auth_event14 = {
    "auth_method": "email",
    "census": "open",
    "config": {},
    "extra_fields":[
        {
            "name": "email",
            "type": "email",
            "required": True,
            "min": 4,
            "max": 255,
            "required_on_authentication": True
        },
        {
            "name":"MemberID",
            "type":"text",
            "required": True,
            "min":9,
            "max":9,
            "private": False,
            "required_on_authentication": True,
            "match_census_on_registration": True,
            "fill_if_empty_on_registration": False,
            "register-pipeline":[
            ],
            "help":" True your Member ID",
            "unique": True
        }
   ],
   "admin_fields":[
      {
         "name":"expected_census",
         "label":"Expected Census",
         "description":"Expected census",
         "type":"int",
         "min":0,
         "step":1,
         "value":1000,
         "required": True,
         "private": True
      }
   ]
}

auth_event15 = {
    "auth_method": "email",
    "census": "open",
    "config": {},
    "extra_fields": [
        {
            "name": "email",
            "type": "email",
            "required": True,
            "min": 4,
            "max": 255,
            "required_on_authentication": True
        },
        {
            "name":"MemberID",
            "type":"text",
            "required": True,
            "min":9,
            "max":9,
            "private": False,
            "required_on_authentication": True,
            "match_census_on_registration": True,
            "fill_if_empty_on_registration": False,
            "register-pipeline":[
            ],
            "help":" True your Member ID",
            "unique": True
        }
   ],
   "admin_fields":[
      {
         "name":"expected_census",
         "label":"Expected Census",
         "description":"Expected census",
         "type":"int",
         "min":0,
         "step":1,
         "value":1000,
         "required": True,
         "private": True
      },
      {
         "name":"expected_census",
         "label":"Expected Census2",
         "description":"Expected census2",
         "type":"int",
         "min":0,
         "step":1,
         "value":1000,
         "required": True,
         "private": True
      }
   ]
}

userdata_metadata16 = {
  "dni": "1234567L",
  "company name": "Sequent Tech S.L"
}

extra_fields16 = [
    {
        "name": "email",
        "type": "email",
        "required": True,
        "min": 4,
        "max": 255,
        "required_on_authentication": True
    },
    {
        "name": "dni",
        "type": "text",
        "required": False,
        "min": 1,
        "required_on_authentication": False,
        "user_editable": True
    },
    {
        "name": "company name",
        "type": "text",
        "required": False,
        "min": 1,
        "required_on_authentication": False,
        "required_when_registered": True,
        "user_editable": True
    },
    {
        "name": "other",
        "type": "text",
        "required": False,
        "min": 1,
        "required_on_authentication": False,
        "required_when_registered": False,
        "user_editable": False
    }
]

# extra-fields pipeline
auth_event17 = {
    "auth_method": "email",
    "census": "open",
    "config": {
        "authentication-action": {"mode": ""},
        "subject": "Confirm your email",
        "msg": "Click __URL__ and put this code __CODE__"
    },
    "extra_fields": [
        {
            "name": "email",
            "type": "email",
            "required": True,
            "min": 4,
            "max": 255,
            "required_on_authentication": True
        },
        {
            "name": "dni",
            "help": "put the dni without dash",
            "type": "dni",
            "required": True,
            "min": 5,
            "max": 12,
            "userid_field": True,
            "required_on_authentication": False,
            "register-pipeline": [
                ["CanonizeDni", {}],
                ["DniChecker", {}]
            ],
            "authenticate-pipeline": [
                ["CanonizeDni", {}]
            ]
        }
    ]
}

# Users
admin = {'username': 'john', 'email': 'john@sequentech.io', 'password': 'smith'}

# Census
census_email_default = {
    "field-validation": "enabled",
    "census": [
        {"email": "baaa@aaa.com"},
        {"email": "caaa@aaa.com"},
        {"email": "daaa@aaa.com"},
        {"email": "eaaa@aaa.com"}
    ]
}

census_email_default1 = {
    "field-validation": "enabled",
    "census": [
        {"email": "baaa@aaa.com"},
    ]
}

census_email_default_used = {
    "field-validation": "enabled",
    "census": [
        {"email": "baaa@aaa.com", "status": "used"},
        {"email": "caaa@aaa.com", "status": "used"},
        {"email": "daaa@aaa.com", "status": "used"},
        {"email": "eaaa@aaa.com", "status": "used"}
    ]
}

census_email_fields = {
    "field-validation": "enabled",
    "census": [
        {"name": "aaaa", "email": "baaa@aaa.com"},
        {"name": "baaa", "email": "caaa@aaa.com"},
        {"name": "caaa", "email": "daaa@aaa.com"},
        {"name": "daaa", "email": "eaaa@aaa.com"}
    ]
}

census_email_repeat = {
    "field-validation": "enabled",
    "census": [
        {"email": "repeat@aaa.com"},
        {"email": "repeat@aaa.com"}
    ]
}

census_email_spaces = {
    "field-validation": "enabled",
    "census": [
        {"email": " baaa@aaa.com"},
        {"email": "caaa@aaa.com "},
        {"email": "daaa@ aaa.com"},
        {"email": "eaaa@aaa .com"},
        {"email": "faaa @aaa.com"},
        {"email": "  gaaa@aaa.com  "},
    ]
}

census_email_no_validate = {
    "field-validation": "disabled",
    "census": [
        {"dni": "11111112H", "email": ""}, # without email and bad dni
        {"dni": "22222222J", "email": ""}, # without email and good dni
        {"dni": "", "email": "qwerty@test.com"}, # without dni
        {"dni": "", "email": "qwerty@test.com"}, # email repeat
        {"dni": True, "email": "qwerty2@test.com"}, # dni bad type
        {"dni": "123123123J", "email": "qwerty"}, # email bad
        {"email": "i\u0144test@test.com"}, # email bad encode
        {"dni": "11111111H", "email": "@@"},
        {"dni": "11111111H", "email": "@@"} # dni repeat 
    ]
}


census_sms_default = {
    "field-validation": "enabled",
    "census": [
        {"tlf": "666666667"},
        {"tlf": "666666668"},
        {"tlf": "666666669"},
        {"tlf": "666666670"}
    ]
}

census_sms_default_used = {
    "field-validation": "enabled",
    "census": [
        {"tlf": "666666667", "status": "used"},
        {"tlf": "666666668", "status": "used"},
        {"tlf": "666666669", "status": "used"},
        {"tlf": "666666670", "status": "used"}
    ]
}

census_sms_fields = {
    "field-validation": "enabled",
    "census": [
        {"name": "aaaa", "tlf": "666666665"},
        {"name": "baaa", "tlf": "666666667"},
        {"name": "caaa", "tlf": "666666668"},
        {"name": "daaa", "tlf": "666666669"}
    ]
}

census_sms_repeat = {
    "field-validation": "enabled",
    "census": [
        {"tlf": "777777777"},
        {"tlf": "777777777"}
    ]
}

census_email_unique_dni = {
    "field-validation": "enabled",
    "census": [
        {"dni": "11111111H", "email": "aaa@aaa.com"},
        {"dni": "22222222J", "email": "bbb@bbb.com"}
    ]
}

census_sms_unique_dni = {
    "field-validation": "enabled",
    "census": [
        {"dni": "11111111H", "tlf": "111111111"},
        {"dni": "22222222J", "tlf": "222222222"}
    ]
}

census_sms_no_validate = {
    "field-validation": "disabled",
    "census": [
        {"dni": "11111112H", "tlf": ""}, # without tlf and bad dni
        {"dni": "22222222J", "tlf": ""}, # without tlf and good dni
        {"dni": "", "tlf": "111111111"}, # without dni
        {"dni": "", "tlf": "111111111"}, # tlf repeat
        {"dni": 123, "tlf": "222222222"}, # dni bad type
        {"dni": "11111111H", "tlf": "333333333"},
        {"dni": "11111111H", "tlf": "444444444"} # dni repeat 
    ]
}

census_email_auth9 = {
    "field-validation": "enabled",
    "census": [
        {"email": "baaa@aaa.com", "match_field": "ma1"},
        {"email": "caaa@aaa.com", "match_field": "mb2"},
        {"email": "daaa@aaa.com", "match_field": "mc3"},
        {"email": "eaaa@aaa.com", "match_field": "mc4"}
    ]
}
# Census
census_email12 = {
    "field-validation": "enabled",
    "census": [
        {"email": "eaaa@aaa.com", 'nº de _socio 你好': 'socio 119'}
    ]
}


# Register
register_email_default = {"email": "bbbb@aaa.com", "captcha": "asdasd"}

register_email_fields = {"name": "aaaa", "email": "bbbb@aaa.com", "captcha": "asdasd"}

register_sms_default = {"tlf": "666666667", "captcha": "asdasd"}

register_sms_fields = {"name": "aaaa", "tlf": "666666667", "captcha": "asdasd"}

sms_fields_incorrect_type1 = {"age": "a lot"}
sms_fields_incorrect_type2 = {"tlf": 666666667}
sms_fields_incorrect_len1 = {"age": 16}
sms_fields_incorrect_len2 = {"name": 100*"n"}

# Authenticate
auth_email_default = {
        "email": "aaaa@aaa.com",
        "code": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
}

auth_email_default1 = {
        "email": "baaa@aaa.com",
        "code": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
}

auth_email_revote = {
        "email": "aaaa@aaa.com",
        "code": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
}

auth_email_fields = {
        "name": "aaaa",
        "email": "aaaa@aaa.com",
        "code": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
}

auth_sms_default = {
        "tlf": "666666666",
        "code": "123456"
}

auth_sms_fields = {
        "name": "aaaa",
        "tlf": "666666666",
        "code": "123456"
}

# Authmethod config
pipe_total_max_ip =  8
pipe_total_max_tlf = 4
pipe_total_max_tlf_with_period = 60
pipe_total_max_period = 60
pipe_times = 5
pipe_timestamp = 5

authmethod_config_email_default = {
        "config": {
            "subject": "Confirm your email",
            "msg": "Click __URL__ and put this code __CODE__",
            "authentication-action": {"mode": ""}
        },
        "pipeline": {
            'give_perms': [
                {'object_type': 'UserData', 'perms': ['edit',], 'object_id': 'UserDataId' },
                {'object_type': 'AuthEvent', 'perms': ['vote',], 'object_id': 'AuthEventId' }
            ],
            "register-pipeline": [
                ["check_whitelisted", {"field": "ip"}],
                ["check_blacklisted", {"field": "ip"}],
                ["check_total_max", {"field": "ip", "max": pipe_total_max_ip}],
            ],
            "authenticate-pipeline": [
                #['check_total_connection', {'times': pipe_times }],
            ]
        }
}

authmethod_config_sms_default = {
        "config": {
            "msg": "Enter in __URL__ and put this code __CODE__",
            "authentication-action": {"mode": ""}
        },
        "pipeline": {
            'give_perms': [
                {'object_type': 'UserData', 'perms': ['edit',], 'object_id': 'UserDataId' },
                {'object_type': 'AuthEvent', 'perms': ['vote',], 'object_id': 'AuthEventId' }
            ],
            "register-pipeline": [
                ["check_whitelisted", {"field": "tlf"}],
                ["check_whitelisted", {"field": "ip"}],
                ["check_blacklisted", {"field": "ip"}],
                ["check_blacklisted", {"field": "tlf"}],
                ["check_total_max", {"field": "ip", "max": pipe_total_max_ip}],
                ["check_total_max", {"field": "tlf", "max": pipe_total_max_tlf}],
                ["check_total_max", {"field": "tlf", "period": pipe_total_max_period, "max": pipe_total_max_tlf_with_period}],
            ],
            "authenticate-pipeline": [
                #['check_total_connection', {'times': pipe_times }],
                #['check_sms_code', {'timestamp': pipe_timestamp }]
            ]
        }
}

authmethod_config_smart_link_default = {
  "config": {
    "authentication-action": {"mode": ""}
  },
  "pipeline": {
    'give_perms': [
      {'object_type': 'UserData', 'perms': ['edit',], 'object_id': 'UserDataId' },
      {'object_type': 'AuthEvent', 'perms': ['vote',], 'object_id': 'AuthEventId' }
    ],
    "register-pipeline": [],
    "authenticate-pipeline": []
  }
}

# Authevent
ae_email_default = {
    "auth_method": "email",
    "census": "open",
    "extra_fields": [
        {
            "name": "email",
            "type": "email",
            "required": True,
            "unique": True,
            "min": 4,
            "max": 255,
            "required_on_authentication": True
        }
    ]
}

ae_email_default__method_config = {
  'pipeline':{
    'give_perms':[
        {
          'perms':[
              'edit'
          ],
          'object_id':'UserDataId',
          'object_type':'UserData'
        },
        {
          'perms':[
              'vote'
          ],
          'object_id':'AuthEventId',
          'object_type':'AuthEvent'
        }
    ],
    'register-pipeline':[
        [
          'check_whitelisted',
          {
              'field':'ip'
          }
        ],
        [
          'check_blacklisted',
          {
              'field':'ip'
          }
        ],
        [
          'check_total_max',
          {
              'max':10,
              'field':'ip',
              'period':3600
          }
        ],
        [
          'check_total_max',
          {
              'max':50,
              'field':'ip',
              'period':86400
          }
        ]
    ],
    'authenticate-pipeline':[

    ],
    'resend-auth-pipeline':[
        [
          'check_whitelisted',
          {
              'field':'ip'
          }
        ],
        [
          'check_blacklisted',
          {
              'field':'ip'
          }
        ],
        [
          'check_total_max',
          {
              'max':10,
              'field':'ip',
              'period':3600
          }
        ],
        [
          'check_total_max',
          {
              'max':50,
              'field':'ip',
              'period':86400
          }
        ]
    ]
  },
  'config':{
    'authentication-action':{
        'mode-config':None,
        'mode':'vote'
    },
    'subject':'Confirm your email',
    'allow_user_resend':False,
    'msg':'Click __URL__ and put this code __CODE__',
    'registration-action':{
        'mode-config':None,
        'mode':'vote'
    }
  }
}

ae_email_real = ae_email_default.copy()
ae_email_real.update({"real": True})

ae_email_real_based_in = ae_email_default.copy()
ae_email_real_based_in.update({"real": True, "based_in": 1})

ae_incorrect_authmethod = ae_email_default.copy()
ae_incorrect_authmethod.update({"auth_method": "a"})

ae_incorrect_census = ae_email_default.copy()
ae_incorrect_census.update({"census": "a"})

ae_without_authmethod = ae_email_default.copy()
ae_without_authmethod.pop("auth_method")

ae_without_census = ae_email_default.copy()
ae_without_census.pop("census")

ae_email_config = ae_email_default.copy()
ae_email_config.update( {
    "config": {
        "authentication-action": {"mode": ""},
        "subject": "Vote",
        "msg": "Enter in __URL__ and put this code __CODE__",
    }
})

ae_email_config_html = ae_email_default.copy()
ae_email_config_html.update( {
    "auth_method_config": {
        "authentication-action":{
            "mode":"vote",
            "mode-config": None
        },
        "registration-action":{
            "mode":"vote",
            "mode-config":None
        },
        "subject": "Vote",
        "msg": "Enter in __URL__ and put this code __CODE__",
        "html_message": "<html><head></head><body>HTML Click __URL__ and put this code __CODE__</body></html>",
    }
})

ae_email_config_incorrect1 = ae_email_config.copy()
ae_email_config_incorrect1.update({"config": {"aaaaaa": "bbbb"}})

ae_email_config_incorrect2 = ae_email_config.copy()
ae_email_config_incorrect2.update({"config": "aaaaaa"})


ae_email_fields = ae_email_default.copy()
ae_email_fields.update( {
    "extra_fields": [
        {
            "name": "email",
            "type": "email",
            "required": True,
            "min": 4,
            "max": 255,
            "unique": True,
            "required_on_authentication": True
        },
        {
            "name": "name",
            "help": "put the name that appear in your dni",
            "type": "text",
            "required": True,
            "min": 2,
            "max": 64,
            "unique": True,
            "required_on_authentication": True
        }
    ]
})

ae_email_fields_captcha = ae_email_fields.copy()
ae_email_fields_captcha.update(
    {
        'extra_fields': [
            {
                "name": "email",
                "type": "email",
                "required": True,
                "min": 4,
                "max": 255,
                "unique": True,
                "required_on_authentication": True
            },
            {
                'name': 'captcha',
                'type': 'captcha',
                'required': True, 
                'required_on_authentication': False
            }
        ]
    }
)

ae_email_fields_incorrect_max_fields = copy.deepcopy(ae_email_fields)
ae_email_fields_incorrect_max_fields["extra_fields"].extend([{"boo": True},
    {"boo": True}, {"boo": True}, {"boo": True}, {"boo": True}, {"boo": True},
    {"boo": True}, {"boo": True}, {"boo": True}, {"boo": True}, {"boo": True},
    {"boo": True}, {"boo": True}, {"boo": True}, {"boo": True}, {"boo": True}]
)

ae_email_fields_incorrect_empty = copy.deepcopy(ae_email_fields)
ae_email_fields_incorrect_empty["extra_fields"].extend([{'name': '', 'type': 'text', 'required_on_authentication': False}])

ae_email_fields_incorrect_len1 = copy.deepcopy(ae_email_fields)
ae_email_fields_incorrect_len1["extra_fields"].extend([{'name': settings.MAX_SIZE_NAME_EXTRA_FIELD*'ii', 'type': 'text', 'required_on_authentication': False}])

from sys import maxsize
ae_email_fields_incorrect_len2 = copy.deepcopy(ae_email_fields)
ae_email_fields_incorrect_len2["extra_fields"].extend([{'name': 'iii', 'type': 'text', 'required_on_authentication': False, 'max': maxsize + 1}])

ae_email_fields_incorrect_type = copy.deepcopy(ae_email_fields)
ae_email_fields_incorrect_type["extra_fields"].extend([{'name': 'name2', 'type': 'null', 'required_on_authentication': False}])

ae_email_fields_incorrect_value_int = copy.deepcopy(ae_email_fields)
ae_email_fields_incorrect_value_int["extra_fields"].extend([{'name': 'name2', 'type': 'text', 'required_on_authentication': False, 'min': '1'}])

ae_email_fields_incorrect_value_bool = copy.deepcopy(ae_email_fields)
ae_email_fields_incorrect_value_bool["extra_fields"].extend([{'name': 'name2', 'type': 'text', 'required_on_authentication': 'False'}])

ae_email_fields_incorrect = copy.deepcopy(ae_email_fields)
ae_email_fields_incorrect["extra_fields"].extend([{'name': 'name2', 'type': 'text', 'required_on_authentication': False, "boo": True}])

ae_email_fields_incorrect_repeat = copy.deepcopy(ae_email_fields)
ae_email_fields_incorrect_repeat["extra_fields"].extend([
    {'name': 'surname', 'type': 'text', 'required_on_authentication': False},
    {'name': 'surname', 'type': 'text', 'required_on_authentication': False}])

ae_email_fields_incorrect_email = copy.deepcopy(ae_email_fields)
ae_email_fields_incorrect_email["extra_fields"].extend([
    {'name': 'email', 'type': 'email', 'required_on_authentication': False}])

ae_email_fields_incorrect_status = copy.deepcopy(ae_email_fields)
ae_email_fields_incorrect_status["extra_fields"].extend([
    {'name': 'status', 'type': 'text', 'required_on_authentication': False}])

ae_sms_default = {
    "auth_method": "sms",
    "census": "open",
    "extra_fields": [
        {
            "name": "tlf",
            "type": "tlf", 
            "unique": True,
            "required": True,
            "min": 4,
            "max": 20,
            "required_on_authentication": True
        }        
    ]
}

ae_sms_config = {
    "auth_method": "sms",
    "census": "open",
    "config": {"msg": "Enter in __URL__ and put this code __CODE__"}
}

ae_sms_fields = {
    "auth_method": "sms",
    "census": "open",
    "extra_fields": [
        {
            "name": "name",
            "help": "whatever",
            "type": "text",
            "required": True,
            "min": 2,
            "max": 64,
            "required_on_authentication": True
        },
        {
            "name": "tlf",
            "type": "tlf", 
            "unique": True,
            "required": True,
            "min": 4,
            "max": 20,
            "required_on_authentication": True
        } 
    ]
}

ae_sms_config_incorrect = {
    "auth_method": "sms",
    "census": "open",
    "config": {"incorrect": "sms code: {code}"}
}

ae_sms_fields_incorrect = {
    "auth_method": "sms",
    "census": "open",
    "extra_fields": [
            {"boo": True}
    ]
}

extra_field_unique = [
        {
            "name": "dni",
            "type": "dni",
            "required": True,
            "unique": True,
            "required_on_authentication": True
        }
]

extra_field_autofill = [
        {
            "name": "mesa",
            "type": "text",
            "required": False,
            "unique": False,
            "required_on_authentication": False,
            "autofill": True,
        }
]

extra_field_date = [
        {
            "name": "date of birth",
            "type": "date",
            "required": False,
            "unique": False,
            "required_on_authentication": False,
            "autofill": False,
        }
]

census_date_field_ok = {
    "census": [
        {"email": "a1@aaa.com", "date of birth": "2018-01-31"},
        {"email": "a2@aaa.com", "date of birth": "2018-02-20"},
        {"email": "a3@aaa.com", "date of birth": "2018-03-14"},
        {"email": "a4@aaa.com", "date of birth": "2018-04-21"},
    ]
}

census_date_field_nok = {
    "census": [
        {"email": "a5@aaa.com", "date of birth": "2018-02-31"},
    ]
}

authmethod_config_openid_connect_default = {
        "config": {},
        "pipeline": {
            'give_perms': [
                {'object_type': 'UserData', 'perms': ['edit',], 'object_id': 'UserDataId' },
                {'object_type': 'AuthEvent', 'perms': ['vote',], 'object_id': 'AuthEventId' }
            ],
            "register-pipeline": [
                ["check_whitelisted", {"field": "ip"}],
                ["check_blacklisted", {"field": "ip"}],
                ["check_total_max", {"field": "ip", "max": pipe_total_max_ip}],
            ],
            "authenticate-pipeline": []
        }
}

auth_event18 = copy.deepcopy(auth_event1)
auth_event18["children_election_info"] = {
    "natural_order": [101,102],
    "presentation": {
        "categories": [
            {
                "id": 1,
                "title": "Executive Board",
                "events": [
                    {
                        "event_id": 101,
                        "title": "Pre/Vice"
                    },
                    {
                        "event_id": 102,
                        "title": "Vocales"
                    }
                ]
            }
        ]
    }
}

# election with no extra fields, used for child elections
auth_event19 = {
    "auth_method": "email-otp",
    "census": "open",
    "config": {
        "authentication-action": {"mode": ""},
        "subject": "Confirm your email",
        "msg": "Click __URL__ and put this code __CODE__"
    },
    "extra_fields": [
        {
            "name": "email",
            "type": "email",
            "required": True,
            "min": 4,
            "max": 255,
            "required_on_authentication": True
        }
    ]
}

def get_auth_event19_census(auth_method):
    if 'email' in auth_method:
        return {
            "census": [
                {"email": "a1@aaa.com"},
                {"email": "a2@aaa.com"},
            ]
        }
    else:
        return {
            "census": [
                {"tlf": "666555444"},
                {"tlf": "666444333"},
            ]
        }

# parent election
def get_auth_event_20(child_id_1, child_id_2):
    return {
        "auth_method": "email-otp",
        "census": "close",
        "config": {"msg": "Enter in __URL__ and put this code __CODE__"},
        "extra_fields": [
            {
                "name": "dni",
                "help": "put the dni without dash",
                "type": "dni",
                "required": True,
                "min": 5,
                "max": 12,
                "required_on_authentication": True
            },
            {
                "name": "email",
                "type": "email",
                "required": True,
                "min": 4,
                "max": 255,
                "required_on_authentication": True
            }
        ],
        "children_election_info": {
            "natural_order": [child_id_1, child_id_2],
            "presentation": {
                "categories": [
                    {
                        "id": 1,
                        "title": "Executive Board",
                        "events": [
                            {
                                "event_id": child_id_1,
                                "title": "Pre/Vice"
                            },
                            {
                                "event_id": child_id_2,
                                "title": "Vocales"
                            }
                        ]
                    }
                ]
            }
        }
    }


def get_auth_event20_census_ok(child_id_1, child_id_2, auth_method):
    if 'email' in auth_method:
        return {
            "census": [
                {
                    "email": "a1@aaa.com", 
                    "dni": "1234567L",
                    "children_event_id_list": [child_id_1, child_id_2]
                },
                {
                    "email": "a2@aaa.com", 
                    "dni": "22222222J",
                    "children_event_id_list": [child_id_1]
                },
            ]
        }
    else:
        return {
            "census": [
                {
                    "tlf": "666555444", 
                    "dni": "1234567L",
                    "children_event_id_list": [child_id_1, child_id_2]
                },
                {
                    "tlf": "666444333", 
                    "dni": "22222222J",
                    "children_event_id_list": [child_id_1]
                },
            ]
        }


def get_auth_event20_census_invalid(auth_method):
    if 'email' in auth_method:
        return {
            "census": [
                {
                    "email": "a3@aaa.com", 
                    "dni": "22222223Z",
                    "children_event_id_list": [1]
                }
            ]
        }
    else:
        return {
            "census": [
                {
                    "tlf": "666777888", 
                    "dni": "22222223Z",
                    "children_event_id_list": [1]
                }
            ]
        }
