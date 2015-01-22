pwd_auth = {'username': 'john', 'password': 'smith'}

pwd_auth_email = {'email': 'john@agoravoting.com', 'password': 'smith'}

auth_event1 = {
    "hmac": ["superuser:11114341", "deadbeefdeadbeef"],
    "name": "foo election",
    "description": "foo election description",
    "auth_method": "sms-code",
    "config": {
        "SMS_PROVIDER": "console",
        "SMS_DOMAIN_ID": "",
        "SMS_LOGIN": "",
        "SMS_PASSWORD": "",
        "SMS_URL": "",
        "SMS_SENDER_ID": "",
        "SMS_VOICE_LANG_CODE": "",
        "sms-message": "Confirm your sms code: ",
    },
    "pipeline": {
        "register-pipeline": [
            #["check_tlf_expire_max", {"field": "tlf", "expire-secs": 120}],
            ["check_whitelisted", {"field": "tlf"}],
            ["check_whitelisted", {"field": "ip"}],
            ["check_blacklisted", {"field": "ip"}],
            ["check_blacklisted", {"field": "tlf"}],
            #["check_ip_total_unconfirmed_requests_max", {"max": 30}],
            ["check_total_max", {"field": "ip", "max": 8}],
            ["check_total_max", {"field": "tlf", "max": 7}],
            ["check_total_max", {"field": "tlf", "period": 1440, "max": 5}],
            ["check_total_max", {"field": "tlf", "period": 60, "max": 3}],
            #["check_id_in_census", {"fields": "tlf"}],
            #["generate_token", {"land_line_rx": "^\+34[89]"}],
        ],
        "validate-pipeline": [
            ['check_total_connection', {'times': 5 }],
            ['check_sms_code', {'timestamp': 5 }], # seconds
        ]
    },
    "metadata": {
        'fieldsRegister': [
            {'name': 'name', 'type': 'text', 'required': False},
            {'name': 'surname', 'type': 'text', 'required': False},
            {'name': 'dni', 'type': 'text', 'required': True, 'max': 9},
            {'name': 'tlf', 'type': 'text', 'required': True, 'max': 12},
            {'name': 'email', 'type': 'text', 'required': True},
            {'name': 'password', 'type': 'password', 'required': True, 'min': 6},
        ],
        'fieldsValidate': [
            {'name': 'dni', 'type': 'text', 'required': True, 'max': 9},
            {'name': 'tlf', 'type': 'text', 'required': True, 'max': 12},
            {'name': 'code', 'type': 'password', 'required': True, 'min': 4},
        ],
        #'capcha': False,
    }
}

auth_event2 = {
    "hmac": ["superuser:11114341", "deadbeefdeadbeef"],
    "name": "bar election",
    "description": "foo election description",
    "auth_method": "sms-code",
    "census": "open",
    "config": {
        "SMS_PROVIDER": "console",
        "SMS_DOMAIN_ID": "",
        "SMS_LOGIN": "",
        "SMS_PASSWORD": "",
        "SMS_URL": "",
        "SMS_SENDER_ID": "",
        "SMS_VOICE_LANG_CODE": "",
        "sms-message": "Confirm your sms code: ",
    },
    "pipeline": {
        "register-pipeline": [
            #["check_tlf_expire_max", {"field": "tlf", "expire-secs": 120}],
            ["check_whitelisted", {"field": "tlf"}],
            ["check_whitelisted", {"field": "ip"}],
            ["check_blacklisted", {"field": "ip"}],
            ["check_blacklisted", {"field": "tlf"}],
            #["check_ip_total_unconfirmed_requests_max", {"max": 30}],
            ["check_total_max", {"field": "ip", "max": 8}],
            ["check_total_max", {"field": "tlf", "max": 7}],
            ["check_total_max", {"field": "tlf", "period": 1440, "max": 5}],
            ["check_total_max", {"field": "tlf", "period": 60, "max": 3}],
            #["check_id_in_census", {"fields": "tlf"}],
            #["generate_token", {"land_line_rx": "^\+34[89]"}],
        ],
        "validate-pipeline": [
            ['check_total_connection', {'times': 5 }],
            ['check_sms_code', {'timestamp': 5 }], # seconds
        ],
        "login-pipeline": [
        ]
    },
    "metadata": {
        'fieldsRegister': [
            {'name': 'name', 'type': 'text', 'required': False},
            {'name': 'surname', 'type': 'text', 'required': False},
            {'name': 'dni', 'type': 'text', 'required': True, 'max': 9},
            {'name': 'tlf', 'type': 'text', 'required': True, 'max': 12},
            {'name': 'email', 'type': 'text', 'required': True},
            {'name': 'password', 'type': 'password', 'required': True, 'min': 6},
        ],
        'fieldsValidate': [
            {'name': 'dni', 'type': 'text', 'required': True, 'max': 9},
            {'name': 'tlf', 'type': 'text', 'required': True, 'max': 12},
            {'name': 'code', 'type': 'password', 'required': True, 'min': 4},
        ],
        'fieldsLogin': [
            {'name': 'dni', 'type': 'text', 'required': True, 'max': 9},
            {'name': 'password', 'type': 'password', 'required': True, 'min': 6},
        ],
        #'capcha': False,
    }
}

auth_event3 = {
    "hmac": ["superuser:11114341", "deadbeefdeadbeef"],
    "name": "main election",
    "description": "main election description",
    "auth_method": "email",
    "census": "open",
    "config": {
        'subject': 'Confirm your email',
        'msg': 'Click in this link for validate your email: ',
        'mail_from': 'authapi@agoravoting.com',
        'give_perms': {'object_type': 'Vote', 'perms': ['create',] },
    },
    "pipeline": {
        "register-pipeline": [],
        "validate-pipeline": [],
        "login-pipeline": []
    },
    "metadata": {
        'fieldsRegister': [
            {'name': 'email', 'type': 'text', 'required': True},
            {'name': 'password', 'type': 'password', 'required': True, 'min': 6},
        ],
        'fieldsValidate': [
            {'name': 'email', 'type': 'text', 'required': True},
            {'name': 'password', 'type': 'password', 'required': True, 'min': 6},
        ]
    }
}

auth_event4 = {
    "hmac": ["superuser:11114341", "deadbeefdeadbeef"],
    "name": "test1",
    "description": "test1 description",
    "auth_method": "user-and-password",
    "census": "open",
    "config": {},
    "pipeline": {
        "register-pipeline": [],
        "validate-pipeline": [],
        "login-pipeline": []
    },
    "metadata": {
        'fieldsLogin': [
            {'name': 'username', 'type': 'text', 'required': False},
            {'name': 'password', 'type': 'password', 'required': True, 'min': 6},
        ],
    }
}

# Users
admin = {'username': 'john', 'password': 'smith'}

# Census
census_email_default = [
        {"email": "aaaa@aaa.com"},
        {"email": "baaa@aaa.com"},
        {"email": "caaa@aaa.com"},
        {"email": "daaa@aaa.com"}
]

census_email_fields = [
        {"name": "aaaa", "email": "aaaa@aaa.com"},
        {"name": "baaa", "email": "baaa@aaa.com"},
        {"name": "caaa", "email": "caaa@aaa.com"},
        {"name": "daaa", "email": "daaa@aaa.com"}
]

census_sms_default = [
        {"tlf": "666666666"},
        {"tlf": "666666667"},
        {"tlf": "666666668"},
        {"tlf": "666666669"}
]

census_sms_fields = [
        {"name": "aaaa", "tlf": "666666666"},
        {"name": "baaa", "tlf": "666666667"},
        {"name": "caaa", "tlf": "666666668"},
        {"name": "daaa", "tlf": "666666669"}
]

# Register
register_email_default = {"email": "aaaa@aaa.com", "captcha": "asdasd"}

register_email_fields = {"name": "aaaa", "email": "aaaa@aaa.com", "captcha": "asdasd"}

register_sms_default = {"tlf": "666666666", "captcha": "asdasd"}

register_sms_fields = {"name": "aaaa", "tlf": "666666666", "captcha": "asdasd"}

# Authenticate
auth_email_default = {
        "email": "aaaa@aaa.com",
        "code": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
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
authmethod_config_email_default = {
        "config": 1,
        "pipeline": 2
}

authmethod_config_sms_default = {
        "config": 1,
        "pipeline": 2
}

# Authevent
ae_email_default = {
    "auth_method": "email",
    "census": "open",
}


ae_email_config = {
    "auth_method": "email",
    "census": "open",
    "config": {
        "subject": "Vote",
        "msg": "Click here: {link} ",
    }
}

ae_email_fields = {
    "auth_method": "email",
    "census": "open",
    "extra_fields": [
            {
            "name": "name",
            "type": "text",
            "required": True,
            "max": 2,
            "max": 64,
            "required_on_authentication": True
            }
    ]
}

ae_email_fields_incorrect1 = {
    "auth_method": "email",
    "census": "open",
    "extra_fields": [
            {"boo": True},
            {"boo": True},
            {"boo": True},
            {"boo": True},
            {"boo": True},
            {"boo": True},
            {"boo": True},
            {"boo": True},
            {"boo": True},
            {"boo": True},
            {"boo": True},
            {"boo": True},
            {"boo": True},
            {"boo": True},
            {"boo": True},
            {"boo": True}
    ]
}

ae_email_fields_incorrect2 = {
    "auth_method": "email",
    "census": "open",
    "extra_fields": [
            {"boo": True}
    ]
}

ae_email_fields = {
        "name": "aaaa",
        "email": "aaaa@aaa.com",
        "code": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
}


ae_email_fields_incorrect  = {
    "auth_method": "email",
    "census": "open",
    "extra_fields": [
            {
            "name": "name",
            "type": "text",
            "required": "True",
            "max": "yes",
            "max": 64,
            "required_on_authentication": True
            }
    ]
}

ae_email_config_incorrect1 = {
    "auth_method": "email",
    "census": "open",
    "config": {"aaaaaa": "bbbb"}
}

ae_email_config_incorrect2 = {
    "auth_method": "email",
    "census": "open",
    "config": "aaaaaa"
}

ae_sms_default = {
    "auth_method": "sms",
    "census": "open",
}

ae_sms_config = {
    "auth_method": "sms",
    "census": "open",
    "config": {"sms-message": "sms code: {code}"}
}

ae_sms_fields = {
    "auth_method": "sms",
    "census": "open",
    "extra_fields": [
            {
            "name": "name",
            "type": "text",
            "required": True,
            "max": 2,
            "max": 64,
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
