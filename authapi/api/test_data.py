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
        'fieldsValidate': 'Link sent. Click for activate account.',
        'capcha': False,
    }
}

auth_event4 = {
    "hmac": ["superuser:11114341", "deadbeefdeadbeef"],
    "name": "test1",
    "description": "test1 description",
    "auth_method": "user-and-password",
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
