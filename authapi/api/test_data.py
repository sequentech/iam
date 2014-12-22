pwd_auth = {
    'auth-method': 'user-and-password',
    'auth-data': {'username': 'john', 'password': 'smith'}
}

pwd_auth_email = {
    'auth-method': 'user-and-password',
    'auth-data': {'email': 'john@agoravoting.com', 'password': 'smith'}
}

auth_event1 = {
    "hmac": ["superuser:11114341", "deadbeefdeadbeef"],
    "name": "foo election",
    "description": "foo election description",
    "auth_method": "sms-code",
    "auth_method_config": {
        "sms-provider": "esendex",
        "user": "foo",
        "password": "wahtever",
        "sms-message": "%(server_name)s: your token is: %(token)s",
        "sms-token-expire-secs": 600,
        "max-token-guesses": 3,
        "authapi": {
            "mode": "on-the-go",
            "fields": [
                {
                    "name": "Name",
                    "type": "string",
                    "length": [13, 255],
                }
            ]
        },
        "register-pipeline": [
            ["register_request"],
            ["check_has_not_status", {"field": "tlf", "status": "voted"}],
            ["check_has_not_voted", {"field": "dni", "status": "voted"}],
            ["check_tlf_expire_max", {"field": "tlf", "expire-secs": 120}],
            ["check_whitelisted", {"field": "tlf"}],
            ["check_whitelisted", {"field": "ip"}],
            ["check_blacklisted", {"field": "ip"}],
            ["check_blacklisted", {"field": "tlf"}],
            ["check_ip_total_unconfirmed_requests_max",
                {"max": 30}],
            ["check_total_max", {"field": "ip", "max": 8}],
            ["check_total_max", {"field": "tlf", "max": 7}],
            ["check_total_max", {"field": "tlf", "period": 1440, "max": 5}],
            ["check_total_max", {"field": "tlf", "period": 60, "max": 3}],
            ["check_id_in_census", {"fields": "tlf"}],
            ["generate_token", {"land_line_rx": "^\+34[89]"}],
            ["send_sms_pipe"],
        ],
        "feedback-pipeline": [
            ["check_sms_code", {"field-auth": "tlf", "field-code":
                "sms-code"}],
            ["mark_as", {"field-auth": "tlf", "status": "voted"}],
        ]
    },
    "metadata": {
        'fields': [
            {'name': 'email', 'type': 'text', 'required': True},
            {'name': 'password', 'type': 'password', 'required': True, 'min': 6},
        ],
    }
}

auth_event2 = {
    "hmac": ["superuser:11114341", "deadbeefdeadbeef"],
    "name": "bar election",
    "description": "foo election description",
    "auth_method": "sms-code",
    "auth_method_config": {
        "sms-provider": "esendex",
        "user": "foo",
        "password": "wahtever",
        "sms-message": "%(server_name)s: your token is: %(token)s",
        "sms-token-expire-secs": 600,
        "max-token-guesses": 3,
        "authapi": {
            "mode": "on-the-go",
            "fields": [
                {
                    "name": "Name",
                    "type": "string",
                    "length": [13, 255],
                }
            ]
        },
        "register-pipeline": [
            ["register_request"],
            ["check_has_not_status", {"field": "tlf", "status": "voted"}],
            ["check_has_not_voted", {"field": "dni", "status": "voted"}],
            ["check_tlf_expire_max", {"field": "tlf", "expire-secs": 120}],
            ["check_whitelisted", {"field": "tlf"}],
            ["check_whitelisted", {"field": "ip"}],
            ["check_blacklisted", {"field": "ip"}],
            ["check_blacklisted", {"field": "tlf"}],
            ["check_ip_total_unconfirmed_requests_max",
                {"max": 30}],
            ["check_total_max", {"field": "ip", "max": 8}],
            ["check_total_max", {"field": "tlf", "max": 7}],
            ["check_total_max", {"field": "tlf", "period": 1440, "max": 5}],
            ["check_total_max", {"field": "tlf", "period": 60, "max": 3}],
            ["check_id_in_census", {"fields": "tlf"}],
            ["generate_token", {"land_line_rx": "^\+34[89]"}],
            ["send_sms_pipe"],
        ],
        "feedback-pipeline": [
            ["check_sms_code", {"field-auth": "tlf", "field-code":
                "sms-code"}],
            ["mark_as", {"field-auth": "tlf", "status": "voted"}],
        ]
    },
    "metadata": {
        'fields': [
            {'name': 'email', 'type': 'text', 'required': True},
            {'name': 'password', 'type': 'password', 'required': True, 'min': 6},
        ],
    }
}
