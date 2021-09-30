METHODS = {}

def check_config(config, auth_method):
    """ Check config when create auth-event. """
    return METHODS[auth_method].check_config(config)

def auth_census(event, data):
    return METHODS[event.auth_method].census(event, data)

def auth_register(event, data):
    return METHODS[event.auth_method].register(event, data)

def auth_authenticate(event, data):
    if event == 0:
        return METHODS['user-and-password'].authenticate(event, data)
    
    return METHODS[event.auth_method].authenticate(event, data)

def auth_resend_auth_code(event, data):
    return METHODS[event.auth_method].resend_auth_code(event, data)

def auth_public_census_query(event, data):
    return METHODS[event.auth_method].public_census_query(event, data)

def auth_generate_auth_code(event, user):
    return METHODS[event.auth_method].generate_auth_code(event, user)

def register_method(name, klass):
    METHODS[name] = klass()


default_app_config = 'authmethods.apps.AuthmethodsConfig'
