import json

METHODS = {}

def patched_auth_event_save(*args, **kwargs):
    '''
    Save function to use in patched auth-events to prevent to inadvertenly save
    a different configuration for the auth-event.
    '''
    raise ValueError(
        "Saving to the database is not allowed in a patched auth_event used "
        "with an alternative auth method."
    )

def get_patched_auth_event(auth_event, request):
    '''
    Obtains a patched auth-event to use. It will either the same event's without
    any patching if the request doesn't request an alternative auth_method, or
    a patched auth-event with the extra_fields, auth_method and 
    auth_method_config changed to match the ones related to the requested 
    alternative authentication method.

    Patching is useful because many authentication and other methods can still
    expect to find the configuration to use in those auth-event properties, and
    thus we don't need to refactor the code o dozens of functions for the 
    use-case of alternative auth-methods.

    Returns (patched_auth_event, error).
    '''
    request = json.loads(request.body.decode('utf-8'))
    requested_alt_auth_method_id = request.get('alt_auth_method_id')

    # if alternative auth method not requested, then just return the unpatched
    # auth_event
    if requested_alt_auth_method_id is None:
        return (auth_event, None)
    else:
        alt_auth_methods = auth_event.alternative_auth_methods
        # if an alternative auth method was requested but event has none 
        # configure, return an error
        if alt_auth_methods is None:
            return (None, dict(
                status='nok',
                msg='requested alternative auth method, but none is defined',
                error_codename='invalid_auth_method'
            ))
        alt_auth_method_ids = [
            alt_auth_method['id']
            for alt_auth_method in alt_auth_methods
        ]
        # if an alternative auth method was requested is not found, return an 
        # error
        if requested_alt_auth_method_id not in alt_auth_method_ids:
            return (None, dict(
                status='nok',
                msg='requested alternative auth method id not found',
                error_codename='auth_method_id_not_found'
            ))
        # return a patched auth-event with the extra_fields, auth_method and 
        # auth_method_config changed to match the ones related to the requested 
        # alternative authentication method
        for alt_auth_method in alt_auth_methods:
            if alt_auth_method['id'] == requested_alt_auth_method_id:
                patched_auth_event = patch_auth_event(
                    auth_event.id,
                    alt_auth_method
                )
                return (patched_auth_event, None)

def patch_auth_event(auth_event_id, alt_auth_method):
    '''
    obtain a new instance of patched_auth_event and patch it to
    not allow saving and change the extra_fields, auth_method and
    auth_method_config
    '''
    from api.models import AuthEvent
    patched_auth_event = AuthEvent.objects.get(pk=auth_event_id)
    patched_auth_event.save = patched_auth_event_save
    patched_auth_event.auth_method = alt_auth_method['auth_method_name']
    patched_auth_event.auth_method_config = alt_auth_method['auth_method_config']
    patched_auth_event.extra_fields = alt_auth_method['extra_fields']
    return patched_auth_event

def check_config(config, auth_method, data):
    """
    Check config when creating an auth-event
    """
    return METHODS[auth_method].check_config(config, data)

def auth_census(auth_event, data):
    (patched_auth_event, error) = get_patched_auth_event(auth_event, data)
    if error is not None:
        return error

    return METHODS[patched_auth_event.auth_method].census(
        patched_auth_event, data
    )

def auth_register(auth_event, data):
    (patched_auth_event, error) = get_patched_auth_event(auth_event, data)
    if error is not None:
        return error

    return METHODS[patched_auth_event.auth_method].register(
        patched_auth_event, data
    )

def auth_authenticate(auth_event, data):
    (patched_auth_event, error) = get_patched_auth_event(auth_event, data)
    if error is not None:
        return error

    return METHODS[patched_auth_event.auth_method].authenticate(
        patched_auth_event, data
    )

def auth_authenticate_otl(auth_event, data):
    (patched_auth_event, error) = get_patched_auth_event(auth_event, data)
    if error is not None:
        return error

    return METHODS[patched_auth_event.auth_method].authenticate_otl(
        patched_auth_event, data
    )

def auth_resend_auth_code(auth_event, data):
    (patched_auth_event, error) = get_patched_auth_event(auth_event, data)
    if error is not None:
        return error

    return METHODS[patched_auth_event.auth_method].resend_auth_code(
        patched_auth_event, data
    )

def auth_public_census_query(auth_event, data):
    (patched_auth_event, error) = get_patched_auth_event(auth_event, data)
    if error is not None:
        return error

    return METHODS[patched_auth_event.auth_method].public_census_query(
        patched_auth_event, data
    )

def auth_generate_auth_code(auth_event, user):
    return METHODS[auth_event.auth_method].generate_auth_code(auth_event, user)

def register_method(name, klass):
    METHODS[name] = klass()

default_app_config = 'authmethods.apps.AuthmethodsConfig'
