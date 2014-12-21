# authapi [![Build Status][1]][2] [![Coverage Status](https://coveralls.io/repos/agoravoting/authapi/badge.png)](https://coveralls.io/r/agoravoting/authapi)

[1]: https://travis-ci.org/agoravoting/authapi.png
[2]: https://travis-ci.org/agoravoting/authapi

# Introduction

The authapi is an isolated server-side component that provides
authentication and authorization primitives. It's is completely decoupled
from agora-core, and it's ignorant of concepts like "election", "vote" or
"agora", even though its primarily developed with Agora voting use-case in
mind. It can be used for other services, completely unrelated to elections.

An Authentication Event (or auth-event) is an important concept in the
authapi. Let's explain it with an example: imagine you're creating a single
election, where you have a given census of electors, and you authenticate the
electors sending a SMS code to their mobile phones. In that case, the election
will have an associated event auth in an authapi, configured with a
census, configured to use the "SMS-code" authentication method, and the SMS
provider credentials details needed to be able to send emails.

Another important entity in authapi is an "User". Each auth-user can be uniquely
referenced by the user-id. The users have some authorization to act over some
objects using ACLs.

Authorization is provided using an Access Control Lists (ACLs) mechanism. Not
every user can create a new auth-event, and not every-one can administrate an
auth-event to configure its details. ACLs are stored in a table of the database,
with an id, a permission string, an object id, an object type, and an user-id.

With ACLs, you can for example say "user 34 has 'create' permission
of object type 'AuthEvent'" or "user 122 has 'admin' permission on object 33 of
type 'Election'", for example. This information can be extracted in the form of
an HMAC credential token that can be used by a third-party application to
verify that the given user has permission to execute any kind of action to any
kind of object.


# Tecnical detail

Technically, authapi should:
 * allow migrations
 * implement unit-tests for the API calls

Basic Database tables:
* AuthEvent
    * id: autoinc int, identifies the event uniquely
    * name: string (255), user-friendly name
    * auth_method: string (255), unix-name of the auth method plugin used
    * auth_method_config: json-string, json configuration string
    * metadata: json-string
* User
    * id: string (255), random uuid, identifies the user uniquely
    * metadata: json-string
    * status: string (255): used to flag the user
* ACL
    * id: autoinc int, identifies the event uniquely
    * user_id: string (255) foreign key, to  User.id, required
    * perm: string (255) title of the permitted action. required
    * object_type: string (255) type of object to which the user is granted permission to. required
    * object_id: string (255) object related to which the user is granted permission to

The authapi is extensible using modules. The mudile can extend authapi in
different entry points defined in authapi, providing:

* new authentication methods
* new pipeline
* in general, new API methods under /\<module-name\>

For create a new module: [Development guide](Development.md)

Examples:

* email-link (required for a minimum version)

Provides authentication by sending a custom email for a set of users. It adds
the entry point for email-sending "POST /email-link/send-mail"

* sms-code

Provides authentication using an SMS code. It adds the entry point for SMS-code
verification "POST /sms-code/verify".

.....

# API:

## POST /login

The requester provides the data used by an authentication mechanism. Example:

    {
      "auth-method": "user-and-password",
      "auth-data": {
        "username": "foo",
        "password": "bar"
      }
    }

If successful, returns a keyed-HMAC session token.
    {
      "auth-token": "khmac:///sha-256;deadbeefdeadbeefdeadbeefdeadbeefdeadbeef/userid:timestamp"
    }

## POST /get-perms

Requires a session auth-token set in the AuthToken header. Requests a given
permission to a given object type and object id  (object id not required).
Example:

    {
      "permission": "create",
      "object_type": "User",
      "object_id": "deadbeef"
    }

If successful, returns a keyed-HMAC permission token:

    {
      "permission-token": "khmac:///sha-256;deadbeefdeadbeefdeadbeefdeadbeefdeadbeef/userid:User:deadbeef:create:timestamp"
    }

## GET /acl/:userid/:object_type/:perm/

If successful, return: { "perm": True } if not { "perm": False }

## POST /acl

Required user with write permission for give permissions. Create an ACL entry.
Example:

{
  "user": "someone"
  "object_type": "User",
  "permission": "create",
}

If everything is ok, it returns STATUS 200

## DELETE /acl

Required user with write permission for delete permissions. Delete an ACL entry.
Example:

{
  "user": "someone"
  "object_type": "User",
  "permission": "create",
}

If everything is ok, it returns STATUS 200

## POST /auth-event

The requester tries to create a new auth-event. Requires a session auth-token
set in the AuthToken header, with an user with permissions "superuser".

Valid Input example:

    {
        "hmac": ["superuser:11114341", "deadbeefdeadbeef"],
        "name": "foo election",
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
                    },
                    ...
                ]
            },
            "register-pipeline": [
                ["register_request"],
                ["check_has_not_status", {"field": "tlf", "status": "voted"}],
                ["check_has_not_voted", {"field": "dni", "status": "voted"}],
                ["check_tlf_expire_max", {"field": "tlf", "expire-secs": 120}],
                ["check_whitelisted", {"field": "tlf"}],
                ["check_whitelisted", {"field", "ip"}],
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
        }
    }

If everything is ok, it returns STATUS 200 with data:

    {"id": 1}


## GET /auth-event

List auth events. Accepts filtering and paging. Not requires user with
permission

## GET /auth-event/:id

Returns some neccesary data for register or login in an event. Not requires user
with permission

## DELETE /auth-event/:id

Requires user with permission `admin-auth-event` over the given event.

## POST /auth-event/:id

Edit the event with id given. Requires user with permission `admin-auth-event`
over the given event.

## PUT /auth-event/:id *

Receives similar data to POST /auth-event. Requires user
with permission `admin-auth-event` over the given event.

## POST /authmethod/:authmethod/register/:id

Provides authentication. Depending on the auth-method used, the
input details needed may vary. If authentication is successful, it returns
STATUS 200 with data:

    {
      "auth-token": "khmac:///sha-256;deadbeefdeadbeefdeadbeefdeadbeefdeadbeef/userid:timestamp"
    }

Depending on the authentication method, the authentication process might
involve more steps and thus it might be delayed. For example, when using
sms-code auth method, a valid answer will be an empty STATUS 200.

## POST /authmethod/:authmethod/validate/:id

Allows an user to verify its SMS code. A valid input could be:

    {
        "dni": "11111111H",
        "mail": "test@agoravoting.com",
        "tlf": "+34666666666",
        "sms-code": "deadbeef"
    }

A valid answer would be a STATUS 200 with the following data:

    {
      "auth-token": "khmac:///sha-256;deadbeefdeadbeefdeadbeefdeadbeefdeadbeef/userid:timestamp"
    }
