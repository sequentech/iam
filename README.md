## authapi [![Build Status][1]][2]
[![Coverage Status](https://coveralls.io/repos/agoravoting/authapi/badge.png)](https://coveralls.io/r/agoravoting/authapi)

[1]: https://travis-ci.org/agoravoting/authapi.png
[2]: https://travis-ci.org/agoravoting/authapi

The authapi is an isolated server-side component written in go language that
provides authentication primitives. It's important that is completely decoupled
from agora-core, and it's ignorant of concepts like "election", "vote" or
"agora". It could be used for authentication for other services, completely
unrelated to elections.

An Authentication Event (or auth-event) is an important concept in the
authapi. Let's explain it with an example: imagine you're creating a single
election, where you have a given census of electors, and you authenticate the
electors sending a SMS code to their mobile phones. In that case, the election
will have an associated event auth in an authapi, configured with a
census, configured to use the "SMS-code" authentication method, and the SMS
provider credentials details needed to be able to send emails.

Another important entity in authapi is an "AuthUser". An user represents
someone related to an auth-event. Each auth-user can be uniquely referenced
by the user-id. Note that the same physical person might have multiple
uath-users associated, one per auth-event. AuthUsers also have associated
metadata, like Full Name, email, tlf number, etc.

The exact details that each auth-user has associated may vary on each
auth-event. Also, some auth-events might have associated a census, while
in others the census might be generated on the go.

Not everyone can create a new auth-event, and not every-one can administrate an
auth-event to configure its details. This requires special permissions, but
the handling of those administration details is delegated externally, using
a trusted HMAC received in the API calls that need priviledges.

The HMAC used for authentication of some requests always contains two
semi-colon separated fields: `<granted-permission>:<expiration-timestamp>`.

Part of the API does not require priviledges, like the API-call to
authenticate. Each authentication attempt gets registered, even if it's not
successful. This information can be useful for diagnosis.

Technically, authapi should:
 * be developed in the Go language
 * use postgresql as the database. We don't really need to use DB-abstractions
 * allow migrations
 * implement unit-tests for the API calls

Basic Database tables:
* AuthEvent
    * id: autoinc int, identifies the event uniquely
    * name: string (255), user-friendly name
    * auth_method: string (255), unix-name of the auth method plugin used
    * auth_method_config: json-string, json configuration string
* AuthUser
    * id: string (255), random uuid, identifies the user uniquely
    * auth_event_id: int, foreign key, to AuthEvent.id
    * metadata: json-string
    * status: string (255): used to flag the user
* AuthAttempt
    * id: autoinc int, identifies the event uniquely
    * auth_user_id: string (255) foreign key, to  AuthUser.id
    * credentials: json-string with the credentials provider by the user
    * action: string (255): action being executed by the user
    * status: string (255): status of the attempt

The authapi is extensible using plugins. There are two kind of plugins: the
ones that provide an auth method, and the ones that provide a pipeline
function. A plugin can add new entry points.

* email-link (required for a minimum version)
Provides authentication by sending a custom email for a set of users. It adds
the entry point for email-sending "POST /p/email-link/send-mail"


* sms-code
Provides authentication using an SMS code. It adds the entry point for SMS-code
verification "POST /p/sms-code/verify".

.....

API:

# POST /auth-event

The requester tries to create a new auth-event. Requires an HMAC with
permissions "superuser".

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

### authapi Admin API

#### GET /auth-event/:id

Returns similar data to the data posted in POST /auth-event. Requires an HMAC
with permission `admin-auth-event-<id>`.

#### GET /auth-event

List auth events. Accepts filtering and paging. Requires an HMAC with
permission `superuser`

#### PUT /auth-event/:id

Receives similar data to POST /auth-event. Requires an HMAC with permission
`admin-auth-event-<id>`.

#### DELETE /auth-event/:id

Requires an HMAC with permission `admin-auth-event-<id>`.

#### GET /auth-event/:id/user

Lists the users. Accepts filtering and paging. Requires an HMAC with permission
`admin-auth-event-<id>`.

#### GET /auth-event/:id/user/:id2

Gets an user details. Requires an HMAC with permission `admin-auth-event-<id>`.

#### POST /auth-event/:id/user/:id2

Removes an user. Requires an HMAC with permission `admin-auth-event-<id>`.

#### POST /auth-event/:id/user

Posts an user. Unusually used, because they are usually created in other ways
using the auth-method plugins. Requires an HMAC with permission
`admin-auth-event-<id>`.

#### GET /auth-event/:id/attempt

Lists the authentication attempts. Supports filtering. Requires an HMAC with
permission `admin-auth-event-<id>`.

# GET /auth-event/:id/attempt/:id2

Gets an authentication attempt details. Supports filtering. Requires an HMAC
with permission `admin-auth-event-<id>`.

### authapi User API

#### POST /auth-event/:id/auth

Provides authentication. Depending on the auth-method used, the
input details needed may vary. If authentication is successful, it returns
STATUS 200 with data:

    {"hmac": ["auth:<event-id>:<user-id>:<timestamp>", "deadbeefdeadbeef"]}

Depending on the authentication method, the authentication process might
involve more steps and thus it might be delayed. For example, when using
sms-code auth method, a valid answer will be an empty STATUS 200.

#### POST /p/sms-code/verify

Allows an user to verify its SMS code. A valid input could be:

    {
        "auth-event-id": 12,
        "tlf": "+34666666666",
        "sms-code": "deadbeef"
    }

A valid answer would be a STATUS 200 with the following data:

    {"hmac": ["auth:<event-id>:<user-id>:<timestamp>", "deadbeefdeadbeef"]}
