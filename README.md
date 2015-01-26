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

# Installation

1. Download from the git repository if you haven't got a copy
    ```
    $ git clone https://github.com/agoraciudadana/authapi && cd authapi
    ```

2. Install package and its dependencies
    ```
    $ mkvirtualenv myenv
    $ pip install -r requirements.txt
    ```

3. Create postgres database:
    ```
    $ sudo su postgres
    $ createuser -P authapi
    $ createdb -O authapi authapi
    ```

4. Load initial data. This command create username admin with password admin, CHANGE IT:
    ```
    $ ./manage.py loaddata initial
    ```

5. Run:
    ```
    $ ./manage.py runserver
    ```

6. In production, for use celery, you need configure in setting the rabbitmq-server and execute:
    ```
    $ ./manage.py syncdb
    $ ./manage.py celeryd
    ```

# Tecnical details

Technically, authapi should:
 * allow migrations
 * implement unit-tests for the API calls

Basic Database tables:
* AuthEvent
    * id: autoinc int, identifies the event uniquely
    * census: string (5), type of census: close(default) or open registration
    * auth_method: string (255), unix-name of the auth method plugin used
    * auth_method_config: json-string, json configuration string
    * extra_fields: json-string
    * status: string (15), status of auth-event: notstarted(default), started or stopped
* User
    * id: string (255), random uuid, identifies the user uniquely
    * event: auth-event associate
    * credits: credits for create auth-event
    * metadata: json-string
    * status: string (255): used to flag the user
* ACL
    * id: autoinc int, identifies the event uniquely
    * user_id: string (255) foreign key, to  User.id, required
    * perm: string (255) title of the permitted action. required
    * object_type: string (255) type of object to which the user is granted permission to. required
    * object_id: string (255) object related to which the user is granted permission to id
      (default=0) mean permission in all id
* CreditsAction
    * user: userdata associate
    * action: choice add or spend
    * status: created, paid, etc
    * quantity: int
    * authevent: auth-event associate
    * payment_metadata: json-string
    * created: datetime
    * updated: datetime

The authapi is extensible using modules. The mudile can extend authapi in
different entry points defined in authapi, providing:

* new authentication methods
* new pipeline
* in general, new API methods under /\<module-name\>

For create a new module: [Development guide](Development.md)

Examples:

* email (required for a minimum version)

Provides authentication by sending a custom email for a set of users.

* sms

Provides authentication using an SMS code.

.....

# API:

## POST /get-perms

Requires a session auth-token set in the AuthToken header. Requests a given
permission to a given object type and object id  (object id not required).

IMPORTANT NOTE: if not especific id, default_id is 0. if id is 0, the user have permission about all id

Request:
    {
      "user": "someone"
      "object_type": "User",
      "permission": "create",
      "object_id": id
    }

    {
      "permission": "create",
      "object_type": "User",
      "object_id": "deadbeef"
    }

Response: If successful, returns a keyed-HMAC permission token:

    {
      "permission-token": "khmac:///sha-256;deadbeefdeadbeefdeadbeefdeadbeefdeadbeef/userid:User:deadbeef:create:timestamp"
    }

## GET /acl/:username/:object_type/:perm/:object_id

Description: object_id is optinal paramameter, if not especific, default will be 0

If successful, return: { "perm": True } if not { "perm": False }

## POST /acl

Required user with write permission for give permissions. Create an ACL entry.

IMPORTANT NOTE: if not especific id, default_id is 0. if id is 0, the user have permission about all id

Request:
    {
      "user": "someone"
      "object_type": "User",
      "permission": "create",
      "object_id": id
    }

Response: If everything is ok, it returns STATUS 200

## DELETE /acl

Required user with write permission for delete permissions. Delete an ACL entry.

IMPORTANT NOTE: if not especific id, default_id is 0. if id is 0, the user have permission about all id

Request:
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
        "auth_method": "sms",
        "census": "open",
        "config": {"sms-message": "Enter in __LINK__ and put this code __CODE__"},
        "extra_fields": [
                {
                "name": "name",
                "type": "text",
                "required": False,
                "max": 2,
                "max": 64,
                "required_on_authentication": True
                },
                {
                "name": "email",
                "type": "text",
                "required": True,
                "min": 4,
                "max": 255,
                "required_on_authentication": True
                },
                {
                "name": "dni",
                "type": "text",
                "required": True,
                #"regex": "TODO",
                "max": 9,
                "max": 9,
                "required_on_authentication": True
                }
        ]
    }

If everything is ok, it returns STATUS 200 with data:

    {"id": 1}


## POST /auth-event/:id/:status

Perms: object_type: 'AuthEvent', perm: 'edit', oject_id: auid

Description: changed the status of auth-event. Possibles: notstarted(default), started or stopped

Response: status 200

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

## GET /auth-event/#auid/census

Perms: object_type: 'AuthEvent', perm: 'edit', oject_id: auid

Description: Get census of auth-event id.

## POST /auth-event/#auid/census

Perms: object_type: 'AuthEvent', perm: 'edit', oject_id: auid

Description: import census data by administrator.
When new user register, check if there is enough credits.
When create users, the administrator will get perms 'edit' about new users.

Request: 
    [
        {
            "tlf": "+34666666666", 
            "dni": "11111111H", 
            "email": "foo@test.com",  
        },
        { 
            "tlf": "+3377777777", 
            "dni": "22222222P", 
            "email": "bar@test.com",  
        },
        ..
    ]

Response: status 200 or status 400 if error

## POST auth-event/#auid/census/send_auth

Perms: object_type: 'AuthEvent', perm: 'edit', oject_id: auid

Description: sends sms/emails (depending on auth method) to the census of an open election for authentication
If template None, will use the dafult template.

Request:
{
    "user-ids": [], # Still not implemented
    "template": "template with __CODE__ and the link is__LINK__"
}

Response: status 200

## POST /auth-event/#auid/register

Perms: none

Description: Provides authentication. Depending on the auth-method used, the
input details needed may vary:

Request:
        {
            "tlf": "+34666666666", 
            "dni": "11111111H", 
            "email": "foo@test.com",  
        }

Response: status 200 or status 400 if error

Depending on the authentication method, the authentication process might
involve more steps and thus it might be delayed. For example, when using
sms auth method, a valid answer will be an empty STATUS 200.

## POST /auth-event/#auid/authenticate

Perms: none

Description: Allows an user to verify if sms or email code and login.
If #auid if 0, 'user-and-password method is used.

Request:
    {
        "dni": "11111111H",
        "mail": "test@agoravoting.com",
        "tlf": "+34666666666",
        "code": "deadbeef"
    }

Response: If authenticate is successful, it returns STATUS 200 with data:
    {
      "auth-token": "khmac:///sha-256;deadbeefdeadbeefdeadbeefdeadbeefdeadbeef/userid:timestamp"
    }

## GET /pack/

Allows a login user view his packs:

If successful, return list of packs.

## POST /pack/

Allows a login user create or edit a own package. A valid input could be:

Create:

    {
        "name": "b",
    }

Edit:

    {
        "pack": 1,
        "status": "pai",
    }

A valid answer would be a STATUS 200 with the following data:

    {
      "status": "ok",
      "id": 1
    }

## GET /user/#id

Perms: You need be authenticated

Description: Get information of user, inclusive UserData.

## GET /user/auth-event

Perms: object_type: 'UserData', perm: 'view', oject_id: id

Description: Get ids auth-event of request user

## GET /available-prices

Perms: none

Description: Get information about prices

## GET /available-payment-methods

Perms: none

Description: Get information about payment methods

## POST /user/#id/add-credits

Perms: object_type: 'UserData', perm: 'edit', oject_id: id

Description: Allows a login user create new add_credits action.

Request: 
    {
        "pack_id": 0,
        "num_credits": 500,
        "payment_method": "paypal"
    }

Response:
    {
        "paypal_url": "foo"
    }

# Utils Commands

* Generate config auth-event and create auth-event:
    ```
    ./manage.py add_event --help
    ```
