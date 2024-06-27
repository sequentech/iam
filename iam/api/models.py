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

import json
from datetime import datetime
from celery import current_app
from django.db import models
from django.core.validators import MaxValueValidator, MinValueValidator
from django.core.exceptions import ValidationError
from django.contrib.auth.models import User
from django.db.models.functions import TruncHour

from django.contrib.postgres import fields
from jsonfield import JSONField

from django.dispatch import receiver
from django.db.models.signals import post_save, pre_save
from django.db.models import Q, Count, DateTimeField
from django.conf import settings
from django.utils import timezone

from contracts.base import check_contract
from contracts import CheckException
from marshmallow import (
    Schema,
    fields as marshmallow_fields,
    decorators
)
from marshmallow.exceptions import ValidationError as MarshMallowValidationError
from django.db.models import CharField
from django.db.models.functions import Length

from utils import genhmac
from api.middleware import CurrentUserMiddleware

CharField.register_lookup(Length, 'length')

CENSUS = (
    ('close', 'Close census'),
    ('open', 'Open census'),
)

AE_STATUSES = (
    ('notstarted', 'not-started'),
    ('started', 'started'),
    ('stopped', 'stopped'),
    ('resumed', 'resumed'),
    ('suspended', 'suspended')
)

AE_TALLY_STATUSES = (
    ('notstarted', 'notstarted'),
    ('pending', 'pending'),
    ('started', 'started'),
    ('success', 'success'),
)

AE_TALLY_MODES = (
    ('active', 'active'),
    ('all', 'all'),
)

CHILDREN_EVENT_ID_LIST_CONTRACT = [
    {
        'check': 'isinstance',
        'type': list
    },
    {
        'check': "iterate-list",
        'check-list': [
            {
                'check': 'isinstance',
                'type': int
            },
        ]
    },
    {
        'check': 'lambda',
        'lambda': lambda d: len(set(d)) == len(d) and len(d) > 0
    }
]

CHILDREN_ELECTION_INFO_CONTRACT = [
    {
        'check': 'isinstance',
        'type': dict
    },
    {
        'check': 'dict-keys-exist',
        'keys': ['natural_order', 'presentation']
    },
    {
        'check': 'index-check-list',
        'index': 'natural_order',
        'check-list': [
            {
                'check': 'isinstance',
                'type': list
            },
            {
                'check': 'length',
                'range': [1, 200]
            },
            {
                'check': 'lambda',
                'lambda': lambda d: len(set(d)) == len(d)
            }
        ]
    },
    {
        'check': 'index-check-list',
        'index': 'presentation',
        'check-list': [
            {
                'check': 'isinstance',
                'type': dict
            },
            {
                'check': 'dict-keys-exact',
                'keys': ['categories']
            },
            {
                'check': 'index-check-list',
                'index': 'categories',
                'check-list': [
                    {
                        'check': 'isinstance',
                        'type': list
                    },
                    {
                        'check': "iterate-list",
                        'check-list': [
                            {
                                'check': 'isinstance',
                                'type': dict
                            },
                            {
                                'check': 'dict-keys-exist',
                                'keys': ['id', 'title', 'events']
                            },
                            {
                                'check': 'index-check-list',
                                'index': 'id',
                                'check-list': [
                                    {
                                        'check': 'isinstance',
                                        'type': int
                                    },
                                    {
                                        'check': 'lambda',
                                        'lambda': lambda d: d >= 1
                                    }
                                ]
                            },
                            {
                                'check': 'index-check-list',
                                'index': 'title',
                                'check-list': [
                                    {
                                        'check': 'isinstance',
                                        'type': str
                                    },
                                    {
                                        'check': 'length',
                                        'range': [1, 254]
                                    }
                                ]
                            },
                            {
                                'check': 'index-check-list',
                                'index': 'title_i18n',
                                'optional': True,
                                'check-list': [
                                    {
                                        'check': 'isinstance',
                                        'type': dict
                                    },
                                    {   # keys are strings
                                        'check': 'lambda',
                                        'lambda': lambda d: all([isinstance(k, str) for k in d.keys()])
                                    },
                                    {   # values are strings
                                        'check': 'lambda',
                                        'lambda': lambda d: all([isinstance(k, str) for k in d.values()])
                                    },
                                ]
                            },
                            {
                                'check': 'index-check-list',
                                'index': 'events',
                                'check-list': [
                                    {
                                        'check': 'isinstance',
                                        'type': list
                                    },
                                    {
                                        'check': "iterate-list",
                                        'check-list': [
                                            {
                                                'check': 'dict-keys-exist',
                                                'keys': ['event_id', 'title']
                                            },
                                            {
                                                'check': 'index-check-list',
                                                'index': 'event_id',
                                                'check-list': [
                                                    {
                                                        'check': 'isinstance',
                                                        'type': int
                                                    },
                                                    {
                                                        'check': 'lambda',
                                                        'lambda': lambda d: d >= 1
                                                    }
                                                ]
                                            },
                                            {
                                                'check': 'index-check-list',
                                                'index': 'title',
                                                'check-list': [
                                                    {
                                                        'check': 'isinstance',
                                                        'type': str
                                                    },
                                                    {
                                                        'check': 'length',
                                                        'range': [1, 254]
                                                    }
                                                ]
                                            },
                                            {
                                                'check': 'index-check-list',
                                                'index': 'title_i18n',
                                                'optional': True,
                                                'check-list': [
                                                    {
                                                        'check': 'isinstance',
                                                        'type': dict
                                                    },
                                                    {   # keys are strings
                                                        'check': 'lambda',
                                                        'lambda': lambda d: all([isinstance(k, str) for k in d.keys()])
                                                    },
                                                    {   # values are strings
                                                        'check': 'lambda',
                                                        'lambda': lambda d: all([isinstance(k, str) for k in d.values()])
                                                    },
                                                ]
                                            }
                                        ]
                                    }
                                ]
                            }
                        ]
                    }
                ]
            }
        ]
    },
    {
        'check': 'lambda',
        'lambda': lambda d: set(d['natural_order']) == set([
            event['event_id']
                for category in d['presentation']['categories']
                    for event in category['events']
        ])
    },
    {
        'check': 'lambda',
        'lambda': lambda d: len(set([
            event['event_id']
                for category in d['presentation']['categories']
                    for event in category['events']
        ])) == len([
            event['event_id']
                for category in d['presentation']['categories']
                    for event in category['events']
        ])
    }
]

def children_election_info_validator(value):
    if value == None:
        return
    else:
        try:
            check_contract(CHILDREN_ELECTION_INFO_CONTRACT, value)
        except CheckException as e:
            raise ValidationError(str(e.data))

def children_event_id_list_validator(value):
    if value == None:
        return
    else:
        try:
            check_contract(CHILDREN_EVENT_ID_LIST_CONTRACT, value)
        except CheckException as e:
            raise ValidationError(str(e.data))

class ScheduledEventSchema(Schema):
    '''
    Schema for elements in the ScheduledEventsSchema, which have a date and
    an associated task_id.
    '''
    event_at = marshmallow_fields.AwareDateTime(
        allow_none=True, load_default=None, dump_default=None
    )
    task_id = marshmallow_fields.String(
        allow_none=True, load_default=None, dump_default=None, dump_only=True
    )


class ScheduledEventsSchema(Schema):
    '''
    Schema for the AuthEvent.scheduled_events field
    '''
    start_voting = marshmallow_fields.Nested(
        ScheduledEventSchema,
        allow_none=True,
        load_default=None,
        dump_default=None
    )
    end_voting = marshmallow_fields.Nested(
        ScheduledEventSchema,
        allow_none=True,
        load_default=None,
        dump_default=None
    )


class OIDCPPublicInfoSchema(Schema):
    '''
    Schema for an OIDC Provider Public Info Configuration
    '''
    id = marshmallow_fields.String(
        required=True, allow_none=False
    )
    title = marshmallow_fields.String(
        required=True, allow_none=False
    )
    description = marshmallow_fields.String(
        required=True, allow_none=False
    )
    icon = marshmallow_fields.Url(
        required=True, allow_none=False, schemes=["https"]
    )
    authorization_endpoint = marshmallow_fields.Url(
        required=True, allow_none=False, schemes=["https"]
    )
    client_id = marshmallow_fields.String(
        required=True, allow_none=False
    )
    scope = marshmallow_fields.String(
        required=True, allow_none=False
    )
    issuer = marshmallow_fields.Url(
        required=True, allow_none=False, schemes=["https"]
    )
    token_endpoint = marshmallow_fields.Url(
        required=True, allow_none=False, schemes=["https"]
    )
    jwks_uri = marshmallow_fields.Url(
        required=True, allow_none=False, schemes=["https"]
    )
    logout_uri = marshmallow_fields.Url(
        required=True, allow_none=False, schemes=["https"]
    )


class OIDCPPrivateInfoSchema(Schema):
    '''
    Schema for an OIDC Provider Private Info Configuration
    '''
    client_secret = marshmallow_fields.String(
        required=True, allow_none=False
    )

class OIDCProviderSchema(Schema):
    '''
    Schema for an OIDC Provider Configuration
    '''
    public_info = marshmallow_fields.Nested(
        OIDCPPublicInfoSchema,
        allow_none=False,
        required=True
    )
    private_info = marshmallow_fields.Nested(
        OIDCPPrivateInfoSchema,
        allow_none=False,
        required=True
    )

    @decorators.validates_schema(pass_original=True)
    def validate_schema(self, data, original_data, **kwargs):
        if not original_data:
            raise ValidationError('The list must have at least one element.')


def get_schema_validator(klass):
    '''
    Given a Marshmallow Schema class, returns a Django field validator function
    '''
    def validator(data):
        try:
            klass().validate(data=data)
        except MarshMallowValidationError as error:
            # Convert the marshmallow validation error to a Django one,
            # because Django doesn't know how to handle marshmallow exceptions.
            raise ValidationError(error.messages)
    return validator


class AuthEvent(models.Model):
    '''
    An Auth Event is an object used for authentication and authorization. It's
    an abstract interface that anyone should be able to use, although the main
    use case is that each AuthEvent corresponds with an Election, in principle
    it could be used for any kind of authentication and authorization event.
    '''
    NOT_STARTED = "notstarted"
    STARTED = "started"
    STOPPED = "stopped"
    SUSPENDED = "suspended"
    RESUMED = "resumed"
    PENDING = "pending"
    SUCCESS = "success"
    TALLY_MODE_ACTIVE = 'active'
    TALLY_MODE_ALL = 'all'


    auth_method = models.CharField(max_length=255)
    census = models.CharField(max_length=5, choices=CENSUS, default="close")
    auth_method_config = JSONField()
    extra_fields = JSONField(blank=True, null=True)
    status = models.CharField(
        max_length=15,
        choices=AE_STATUSES,
        default=NOT_STARTED
    )

    # Contains information about the alternative authentication methods
    # supported in this Auth Event, if any. Example:
    # [
    #     {
    #         "id": "email",
    #         "auth_method_name": "email",
    #         "auth_method_config": <auth_method_config>,
    #         "extra_fields": <extra_fields>, 
    #         "public_name": "Email",
    #         "public_name_i18n": {"es": "Nombre"},
    #         "icon": "{null/name/url}"
    #     }
    # ]
    alternative_auth_methods = JSONField(blank=True, db_index=False, null=True)

    # the election scheduled events, like start, stop, allow_tally, tally.
    # Example:
    # {
    #     "start_voting": {
    #         "event_at": "2023-07-13T09:42:12.564355",
    #         "task_id": None
    #     },
    #     "end_voting": {
    #         "event_at": "2023-07-13T09:42:12.564355",
    #         "task_id": "7f560718-24d2-4a96-824d-da3787703a06"
    #     }
    # }
    scheduled_events = JSONField(
        blank=True,
        db_index=False,
        null=True,
        validators=[get_schema_validator(ScheduledEventsSchema)]
    )

    # the OIDC providers used in this election
    # Example:
    # [
    #     {
    #         "public_info": {
    #             "id": "google",
    #             "title": "Google",
    #             "description": "Authenticate with Google",
    #             "icon": "https://www.google.com/favicon.ico",
    #             "authorization_endpoint": "https://accounts.google.com/o/oauth2/v2/auth",
    #             "client_id": "<CLIENT_ID>.apps.googleusercontent.com",
    #             "issuer": "https://accounts.google.com",
    #             "token_endpoint": "https://oauth2.googleapis.com/token",
    #             "jwks_uri": "https://www.googleapis.com/oauth2/v3/certs",
    #             "logout_uri": "https://accounts.google.com/o/oauth2/v2/auth_logout"
    #         },
    #         "private_info": {
    #             "client_secret": "<CLIENT_SECRET>"
    #         }
    #     }
    # ]
    oidc_providers = JSONField(
        blank=True,
        db_index=False,
        null=True,
        validators=[get_schema_validator(OIDCProviderSchema(many=True))]
    )

    # used by iam_celery to know what tallies to launch, and to serialize
    # those launches one by one. set/get with (s|g)et_tally_status api calls
    tally_status = models.CharField(
        max_length=15, 
        choices=AE_TALLY_STATUSES,
        default=NOT_STARTED
    )

    # used by iam_celery to know what tallies mode should be used, and to
    # serialize those launches one by one. set/get with (s|g)et_tally_status api
    # calls
    tally_mode = models.CharField(
        max_length=15, 
        choices=AE_TALLY_MODES, 
        default=TALLY_MODE_ACTIVE
    )
    
    created = models.DateTimeField(auto_now_add=True)
    admin_fields = JSONField(blank=True, null=True)
    support_otl_enabled = models.BooleanField(default=False)
    inside_authenticate_otl_period = models.BooleanField(default=False)
    has_ballot_boxes = models.BooleanField(default=True)
    allow_public_census_query = models.BooleanField(default=True)

    # allows to hide default login lookup field during the authentication
    # step. For example, in email authentication it would not show the
    # email field.
    #
    # It only makes sense to use when another required_on_authentication
    # extra_field exists that can be used to find the user to authenticate.
    hide_default_login_lookup_field = models.BooleanField(default=False)

    # Contains the information related on how to show or act related to
    # the children elections. Example:
    # {
    #     "natural_order": [101,102,103],
    #     "presentation": {
    #         "categories": [
    #             {
    #                 "id": 1,
    #                 "title": "Executive Board",
    #                 "events": [
    #                     {
    #                         "event_id": 101,
    #                         "title": "Pre/Vice"
    #                     },
    #                     {
    #                         "event_id": 102,
    #                         "title": "Vocales"
    #                     }
    #                 ]
    #             }
    #         ]
    #     }
    # }
    children_election_info = JSONField(
        blank=True, 
        null=True, 
        validators=[children_election_info_validator])

    # allow for hierarchy of elections
    parent = models.ForeignKey(
        'self', 
        models.CASCADE, 
        related_name="children", 
        null=True
    )

    # 0 means any number of logins is allowed
    num_successful_logins_allowed = models.IntegerField(
        default=True,
        validators=[
            MinValueValidator(0)
        ]
    )
    based_in = models.IntegerField(null=True) # auth_event_id


    # 0 means any number of logins is allowed
    refresh_token_duration_secs = models.IntegerField(
        default=600,
        validators=[
            MinValueValidator(0)
        ]
    )

    # 0 means any number of logins is allowed
    access_token_duration_secs = models.IntegerField(
        default=120,
        validators=[
            MinValueValidator(0)
        ]
    )

    # will return true if allow_user_resend is defined and it's True,
    # false otherwise
    def check_allow_user_resend(self):
       return (
            self.auth_method in ['email-otp', 'sms-otp'] or
            (
                isinstance(self.auth_method_config, dict) and
                isinstance(self.auth_method_config.get('config', None), dict) and
                True == self.auth_method_config['config']\
                    .get('allow_user_resend', None)
            )
       )

    def get_public_config(self):
        from authmethods import METHODS
        base_config = {
            'allow_user_resend': self.check_allow_user_resend()
        }
        if not hasattr(METHODS[self.auth_method], "get_public_config"):
            return base_config
        public_config = {
            **base_config,
            **METHODS[self.auth_method].get_public_config(self),
        }
        return public_config

    def serialize(self, restrict=False):
        '''
        Used to serialize data when the user has priviledges to see all the data
        (for example, admins). This includes auth method config, stats, and
        access to private extra_fields.
        '''
        # auth codes sent by authmethod
        from authmethods.models import Code

        def none_list(e):
          if e is None:
              return []
          return e

        d = {
            'id': self.id,
            'auth_method': self.auth_method,
            'census': self.census,
            'users': self.len_census(),
            'has_ballot_boxes': self.has_ballot_boxes,
            'tally_status': self.tally_status,
            'allow_public_census_query': self.allow_public_census_query,
            'created': (self.created.isoformat()
                        if hasattr(self.created, 'isoformat')
                        else self.created),
            'based_in': self.based_in,
            'num_successful_logins_allowed': self.num_successful_logins_allowed,
            'hide_default_login_lookup_field': self.hide_default_login_lookup_field,
            'parent_id': self.parent.id if self.parent is not None else None,
            'children_election_info': self.children_election_info,
            'auth_method_config': {
               'config': self.get_public_config()
            },
            'scheduled_events': self.scheduled_events,
            'oidc_providers': [
                dict(public_info=provider["public_info"])
                for provider in none_list(self.oidc_providers)
            ],
            'support_otl_enabled': self.support_otl_enabled,
            'inside_authenticate_otl_period': self.inside_authenticate_otl_period
        }
        
        def restrict_extra_fields(fields):
            return [
                f for f in none_list(fields)
                    if not f.get('private', False)
            ]

        def restrict_alt_auth_methods():
            from authmethods import patch_auth_event
            if self.alternative_auth_methods is None:
                return self.alternative_auth_methods
            
            return [
                dict(
                    id=alt_auth_method["id"],
                    auth_method_name=alt_auth_method["auth_method_name"],
                    extra_fields=restrict_extra_fields(
                        alt_auth_method["extra_fields"]
                    ),
                    public_name=alt_auth_method["public_name"],
                    public_name_i18n=alt_auth_method["public_name_i18n"],
                    icon=alt_auth_method["icon"],
                    auth_method_config=dict(
                        config=patch_auth_event(
                            self.id, alt_auth_method
                        ).get_public_config()
                    )
                )
                for alt_auth_method in self.alternative_auth_methods
            ]

        if restrict:
            d.update({
                'extra_fields': restrict_extra_fields(self.extra_fields),
                'admin_fields': restrict_extra_fields(self.admin_fields),
                'alternative_auth_methods': restrict_alt_auth_methods()
            })

        else:
            d.update({
                'extra_fields': self.extra_fields,
                'alternative_auth_methods': self.alternative_auth_methods,
                'auth_method_config': self.auth_method_config,
                'auth_method_stats': {
                    self.auth_method: Code.objects.filter(auth_event_id=self.id).count()
                },
                'admin_fields': self.admin_fields,
                'total_votes': self.get_num_votes(),
                'children_tally_status': self.children_tally_status()
            })

        return d

    def serialize_restrict(self):
        '''
        Used to serialize public data that anyone should be able to see about an
        AuthEvent.
        '''
        return self.serialize(restrict=True)

    def get_census_query(self):
        '''
        returns a query with all the census of this event.
        '''
        sub_query = Q(object_id=self.id)
        if self.children_election_info:
            children_election_ids = self.children_election_info['natural_order']
            if self.parent is None:
                sub_query |= Q(
                    object_id__in=children_election_ids
                )
        elif self.parent_id:
            sub_query |= Q(
                    object_id=self.parent_id,
                    user__children_event_id_list__contains=self.id
                )

        # Note that we order so that paginated results are stable.
        return ACL.objects\
            .filter(
                Q(
                    object_type='AuthEvent',
                    perm='vote',
                    object_id__isnull=False
                ) & sub_query
            )\
            .order_by('user_id')\
            .distinct()

    def get_num_votes_query(self):
        '''
        Returns the number of votes in this election and in
        children elections (if any).
        '''
        if self.children_election_info:
            children_election_ids = self.children_election_info['natural_order']
        else:
            children_election_ids = []

        return SuccessfulLogin.objects\
            .filter(
                Q(auth_event_id=self.pk) |
                Q(auth_event__parent_id=self.pk) |
                Q(auth_event__parent_id__in=children_election_ids)
            )\
            .order_by('user_id', '-created')\
            .distinct('user_id')
    
    def get_votes_per_hour(self):
        '''
        Returns the number of votes per hour in this election and in
        children elections (if any).
        '''
        if self.children_election_info:
            parents2 = self.children_election_info['natural_order']
        else:
            parents2 = []

        q_base = SuccessfulLogin.objects\
            .filter(
                Q(auth_event_id=self.pk) |
                Q(auth_event__parent_id=self.pk) |
                Q(auth_event__parent_id__in=parents2)
            )
        subquery_distinct = q_base\
            .order_by('user_id', '-created')\
            .distinct('user_id')

        q = q_base\
            .annotate(hour=TruncHour('created'))\
            .values('hour')\
            .annotate(votes=Count('user_id'))\
            .order_by('hour')\
            .filter(id__in=subquery_distinct)
        
        return [
                dict(
                    hour=str(obj['hour']),
                    votes=obj['votes']
                )
                for obj in q
            ]


    def get_num_votes(self):
        '''
        Returns the number of votes in this election and in
        children elections (if any).
        '''
        return self.get_num_votes_query().count()
    
    def children_tally_status(self):
        '''
        Returns the tally status of children elections
        '''
        return list(
            AuthEvent.objects\
                .filter(
                    Q(parent_id=self.pk)
                )\
                .values('tally_status', 'id')
        )

    def get_owners(self):
        '''
        Returns the list of people that can edit this event
        '''
        return ACL.objects.filter(
            object_type='AuthEvent',
            perm='edit',
            object_id=self.id)

    def len_census(self):
        return self.get_census_query().count()

    def autofill_fields(self, from_user=None, to_user=None):
        if not from_user or not to_user:
            return

        extra_fields = self.extra_fields or []
        fields = [i for i in extra_fields if i.get("autofill", False)]
        for afield in fields:
            name = afield["name"]
            value = from_user.userdata.metadata.get(name, "NOT SET")
            to_user.userdata.metadata[name] = value
        to_user.userdata.save()

    def allow_set_status(self, status):
        '''
        Returns true if the new status is allowed
        '''
        if not settings.ENFORCE_STATE_CONTROLS:
            return True

        if (
            status == AuthEvent.STARTED and
            self.status != AuthEvent.NOT_STARTED
        ) or (
            status == AuthEvent.SUSPENDED and
            self.status != AuthEvent.STARTED and
            self.status != AuthEvent.RESUMED
        ) or (
            status == AuthEvent.RESUMED and
            self.status != AuthEvent.SUSPENDED
        ) or (
            status == AuthEvent.PENDING and
            self.status != AuthEvent.STOPPED
        ) or (
            status == AuthEvent.SUCCESS and
            self.status != AuthEvent.PENDING
        ) or (
            status == AuthEvent.STOPPED and
            self.status != AuthEvent.STARTED and
            self.status != AuthEvent.RESUMED and
            self.status != AuthEvent.SUSPENDED
        ):
            return False
        else:
            return True

    def __str__(self):
        return "%s - %s" % (self.id, self.census)


@receiver(pre_save, sender=AuthEvent)
def update_scheduled_events(sender, instance, **kwargs):
    '''
    Update the scheduled events in django celery
    '''
    old_instance = None
    try:
        old_instance = AuthEvent.objects.get(pk=instance.pk)
    except:
        # It's a new instance so it has no previous state
        pass

    # scheduled_events can be empty, but once a task_id has been assigned, it
    # cannot be removed unless it has been revoked in this very function. No
    # other part of the code changes an scheduled event task_id. This allows us
    # to reliably update and revoke tasks by looking them up using the task_id.
    default_events = dict(
        start_voting=None,
        end_voting=None,
    )

    alt_status = dict(
        start_voting='start',
        end_voting='stop',
    )

    events = (instance.scheduled_events
        if instance.scheduled_events != None
        else default_events
    )
    old_events = (old_instance.scheduled_events
        if old_instance != None and old_instance.scheduled_events != None
        else default_events
    )
    main_event = (instance.parent if instance.parent != None else instance)
    user = CurrentUserMiddleware.get_current_user()
    for event_name, event_data in events.items():
        old_event_data = old_events.get(event_name, None)
        old_event_date = (
            old_event_data['event_at']
            if old_event_data != None
            else None
        )
        old_task_id = (
            old_event_data.get('task_id')
            if old_event_data != None
            else None
        )
        event_date = (
            event_data['event_at']
            if event_data != None
            else None
        )
        task_id = (
            event_data.get('task_id')
            if event_data != None
            else None
        )

        # first ensure only this function changes task_ids
        if old_task_id != task_id and event_data != None:
            event_data['task_id'] = old_task_id

        # nothing changed so we should just continue
        if old_event_date == event_date:
            continue

        # date changed, so we need to cancel previous task if there was one
        if old_task_id != None:
            current_app.control.revoke(old_task_id)

            # change the task id to None since now we revoked it
            if event_data != None:
                event_data['task_id'] = None

            # log the action
            action = Action(
                executer=user,
                receiver=None,
                action_name=f'authevent:{event_name}:revoked',
                event=main_event,
                metadata=dict(
                    auth_event=instance.pk,
                    old_event_date=old_event_date,
                    old_task_id=old_task_id
                )
            )
            action.save()

        # we need to schedule the new task
        if event_date != None:
            eta = datetime.fromisoformat(event_date)
            if eta < timezone.now():
                print("not scheduling event in the past")
                continue
            from api.tasks import set_status_task
            task_id = event_data['task_id'] = set_status_task.apply_async(
                args=[
                    alt_status[event_name],
                    user.id,
                    main_event.id
                ],
                eta=eta,
                retry=False
            ).id
            # log the action, only if authevent is created
            if main_event.pk != None:
                action = Action(
                    executer=user,
                    receiver=None,
                    action_name=f'authevent:{event_name}:scheduled',
                    event=main_event,
                    metadata=dict(
                        auth_event=instance.pk,
                        new_event_date=event_date,
                        new_task_id=task_id
                    )
                )
                action.save()

STATUSES = (
    ('act', 'Active'),
    ('pen', 'Pending'),
    ('dis', 'Disabled'),
)

class UserData(models.Model):
    '''
    This is a class attached one to one to a user, that stores extra user
    information.  We store some user authentication and status information
    like telephone number (in case authentication works via telephone), and
    metadat, in this model.

    In iam each user is created in relation with a specific authevent.
    '''
    user = models.OneToOneField(User, models.CASCADE, related_name="userdata")
    event = models.ForeignKey(AuthEvent, models.CASCADE, related_name="userdata", null=True)
    tlf = models.CharField(max_length=20, blank=True, null=True)
    metadata = fields.JSONField(default=dict, blank=True, null=True)
    status = models.CharField(max_length=255, choices=STATUSES, default="act", db_index=True)
    draft_election = fields.JSONField(default=dict, blank=True, null=True, db_index=False)
    use_generated_auth_code = models.BooleanField(default=False)

    # Stablishes in which children elections can this user vote
    children_event_id_list = JSONField(
        blank=True, 
        null=True, 
        validators=[children_event_id_list_validator])

    def get_perms(self, obj, permission, object_id=0):
        q = Q(object_type=obj, perm=permission)
        q2 = Q(object_id=object_id)
        if not object_id:
            q2 |= Q(object_id='')

        return self.acls.filter(q & q2)

    def has_perms(self, obj, permission, object_id=0):
        return bool(self.get_perms(obj, permission, object_id).count())

    def serialize_draft(self):
        d = {}
        if self.draft_election:
            if type(self.draft_election) == str:
                draft_election = json.loads(self.draft_election)
                if type(draft_election) == str:
                    draft_election = json.loads(draft_election)
            else:
                draft_election = self.draft_election
            d.update(draft_election)
        return d


    def serialize(self):
        d = {
            'username': self.user.username,
            'active': self.user.is_active,
        }
        if self.user.email:
            d['email'] = self.user.email
        if self.tlf:
            d['tlf'] = self.tlf
        return d

    def serialize_metadata(self):
        d = {}
        if self.metadata:
            if type(self.metadata) == str:
                metadata = json.loads(self.metadata)
                if type(metadata) == str:
                    metadata = json.loads(metadata)
            else:
                metadata = self.metadata
            d.update(metadata)
        return d

    def serialize_children_voted_elections(self, auth_event):
        if auth_event.children_election_info:
            return list(set([
                successful_login.auth_event.pk
                for successful_login in self.successful_logins.filter(
                    Q(is_active=True) & 
                    (
                        Q(auth_event__parent_id=auth_event.pk) |
                        Q(auth_event__parent__parent_id=auth_event.pk)
                    )
                )
            ]))
        else:
            return list(set([
                successful_login.auth_event.pk
                for successful_login in self.successful_logins.filter(
                    is_active=True, 
                    auth_event_id=auth_event.pk
                )
            ]))

    def serialize_data(self):
        d = self.serialize()
        if not self.event.auth_method == 'user-and-password':
            del d['username']
        if self.metadata:
            if type(self.metadata) == str:
                metadata = json.loads(self.metadata)
                if type(metadata) == str:
                    metadata = json.loads(metadata)
            else:
                metadata = self.metadata
            metadata.update(d)
            d = metadata
        return d

    def __str__(self):
        return self.user.username

@receiver(post_save, sender=User)
def create_user_data(sender, instance, created, *args, **kwargs):
    ud, _ = UserData.objects.get_or_create(user=instance)
    ud.save()


# List of allowed actions used as only valid values for the Action model
# action_name column
ALLOWED_ACTIONS = (
    ('authevent:create', 'authevent:create'),
    ('authevent:callback', 'authevent:callback'),
    ('authevent:edit', 'authevent:edit'),
    ('authevent:start', 'authevent:start'),
    ('authevent:stop', 'authevent:stop'),
    ('user:activate', 'user:activate'),
    ('user:successful-login', 'user:successful-login'),
    ('user:send-auth', 'user:send-auth'),
    ('user:deactivate', 'user:deactivate'),
    ('user:register', 'user:register'),
    ('user:authenticate', 'user:authenticate'),
    ('user:added-to-census', 'user:added-to-census'),
    ('user:deleted-from-census', 'user:deleted-from-census'),
    ('user:resend-authcode', 'user:resend-authcode'),
    ('authevent:start_voting:scheduled', 'authevent:start_voting:scheduled'),
    ('authevent:start_voting:revoked', 'authevent:start_voting:revoked'),
    ('authevent:end_voting:scheduled', 'authevent:end_voting:scheduled'),
    ('authevent:end_voting:revoked', 'authevent:end_voting:revoked'),
)

class Action(models.Model):
    '''
    Registers (potentially) any action performed by an user for traceability
    and transparency.
    '''

    # user that executed the action
    executer = models.ForeignKey(User, models.CASCADE, related_name="executed_actions",
        db_index=True, null=True)

    # date at which the action was executed
    created = models.DateTimeField(default=timezone.now, db_index=True)

    # name of the action executed
    action_name = models.CharField(max_length=255, db_index=True,
        choices=ALLOWED_ACTIONS)

    # event related to the action
    event = models.ForeignKey(AuthEvent, models.CASCADE, related_name="related_actions",
        null=True, db_index=True)

    # user onto which the action was executed
    receiver = models.ForeignKey(User, models.CASCADE, related_name="received_actions",
        db_index=True, null=True)

    # any other relevant information, which varies depending on the action
    metadata = fields.JSONField(default=dict)

    def serialize(self):
        d = {
            'id': self.id,
            'executer_id': self.executer.id if self.executer is not None else None,
            'executer_username': self.executer.username  if self.executer is not None else None,
            'executer_email': self.executer.email  if self.executer is not None else None,
            'receiver_id': self.receiver.id if self.receiver else None,
            'receiver_username': (
                self.receiver.username if self.receiver else None
            ),
            'receiver_email': (
                self.receiver.email if self.receiver else None
            ),
            'action_name': self.action_name,
            'created': (
                self.created.isoformat()
                if hasattr(self.created, 'isoformat')
                else self.created
            ),
            'event_id': self.event.id if self.event else None,
            'metadata': self.metadata
        }
        return d

    def __str__(self):
        return "%s - %s - %s" % (self.receiver.username, self.action_name, self.created)

class ACL(models.Model):
    '''
    The permission model is based in Access Control Lists, and this data model
    stores these lists in the database. A permission specifies things like:
    "user <foo> has permission <permission> over object_id <1> of object_type <bar>".

    This allows for a very flexible permission system. The idea is that these
    permissions can be used outside iam through HMAC tokens that contain
    authenticated permission information.
    '''
    user = models.ForeignKey(UserData, models.CASCADE, related_name="acls")
    perm = models.CharField(max_length=255)
    object_type = models.CharField(max_length=255, blank=True, null=True)
    object_id = models.CharField(max_length=255, default=0)
    created = models.DateTimeField(default=timezone.now)

    def serialize(self):
        d = {
            'perm': self.perm,
            'object_type': self.object_type or '',
            'object_id': self.object_id or '',
            'created': self.created.isoformat() if hasattr(self.created, 'isoformat') else self.created
        }
        return d

    def get_hmac(self):
        msg = ':'.join((self.user.user.username, self.object_type, str(self.object_id), self.perm))
        khmac = genhmac(settings.SHARED_SECRET, msg)
        return khmac

    def __str__(self):
        return "%s - %s - %s - %s" % (self.user.user.username, self.perm,
                                      self.object_type, self.object_id)

class SuccessfulLogin(models.Model):
    '''
    Each successful login attempt is recorded with an object of this type, and
    usually triggered by a explicit call to /authevent/<ID>/successful_login
    '''
    user = models.ForeignKey(UserData, models.CASCADE, related_name="successful_logins")
    created = models.DateTimeField(default=timezone.now)

    # when counting the number of successful logins, only active ones count
    is_active = models.BooleanField(default=True)
    auth_event = models.ForeignKey(
        AuthEvent, 
        models.CASCADE, 
        related_name="successful_logins", 
        null=True,
        default=None)

    def __str__(self):
        return "%d: %s - %s" % (self.id, self.user.user.username, str(self.created),)

class BallotBox(models.Model):
    '''
    Registers the list of ballot boxes related to a ballot box auth_event
    '''
    auth_event = models.ForeignKey(AuthEvent, models.CASCADE, related_name="ballot_boxes")
    name = models.CharField(max_length=255, db_index=True)
    created = models.DateTimeField(default=timezone.now, db_index=True)

    def __str__(self):
        return "%d: %s - %d - %s" % (
            self.id,
            self.name,
            self.auth_event.id,
            str(self.created)
        )

    class Meta:
        unique_together = (
            ("auth_event", "name"),
        )

class TallySheet(models.Model):
    '''
    Each tally sheet related to a ballot box can be registered here
    '''
    # related ballot box
    ballot_box = models.ForeignKey(BallotBox, models.CASCADE, related_name="tally_sheets")

    # date at which the tally sheet was created
    created = models.DateTimeField(default=timezone.now, db_index=True)

    # person who registered this tally sheet
    creator = models.ForeignKey(User, models.CASCADE, related_name="created_tally_sheets",
        db_index=True, null=False)

    # json data of the tally sheet. for now it only supports simple plurality
    # elections. The format is like in this example:
    #
    # data = dict(
    #     num_votes=222,
    #     questions=[
    #         dict(
    #             title="Do you want Foo Bar to be president?",
    #             blank_votes=1,
    #             null_votes=1,
    #             tally_type="plurality-at-large",
    #             answers=[
    #               dict(text="Yes", num_votes=200),
    #               dict(text="No", num_votes=120)
    #             ]
    #         )
    #     ]
    # )
    data = JSONField()

    def __str__(self):
        return "%d: %s - %d - %s" % (
            self.id,
            self.ballot_box.name,
            self.ballot_box.auth_event.id,
            str(self.created)
        )
