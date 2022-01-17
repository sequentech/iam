# This file is part of iam.
# Copyright (C) 2016  Sequent Tech Inc <legal@sequentech.io>

# iam is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License.

# iam  is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.

# You should have received a copy of the GNU Affero General Public License
# along with iam.  If not, see <http://www.gnu.org/licenses/>.

from django.core.management.base import BaseCommand, CommandError
from django.contrib.auth.models import User
from api.models import AuthEvent, ACL
from authmethods.utils import generate_username
import json

# The upsert_users Django manage command for Authapi updates the permissions for
# a list of users, if those users already exist, and inserts those users with 
# the given permissions in case they don't exist.
# This command requires the usersdata argument, which is the path to a text file
# with the following JSON format:
#
# [
#  {
#    "username": "census1",
#    "email": "census1@election.com",
#    "password": "bbbbbbbbbb",
#    "is_active": true,
#    "is_admin": false,
#    "election_permissions": [
#      { 
#        "election_id": 190031,
#        "permissions": [
#          "view",
#          "send-auth",
#          "view-stats",
#          "view-voters",
#          "view-census",
#          "census-add",
#          "census-activation"
#        ]
#      },
#      { 
#        "election_id": 190030,
#        "permissions": [],
#        "help": "allow login as an admin and allow to create elections"
#      }
#    ]
#   }
# ]

def insert_or_update(cls, kwargs):
    l = cls.objects.filter(**kwargs)
    if len(l) == 0:
        obj = ACL(**kwargs)
        obj.save()

class Command(BaseCommand):
    help = 'updates users data'

    def add_arguments(self, parser):
        parser.add_argument(
            'usersdata',
            help='Path to the JSON file with the users data.',
            nargs=1,
            type=str)
        
        parser.add_argument(
            '--event-id',
            help='Main event id to assign the voters to.',
            type=int,
            default=1
        )

        parser.add_argument(
            '--metadata-lookup',
            help=(
                'By default, voters are found looking up the username, but '
                'you can apply this to use some userdata.metadata field '
                'instead.'
            ),
            type=str,
            default=None
        )

        parser.add_argument(
            '--update-only',
            help=(
                'Only will apply user updates, never create a new user, '
                'failing if any user is not found.'
            ),
            action="store_true",
            default=False
        )

        parser.add_argument(
            '--create-only',
            help=(
                'Only will create previously inexistant users, failing if an '
                'user is found.'
            ),
            action="store_true",
            default=False
        )

        parser.add_argument(
            '--dry-run',
            help=(
                'If enabled, the script will apply no change, listing the '
                'users to be updated/created instead.'
            ),
            action="store_true",
            default=False
        )

    def handle(self, *args, **kwargs):
        event_id = kwargs["event_id"]
        lookup = kwargs["metadata_lookup"]
        dry_run = kwargs["dry_run"]
        update_only = kwargs["update_only"]
        create_only = kwargs["create_only"]
        users_data = json\
            .loads(
                open(kwargs['usersdata'][0], 'r').read()
            )

        # process each user

        auth_event = AuthEvent.objects.get(pk=event_id)
        for user_data in users_data:
            if lookup is None:
                users = User.objects.filter(
                    username=user_data['username'],
                    userdata__event_id=event_id
                )
                user_id = user_data['username']
            else:
                users = User.objects.filter(
                    userdata__metadata__contains={
                        lookup: user_data['metadata'][lookup]
                    },
                    userdata__event_id=event_id
                )
                user_id = user_data['metadata'][lookup]

            # user doesn't exist -> create it
            if len(users) == 0:
                if update_only:
                    print("Error: user with id %s does not exist" % user_id)
                    exit(1)

                if lookup and not 'username' in user_data:
                    user_data['username'] = generate_username(
                        user_data, 
                        auth_event
                )
                kwargs = dict(username=user_data['username'])
                if 'email' in user_data:
                    kwargs['email'] = user_data['email']

                if dry_run:
                    print("CREATE user %s (username=%s)" % (
                        user_id, user_data['username']
                    ))
                    continue
                else:
                    db_user = User.objects.create_user(kwargs)
            else:
                if create_only:
                    print("Error: user with id %s does not exist" % user_id)
                    exit(1)

                # user exists -> update it
                db_user = users[0]
                if dry_run:
                    print("UPDATE user %s (username=%s)" % (
                        user_id, db_user.username
                    ))

                if 'email' in user_data:
                    if dry_run:
                        print("--> SET email = " + user_data['email'])
                    db_user.email = user_data['email']
            
            db_user.is_active = user_data.get('is_active', False)
            db_user.is_admin = user_data.get('is_admin', False)
            db_user.is_staff = user_data.get('is_admin', False)

            # if password is set, update it
            if 'password' in user_data:
                if dry_run:
                    print("--> SET password = ****")
                db_user.set_password(user_data['password'])

            # in any of the previous cases, save to DB
            if not dry_run:
                db_user.save()

            db_user.userdata.event_id = event_id

            # if tlf is set, update it
            if 'tlf' in user_data:
                if dry_run:
                    print("--> SET tlf = " + user_data['tlf'])
                db_user.userdata.tlf = user_data['tlf']
            
            if 'metadata' in user_data:
                if dry_run:
                    print("--> SET metadata = %r" % user_data['metadata'])
                db_user.userdata.metadata = user_data['metadata']

            # if children_event_id_list is set, update it
            if 'children_event_id_list' in user_data.get('metadata', dict()):
                if dry_run:
                    print(
                        "--> SET children_event_id_list = %r" % 
                        user_data['metadata']['children_event_id_list']
                    )
                db_user.userdata.children_event_id_list = user_data['metadata']['children_event_id_list']

            if not dry_run:
                db_user.userdata.save()
            else:
                continue

            # make sure the user has permission to login as an admin
            if event_id == 1:
                insert_or_update(
                    ACL,
                    dict(
                        user=db_user.userdata,
                        perm='edit',
                        object_type='AuthEvent',
                        object_id=1
                    )
                )

            for el in user_data.get('election_permissions', []):
                # if permission list is empty, it means we have to ensure
                # that the user has no permission for that election
                perms = ACL.objects.filter(
                    user=db_user.userdata,
                    object_type='AuthEvent',
                    object_id=int(el['election_id'])
                )
                for perm in perms:
                    perm.delete()

                if len(el['permissions']) > 0:
                    # ensure each permission for this election
                    for perm in el['permissions']:
                        insert_or_update(
                            ACL,
                            dict(
                                user=db_user.userdata,
                                perm=perm,
                                object_type='AuthEvent',
                                object_id=int(el['election_id'])
                            )
                        )
