# This file is part of authapi.
# Copyright (C) 2020  Agora Voting SL <agora@agoravoting.com>

# authapi is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License.

# authapi  is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.

# You should have received a copy of the GNU Affero General Public License
# along with authapi.  If not, see <http://www.gnu.org/licenses/>.

from django.core.management.base import BaseCommand, CommandError
from django.db import connection

# Delete all the voters (manually cascading on related tables) in authapi
# for a specific election (event-id)
class Command(BaseCommand):
  help = 'delete all voters for a specific election'

  def add_arguments(self, parser):
    parser.add_argument(
      'event-id',
      nargs=1,
      type=int
    )

  def handle(self, *args, **options):
    event_id = options['event-id'][0]
    with connection.cursor() as conn:
      delete_acls = '''
      DELETE FROM api_acl A
      WHERE EXISTS (
      SELECT FROM api_userdata M
      INNER JOIN auth_user U
      ON U.id = M.user_id
      WHERE M.event_id=%s AND M.status = 'act' AND A.user_id = U.id
      )'''
      print('deleting acls for election %s..' % event_id)
      conn.execute(delete_acls, [event_id])
      print('deleted %d acls' % conn.rowcount)

      delete_actions = '''
      DELETE FROM api_action M
      WHERE EXISTS (
          SELECT FROM auth_user U
          WHERE (U.id = M.executer_id OR U.id = M.receiver_id) AND M.event_id=%s
      )'''
      print('deleting actions for election %s..' % event_id)
      conn.execute(delete_actions, [event_id])
      print('deleted %d actions' % conn.rowcount)

      delete_userdatas = '''
      DELETE FROM api_userdata M
      WHERE EXISTS (
          SELECT FROM auth_user U
          WHERE U.id = M.user_id AND M.event_id=%s
      )'''
      print('deleting userdatas for election %s..' % event_id)
      conn.execute(delete_userdatas, [event_id])
      print('deleted %d userdatas' % conn.rowcount)

      # Every user needs to have an user data. As we deleted the user data at this
      # stage, we lost the connection with the event_id (the election), so the way
      # to remove the users related to the election is to remove all users with no
      # corresponding userdata.
      delete_users = '''
      DELETE FROM auth_user U
      WHERE not exists (
          SELECT FROM api_userdata M
          WHERE U.id = M.user_id
      )'''
      print('deleting users for election %s..' % event_id)
      conn.execute(delete_users, [event_id])
      print('deleted %d users' % conn.rowcount)
