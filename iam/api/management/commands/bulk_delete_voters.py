# This file is part of iam.
# Copyright (C) 2021  Sequent Tech Inc <legal@sequentech.io>

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
from django.db import connection
import time


class Command(BaseCommand):
  '''
  Delete all the voters (manually cascading on related tables) in iam
  for a specific election (event-id)
  '''
  # NOTES:
  #
  # How to do something like DELETE JOIN in PostgreSQL with USING clause:
  # https://www.postgresqltutorial.com/postgresql-delete-join/
  
  help = 'delete all voters for a specific election'

  def add_arguments(self, parser):
    parser.add_argument(
      'event-id',
      nargs=1,
      type=int
    )
  def exec_sql(self, sql = "", params = [], exec_lambda = None):
    '''
    Executes an SQL statement
    '''
    timer = None
    
    if exec_lambda is not None:
      print("\nExecuting lambda SQL statement: %s" % sql)
      timer = time.perf_counter()
      ret = exec_lambda()
    else:
      print("\nExecuting SQL statement: %s, params = %r" % (sql, params))
      timer = time.perf_counter()
      ret =  self.connection.execute(sql, params)
    timer2 = time.perf_counter()
    print("... done in %.2f secs" % (timer2 - timer))
    return ret

  def handle(self, *args, **options):
    event_id = int(options['event-id'][0])
    self.connection = connection.cursor()
    delete_acls = '''
    START TRANSACTION;

    SET CONSTRAINTS ALL DEFERRED;

    WITH users_to_delete AS (
      SELECT
      M.id AS userdata_id,
      U.id AS user_id
      FROM api_userdata M
      INNER JOIN auth_user U
      ON U.id = M.user_id
      WHERE M.event_id=%(event_id)d
    ),
    delete_acls AS (
      DELETE FROM api_acl
      USING users_to_delete
      WHERE api_acl.user_id = users_to_delete.userdata_id
    ),
    delete_actions AS (
      DELETE FROM api_action
      USING users_to_delete
      WHERE
        api_action.event_id=%(event_id)d
        AND (
          api_action.executer_id = users_to_delete.user_id
          OR api_action.receiver_id = users_to_delete.user_id
        )
    ),
    delete_userdata AS (
      DELETE FROM api_userdata
      USING users_to_delete
      WHERE api_userdata.id = users_to_delete.userdata_id
    )
    DELETE FROM auth_user
    USING users_to_delete
    WHERE auth_user.id = users_to_delete.user_id;

    COMMIT TRANSACTION;
    ''' % dict(event_id=event_id)
    self.exec_sql(delete_acls)

    vacuum_statement = "VACUUM FULL ANALYZE;"
    self.exec_sql(vacuum_statement)
