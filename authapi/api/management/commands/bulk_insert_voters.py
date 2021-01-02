# This file is part of authapi.
# Copyright (C) 2021  Agora Voting SL <agora@agoravoting.com>

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
from django.contrib.auth.models import User
from django.contrib.auth.hashers import UNUSABLE_PASSWORD_PREFIX
from api.models import AuthEvent
import csv
import time
import tempfile, shutil, os

class Command(BaseCommand):
  '''
  Inserts in bulk a CSV list of voters in an election. It's made using COPY
  command and a temporal table to make it fast.
  '''
  # URL of sources of inspiration:
  #
  # How to do bulk inserts with Postgresql, a temporal table and COPY
  # https://www.trineo.com/blog/2018/08/using-copy-in-postgres-for-importing-large-csvs
  #
  # How to insert mixing SELECT and VALUES:
  # https://stackoverflow.com/a/26080
  #
  # How to insert multiple tables in a single SQL statement:
  # https://stackoverflow.com/a/20561627
  #
  # About WITH Queries (Common Table Expressions) in PostgreSQL:
  # https://www.postgresql.org/docs/10/queries-with.html

  help = 'Bulk insert voters in an election'

  event_id = None
  voters_csv = None
  columns = []
  connection = None

  def add_arguments(self, parser):
    parser.add_argument(
      'event-id',
      nargs=1,
      type=int
    )
    parser.add_argument(
      'voters-csv',
      nargs=1,
      type=str
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
  
  def init(self, event_id, voters_csv):
    '''
    Initializes the class, setting its class members and doing some initial
    minor verifications.
    '''
    self.event_id = int(event_id)
    self.voters_csv = voters_csv
    self.connection = connection.cursor()
    with open(voters_csv, 'r') as csv_file:
      csv_reader = csv.reader(csv_file)
      self.columns = [column.strip() for column in csv_reader.__next__()]
      assert(len(self.columns) > 0)
  
    # verify event_id exists, fails if it doesn't
    AuthEvent.objects.get(pk=self.event_id)

  def create_voters_csv_table(self):
    '''
    Create the temporal table to read the CSV. It will first remove any previous
    temporal table with the same name.
    '''
    drop_statement = "DROP TABLE IF EXISTS voters_csv_table;"
    
    create_statement = "CREATE TABLE voters_csv_table ("
    first = True
    for column in self.columns:
      if first:
        first = False
        create_statement += "\n  %s  VARCHAR" % column
      else:
        create_statement += ",\n  %s  VARCHAR" % column
    create_statement += "\n);" 

    self.exec_sql(drop_statement)
    self.exec_sql(create_statement)

  def load_voters_csv_table(self):
    '''
    Load Voters CSV table with a COPY statement
    '''
    with open(self.voters_csv, 'r') as csv_file:
      # ignore the first line, which contains the column headers
      csv_file.readline()
      self.exec_sql(
        sql="self.connection.copy_from(csv_file, 'voters_csv_table')",
        exec_lambda=lambda: 
          self.connection.copy_from(csv_file, 'voters_csv_table')
      )
  
  def load_voters_into_django_tables(self):
    '''
    With a single composite SQL statement, insert the voters into the django
    tables from the temporal voters_csv_table
    '''
    load_voters_statement = '''
    START TRANSACTION;

    SET CONSTRAINTS ALL DEFERRED;

    WITH csv_data(email) AS (
      SELECT email FROM voters_csv_table
    ),
    user_insert AS (
      INSERT INTO auth_user (
        password,
        is_superuser,
        username,
        first_name,
        last_name,
        email,
        is_staff,
        is_active,
        date_joined
      )
      SELECT
        concat('%(password_prefix)s', substr(md5(random()::text), 0, 25)) AS password,
        FALSE AS is_superuser,
        substr(md5(concat(random()::text, csv_data.email)), 0, 25) AS username,
        '' AS first_name,
        '' AS last_name,
        csv_data.email AS email,
        FALSE AS is_staff,
        TRUE AS is_active,
        NOW() AS date_joined
      FROM csv_data
      RETURNING username, id AS user_id
    ),
    userdata_insert AS (
      INSERT INTO api_userdata (
        metadata,
        status,
        event_id,
        user_id,
        tlf,
        children_event_id_list
      )
      SELECT
        '{}' AS metadata,
        'act' AS status,
        %(event_id)d AS event_id,
        user_insert.user_id AS user_id,
        NULL AS tlf,
        NULL AS children_event_id_list
      FROM user_insert
      RETURNING id AS userdata_id
    ),
    vote_perm AS (
      INSERT INTO api_acl (
        perm,
        user_id,
        object_id,
        object_type,
        created
      )
      SELECT
        'vote' AS perm,
        userdata_insert.userdata_id AS user_id,
        %(event_id)d AS object_id,
        'AuthEvent' AS object_type,
        NOW() AS created
      FROM userdata_insert
      RETURNING id AS perm_id
    )
    INSERT INTO api_acl (
      perm,
      user_id,
      object_id,
      object_type,
      created
    )
    SELECT
      'edit' AS perm,
      userdata_insert.userdata_id AS user_id,
      userdata_insert.userdata_id AS object_id,
      'UserData' AS object_type,
      NOW() AS created
    FROM userdata_insert;

    COMMIT TRANSACTION;
    ''' % dict(
      password_prefix=UNUSABLE_PASSWORD_PREFIX,
      event_id=self.event_id
    )
    self.exec_sql(load_voters_statement)
  
  def clean_up(self):
    '''
    Removes the temporal voters_csv_table and frees unused database space
    '''
    drop_statement = "DROP TABLE IF EXISTS voters_csv_table;"
    vacuum_statement = "VACUUM FULL ANALYZE VERBOSE;"

    self.exec_sql(drop_statement)
    self.exec_sql(vacuum_statement)

  def handle(self, *args, **options):
    '''
    Handles the whole command execution
    '''
    self.init(
      event_id = options['event-id'][0],
      voters_csv = options['voters-csv'][0]
    )

    try:
      self.create_voters_csv_table()
      self.load_voters_csv_table()
      self.load_voters_into_django_tables()
    finally:
      self.clean_up()

    '''with connection.cursor() as conn:
      u = User()
      for i in range(1,10000):
        u.set_password('egergergEGegY21')
        print(u.password)'''
