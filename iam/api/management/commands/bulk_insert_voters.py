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

from django.core.management.base import BaseCommand
from django.db import connection
from django.contrib.auth.models import User
from django.contrib.auth.hashers import (
  UNUSABLE_PASSWORD_PREFIX,
  PBKDF2PasswordHasher
)
from api.models import AuthEvent
import csv
import time

class Command(BaseCommand):
  '''
  Inserts in bulk a CSV list of voters in an election. It's made using COPY
  command and a temporal table to make it fast.

  CSV format is used, with ';' as separator. Data cannot be escaped with quotes,
  so the separator cannot appear in the data.

  It supports parent-children elections. An example CSV is:

  email;tlf;Número de colegiado;Nombre;children_event_id_list
  john@example.com;+34777444111;50010;DOE JOHN;[11222,11223]
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
  iterations = None
  voters_csv = None
  columns = []
  cursor = None

  def add_arguments(self, parser):
    parser.add_argument(
      'event-id',
      type=int
    )
    parser.add_argument(
      'voters-csv',
      type=str
    )
    parser.add_argument(
      '--iterations',
      type=int,
      default=PBKDF2PasswordHasher.iterations,
      help="Number of PBKDF2 to use for passwords, defaults to %d" % PBKDF2PasswordHasher.iterations
    )
  
  def exec_sql(self, sql = "", params = None, exec_lambda = None):
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
      ret =  self.cursor.execute(sql, params)
    timer2 = time.perf_counter()
    print("... done in %.2f secs" % (timer2 - timer))
    return ret
  
  def init(self, event_id, voters_csv, iterations):
    '''
    Initializes the class, setting its class members and doing some initial
    minor verifications.
    '''
    self.event_id = int(event_id)
    self.voters_csv = voters_csv
    self.iterations = int(iterations)
    self.cursor = connection.cursor()

    # verify positive event_id and number of iterations
    assert(self.event_id >= 0)
    assert(self.iterations > 0)

    with open(voters_csv, 'r') as csv_file:
      csv_reader = csv.reader(csv_file, delimiter=';')
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
        create_statement += "\n  \"%s\"  VARCHAR" % column
      else:
        create_statement += ",\n  \"%s\"  VARCHAR" % column
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
        sql="self.cursor.copy_from(csv_file, 'voters_csv_table', sep=';')",
        exec_lambda=lambda: 
          self.cursor.copy_from(csv_file, 'voters_csv_table', sep=';')
      )
  
  def load_password_function(self):
    '''
    Creates or updates the password function (PBKDF2)
    '''
    password_function = '''
    CREATE OR REPLACE FUNCTION PBKDF2 
      (salt bytea, pw text, count integer, desired_length integer, algorithm text)
      returns bytea
      immutable
      language plpgsql
    as $$
    declare 
      hash_length integer;
      block_count integer;
      output bytea;
      the_last bytea;
      xorsum bytea;
      i_as_int32 bytea;
      i integer;
      j integer;
      k integer;
    begin
      algorithm := lower(algorithm);
      case algorithm
      when 'md5' then
        hash_length := 16;
      when 'sha1' then
        hash_length = 20;
      when 'sha256' then
        hash_length = 32;
      when 'sha512' then
        hash_length = 64;
      else
        raise exception 'Unknown algorithm "%"', algorithm;
      end case;

      block_count := ceil(desired_length::real / hash_length::real);

      for i in 1 .. block_count loop    
        i_as_int32 := E'\\\\000\\\\000\\\\000'::bytea || chr(i)::bytea;
        i_as_int32 := substring(i_as_int32, length(i_as_int32) - 3);

        the_last := salt::bytea || i_as_int32;

        xorsum := HMAC(the_last, pw::bytea, algorithm);
        the_last := xorsum;

        for j in 2 .. count loop
          the_last := HMAC(the_last, pw::bytea, algorithm);

          --
          -- xor the two
          --
          for k in 1 .. length(xorsum) loop
            xorsum := set_byte(xorsum, k - 1, get_byte(xorsum, k - 1) # get_byte(the_last, k - 1));
          end loop;
        end loop;

        if output is null then
          output := xorsum;
        else
          output := output || xorsum;
        end if;
      end loop;

      return substring(output from 1 for desired_length);
    end $$;
    '''
    self.exec_sql(password_function)

  def get_loader_sql_options(self):
    sql_options = dict()

    if 'email' in self.columns:
      base_salt_field = 'email'
    elif 'tlf' in self.columns:
      base_salt_field = 'tlf'
    else:
      base_salt_field = self.columns[0]
    sql_options['base_salt_field'] = base_salt_field

    if 'password' in self.columns:
      # assign password encoded in django format with PBKDF2:
      #
      # <algorithm>$<iterations>$<salt>$<hash>

      self.load_password_function()

      sql_options['password_function'] = """
        concat(
          'pbkdf2_sha256$%(iterations)d$',
          substr(md5(csv_data."%(base_salt_field)s"), 0, 12),
          '$',
          encode(
            PBKDF2(
              substr(md5(csv_data."%(base_salt_field)s"), 0, 12)::bytea,
              csv_data.password,
              %(iterations)d,
              32,
              'sha256'
            ),
            'base64'
          )
        ) AS password
      """ % dict(
        iterations = self.iterations,
        base_salt_field = base_salt_field
      )
    else:
      # assign a random invalid password (in django format) if no password is supplied
      sql_options['password_function'] = """
        concat(
          '%(password_prefix)s', 
          substr(md5(random()::text), 0, 25)
        ) AS password
      """ % dict (password_prefix = UNUSABLE_PASSWORD_PREFIX)

    if 'tlf' in self.columns:
      sql_options['tlf'] = 'csv_data.tlf'
    else:
      sql_options['tlf'] = 'NULL'

    # metadata will be a collection of data from the CSV fields, just without
    # tlf or email fields
    if 'children_event_id_list' in self.columns:
      sql_options['metadata'] = """
      concat(
        '{"children_event_id_list": ',
        csv_data.children_event_id_list"""
    else:
      sql_options['metadata'] = """
      concat(
        '{"children_event_id_list": []'"""

    for column in self.columns:
      if column in ['tlf', 'email', 'password', 'children_event_id_list']:
        continue
      sql_options['metadata'] += """, 
      ', "%(column)s": "',
      csv_data."%(column)s",
      '"' """ % dict(column=column)
      
    sql_options['metadata'] += ", '}')::jsonb AS metadata"

    # Allow to set children_event_id_list
    if 'children_event_id_list'in self.columns:
      sql_options['children_event_id_list'] = 'csv_data.children_event_id_list'
    else:
      sql_options['children_event_id_list'] = 'NULL'

    if 'email' in self.columns:
      sql_options['email_field'] = 'csv_data.email'
    else:
      sql_options['email_field'] = "''"

    return sql_options
  
  def insert_codes_statement(self):
    if 'authmethods_code' not in self.columns:
      return ''

    return '''
      code_insert AS (
        INSERT INTO authmethods_code (
          code,
          user_id,
          auth_event_id,
          is_enabled,
          created
        )
        SELECT
          csv_data.authmethods_code AS code,
          userdata_insert.userdata_id AS user_id,
          %(event_id)d AS auth_event_id,
          true AS is_enabled,
          NOW() AS created
        FROM user_insert
        INNER JOIN csv_data ON csv_data.username = user_insert.username
        INNER JOIN userdata_insert ON userdata_insert.user_id = user_insert.user_id
        WHERE csv_data.authmethods_code IS NOT NULL
      ),
    ''' % dict(
      event_id=self.event_id
    )

  def load_voters_into_django_tables(self):
    '''
    With a single composite SQL statement, insert the voters into the django
    tables from the temporal voters_csv_table
    '''
    sql_options = self.get_loader_sql_options()
    code_sql_statement = self.insert_codes_statement()

    load_voters_statement = '''
    START TRANSACTION;

    SET CONSTRAINTS ALL DEFERRED;

    WITH csv_data(%(all_fields)s) AS (
      SELECT 
        %(all_fields)s,
        substr(md5(concat(random()::text, "%(base_salt_field)s")), 0, 25) AS username
      FROM voters_csv_table
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
        %(password_function)s,
        FALSE AS is_superuser,
        csv_data.username as username,
        '' AS first_name,
        '' AS last_name,
        %(email_field)s AS email,
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
        children_event_id_list,
        use_generated_auth_code
      )
      SELECT
        %(metadata)s,
        'act' AS status,
        %(event_id)d AS event_id,
        user_insert.user_id AS user_id,
        %(tlf)s AS tlf,
        %(children_event_id_list)s AS children_event_id_list,
        False AS use_generated_auth_code
      FROM user_insert
      LEFT JOIN csv_data ON csv_data.username = user_insert.username
      RETURNING id AS userdata_id, user_id
    ),
    %(code_sql_statement)s
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
      all_fields=", ".join(['"%s"' % column for column in self.columns]),
      event_id=self.event_id,
      password_function=sql_options['password_function'],
      base_salt_field=sql_options['base_salt_field'],
      metadata=sql_options['metadata'],
      children_event_id_list=sql_options['children_event_id_list'],
      tlf=sql_options['tlf'],
      email_field=sql_options['email_field'],
      code_sql_statement=code_sql_statement
    )
    self.exec_sql(load_voters_statement)
  
  def clean_up(self):
    '''
    Removes the temporal voters_csv_table and frees unused database space
    '''
    drop_statement = "DROP TABLE IF EXISTS voters_csv_table;"
    vacuum_statement = "VACUUM FULL ANALYZE;"

    self.exec_sql(drop_statement)
    self.exec_sql(vacuum_statement)

  def handle(self, *args, **options):
    '''
    Handles the whole command execution
    '''
    self.init(
      event_id = options['event-id'],
      voters_csv = options['voters-csv'],
      iterations = options['iterations']
    )

    try:
      self.create_voters_csv_table()
      self.load_voters_csv_table()
      self.load_voters_into_django_tables()
    finally:
      self.clean_up()
