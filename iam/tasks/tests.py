# This file is part of iam.
# Copyright (C) 2022 Sequent Tech Inc <legal@sequentech.io>

# iam is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License.

# iam  is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.

# You should have received a copy of the GNU Affero General Public License
# along with iam.  If not, see <http://www.gnu.org/licenses/>.

import os
import tempfile
from django.utils import timezone
from datetime import datetime, timedelta
from django.conf import settings
from django.contrib.auth.models import User
from django.test import TestCase
from django.test.utils import override_settings

from api import test_data
from api.models import ACL
from authmethods.models import Code
from api.tests import JClient, flush_db_load_fixture, parse_json_response
from tasks.models import Task
from utils import reproducible_json_dumps

class TestTasks(TestCase):
    '''
    Unit tests for tasks.views
    '''
    def setUpTestData():
        flush_db_load_fixture()

    def setUp(self):
        admin_user = User(
            username='test_admin',
            email=test_data.auth_email_default['email']
        )
        admin_user.save()
        admin_user.userdata.event_id=settings.ADMIN_AUTH_ID
        admin_user.userdata.save()
        self.admin_user = admin_user

        admin_user_2 = User(
            username='test_admin2',
            email=test_data.auth_email_default1['email']
        )
        admin_user_2.save()
        self.admin_user_2 = admin_user_2

        acl = ACL(
            user=admin_user.userdata,
            object_type='AuthEvent',
            perm='edit',
            object_id=settings.ADMIN_AUTH_ID
        )
        acl.save()

        code = Code(
            user=admin_user.userdata,
            code=test_data.auth_email_default['code'],
            auth_event_id=settings.ADMIN_AUTH_ID
        )
        code.save()

        self.empty_response = {
            'status': 'ok',
            'tasks': [], 
            'page': 1, 
            'total_count': 0, 
            'page_range': [1], 
            'start_index': 0,
            'end_index': 0, 
            'has_next': False, 
            'has_previous': False
        }

    def check_timing(self, data, key, timeout_secs):
        '''
        Checks that a given datetime is less than {timeout_secs} seconds old
        '''
        self.assertTrue(
            (
                timezone.now() -
                datetime.fromisoformat(data[key])
            ) < timedelta(seconds=timeout_secs)
        )

    def create_temp_executable(self, content):
        '''
        Create a temporary executable script, returning the file
        '''
        file = tempfile.NamedTemporaryFile(delete=False)
        file.write(content.encode('utf-8'))
        os.chmod(file.name, 0o700)
        return file.name

    def test_list_requires_auth(self):
        '''
        Check that listing tasks requires the user to be authenticated
        '''
        client = JClient()
        response = client.get('/api/tasks/', {})
        self.assertEqual(response.status_code, 403)

    def test_list_requires_admin_auth(self):
        '''
        Check that listing tasks works when user event_id is
        settings.ADMIN_AUTH_ID but not otherwise
        '''
        client = JClient()
        client.authenticate(
            settings.ADMIN_AUTH_ID,
            test_data.auth_email_default
        )
        response = client.get('/api/tasks/', {})
        self.assertEqual(response.status_code, 200)

        self.admin_user.userdata.event_id = None
        self.admin_user.userdata.save()

        response = client.get('/api/tasks/', {})
        self.assertEqual(response.status_code, 403)

    def test_list_empty(self):
        '''
        Check that an empty list of tasks works as expected
        '''
        client = JClient()
        client.authenticate(
            settings.ADMIN_AUTH_ID,
            test_data.auth_email_default
        )
        response = client.get('/api/tasks/', {})
        self.assertEqual(response.status_code, 200)
        response_data = parse_json_response(response)
        self.assertEqual(
            reproducible_json_dumps(response_data),
            reproducible_json_dumps(self.empty_response)
        )

    def test_list_empty2(self):
        '''
        Check that tasks for other users do not list in current user
        '''
        # create a task for self.admin_user_2, should not appear listed for
        # self.admin_user
        task = Task(
            executer=self.admin_user_2,
            status=Task.CREATED
        )
        task.save()

        client = JClient()
        client.authenticate(
            settings.ADMIN_AUTH_ID,
            test_data.auth_email_default
        )
        response = client.get('/api/tasks/', {})
        self.assertEqual(response.status_code, 200)
        response_data = parse_json_response(response)
        self.assertEqual(
            reproducible_json_dumps(response_data),
            reproducible_json_dumps(self.empty_response)
        )

    def test_list_one(self):
        '''
        Check that a list with one task from current user works as expected
        '''
        task = Task(
            executer=self.admin_user,
            status=Task.CREATED
        )
        task.save()

        client = JClient()
        client.authenticate(
            settings.ADMIN_AUTH_ID,
            test_data.auth_email_default
        )
        response = client.get('/api/tasks/', {})
        self.assertEqual(response.status_code, 200)
        response_data = parse_json_response(response)
        expected_response = {
            'status': 'ok',
            'tasks': [
                {
                    'id': task.id,
                    'executer_username': 'test_admin',
                    'status': 'created', 
                    'metadata': {}, 
                    'name': '', 
                    'input': {},
                    'output': {}
                }
            ], 
            'page': 1, 
            'total_count': 1, 
            'page_range': [1], 
            'start_index': 1,
            'end_index': 1, 
            'has_next': False, 
            'has_previous': False
        }
        self.assertEqual(
            reproducible_json_dumps(response_data),
            reproducible_json_dumps(expected_response)
        )

    def test_cancel_one(self):
        '''
        Check that cancelling a task works as expected
        '''
        task = Task(
            executer=self.admin_user,
            status=Task.RUNNING
        )
        task.save()

        client = JClient()
        client.authenticate(
            settings.ADMIN_AUTH_ID,
            test_data.auth_email_default
        )
        # cancelling works
        response = client.post(f'/api/tasks/{task.id}/cancel/', {})
        self.assertEqual(response.status_code, 200)

        task.refresh_from_db()
        # it's been cancelled
        self.assertEqual(task.status, Task.CANCELLING)

        # cannot be recancelled
        response = client.post(f'/api/tasks/{task.id}/cancel/', {})
        self.assertEqual(response.status_code, 404)

    def test_cancel_requires_auth(self):
        '''
        Check that cancel perms work as expected
        '''
        task = Task(
            executer=self.admin_user_2,
            status=Task.RUNNING
        )
        task.save()

        # unauthenticated cancelling is prohibited
        client = JClient()
        response = client.post(f'/api/tasks/{task.id}/cancel/', {})
        self.assertEqual(response.status_code, 403)

        # authenticate as self.admin_user
        client = JClient()
        client.authenticate(
            settings.ADMIN_AUTH_ID,
            test_data.auth_email_default
        )

        # cancelling a task for another user (self.admin_user_2) is not allowed
        client = JClient()
        response = client.post(f'/api/tasks/{task.id}/cancel/', {})
        self.assertEqual(response.status_code, 403)

    def test_cancel_requires_admin_auth(self):
        '''
        Check that cancelling tasks works when user event_id is
        settings.ADMIN_AUTH_ID but not otherwise
        '''
        task = Task(
            executer=self.admin_user,
            status=Task.RUNNING
        )
        task.save()

        client = JClient()
        client.authenticate(
            settings.ADMIN_AUTH_ID,
            test_data.auth_email_default
        )

        self.admin_user.userdata.event_id = None
        self.admin_user.userdata.save()

        response = client.post(f'/api/tasks/{task.id}/cancel/', {})
        self.assertEqual(response.status_code, 403)

        self.admin_user.userdata.event_id = settings.ADMIN_AUTH_ID
        self.admin_user.userdata.save()

        response = client.post(f'/api/tasks/{task.id}/cancel/', {})
        self.assertEqual(response.status_code, 200)

    def test_task_run_errored_command(self):
        task = Task(
            executer=self.admin_user,
            status=Task.PENDING
        )
        task.save()
        task.run_command('wrong command')
        task.refresh_from_db()
        self.assertEqual(task.status, Task.ERROR)

        self.assertDictEqual(
            task.output,
            dict(
                error=(
                    "ERROR while running 'wrong command':\n"
                    "[Errno 2] No such file or directory: 'wrong command'"
                )
            )
        )
        self.assertEqual(
            task.metadata['command'],
            'wrong command'
        )
        # datetimes should be present and less than 1 second ago
        self.check_timing(task.metadata, 'last_update', 1)
        self.check_timing(task.metadata, 'started_time', 1)
        self.check_timing(task.metadata, 'finished_date', 1)

        # As the command failed to launch, command_return_code shouldn't be set
        self.assertEqual(task.metadata['command_return_code'], None)

    def test_task_run_fast_command(self):
        task = Task(
            executer=self.admin_user,
            status=Task.PENDING
        )
        task.save()
        runfile_path = self.create_temp_executable(
            "#!/bin/bash\n"
            "echo 'hello world!'\n"
        )
        task.run_command(runfile_path)
        task.refresh_from_db()
        self.assertEqual(task.status, Task.SUCCESS)
        self.assertDictEqual(
            task.output,
            dict(stdout="hello world!\n")
        )
        self.assertEqual(
            task.metadata['command'],
            runfile_path
        )
        os.unlink(runfile_path)
        # datetimes should be present and less than 2 seconds ago (i.e. fast)
        self.check_timing(task.metadata, 'last_update', 2)
        self.check_timing(task.metadata, 'started_time', 2)
        self.check_timing(task.metadata, 'finished_date', 2)

        # As the command failed to launch, command_return_code should be 0
        self.assertEqual(task.metadata['command_return_code'], 0)

    def test_task_run_slow_command(self):
        task = Task(
            executer=self.admin_user,
            status=Task.PENDING
        )
        task.save()
        runfile_path = self.create_temp_executable(
            '#!/bin/bash\n'
            'for i in $(seq 1 5); do\n'
            '    echo "iteration" $i\n'
            '    sleep 1\n'
            'done\n'
        )
        task.run_command(runfile_path)
        task.refresh_from_db()
        self.assertEqual(task.status, Task.SUCCESS)
        self.assertDictEqual(
            task.output,
            dict(
                stdout=(
                    "iteration 1\n"
                    "iteration 2\n"
                    "iteration 3\n"
                    "iteration 4\n"
                    "iteration 5\n"
                )
            )
        )
        self.assertEqual(
            task.metadata['command'],
            runfile_path
        )
        os.unlink(runfile_path)
        # datetimes should be present and less than 6 seconds ago (i.e. slow but
        # not so slow).
        self.check_timing(task.metadata, 'last_update', 6)
        self.check_timing(task.metadata, 'started_time', 6)
        self.check_timing(task.metadata, 'finished_date', 6)

        # As the command failed to launch, command_return_code should be 0
        self.assertEqual(task.metadata['command_return_code'], 0)

    def test_task_run_return_code(self):
        task = Task(
            executer=self.admin_user,
            status=Task.PENDING
        )
        task.save()
        runfile_path = self.create_temp_executable(
            "#!/bin/bash\n"
            "exit 1\n"
        )
        task.run_command(runfile_path)
        task.refresh_from_db()
        self.assertEqual(task.status, Task.ERROR)
        # As the command failed to launch, command_return_code should be 1
        self.assertEqual(task.metadata['command_return_code'], 1)

    def test_task_run_timeout_command(self):
        '''
        Checks that task timeout means that a task that takes longer to execute
        that the given timeout will be killed and marked as timedout.
        '''
        task = Task(
            executer=self.admin_user,
            status=Task.PENDING
        )
        task.save()
        task.run_command(['sleep', '5'], timeout_secs=2)
        task.refresh_from_db()
        self.assertEqual(task.status, Task.TIMEDOUT)
        # datetimes should be present and less than 4 seconds ago
        self.check_timing(task.metadata, 'last_update', 4)
        self.check_timing(task.metadata, 'started_time', 4)
        self.check_timing(task.metadata, 'finished_date', 4)

        # As the command failed to launch, command_return_code should be unset
        self.assertEqual(task.metadata['command_return_code'], None)

    def test_task_run_timeout_command2(self):
        '''
        Checks that task timeout means that a task that takes less time to
        execute that the given timeout will be killed and marked as successfully
        executed.
        '''
        task = Task(
            executer=self.admin_user,
            status=Task.PENDING
        )
        task.save()
        task.run_command(['sleep', '1'], timeout_secs=2)
        task.refresh_from_db()
        self.assertEqual(task.status, Task.SUCCESS)
        # datetimes should be present and less than 2 seconds ago
        self.check_timing(task.metadata, 'last_update', 2)
        self.check_timing(task.metadata, 'started_time', 2)
        self.check_timing(task.metadata, 'finished_date', 2)

        # As the command failed to launch, command_return_code should be 0
        self.assertEqual(task.metadata['command_return_code'], 0)

    @override_settings(CELERY_ALWAYS_EAGER=True)
    def test_task_launch_self_testing(self):
        '''
        Self testing API call should run settings.TASK_SELF_TEST_COMMAND
        '''
        # authenticate as self.admin_user
        client = JClient()
        client.authenticate(
            settings.ADMIN_AUTH_ID,
            test_data.auth_email_default
        )

        # execute the task with the TASK_SELF_TEST_COMMAND being a simple "echo
        # hello", because testing the TASK_SELF_TEST_COMMAND is not the
        # objective of this test.
        with self.settings(
            TASK_SELF_TEST_COMMAND=["echo", "hello"]
        ):
            # launch the self-test
            response = client.post(f'/api/tasks/launch-self-test/', {})
            self.assertEqual(response.status_code, 200)

            # obtain the task
            response_data = parse_json_response(response)
            task_id = response_data['task']['id']
            task = Task.objects.get(pk=task_id)

            # check that the task was completed as expected
            self.assertEqual(task.status, Task.SUCCESS)
            self.assertEqual(task.metadata['command'], ['echo', 'hello'])
            self.assertEqual(task.metadata['command_return_code'], 0)
            self.assertEqual(task.output["stdout"], 'hello\n')
            self.assertTrue('error' not in task.output)

    @override_settings(CELERY_ALWAYS_EAGER=True)
    def test_task_launch_self_testing_requires_auth(self):
        '''
        Self testing API call should require an authenticated user
        '''
        # execute the task with the TASK_SELF_TEST_COMMAND being a simple "echo
        # hello", because testing the TASK_SELF_TEST_COMMAND is not the
        # objective of this test.
        with self.settings(
            TASK_SELF_TEST_COMMAND=["echo", "hello"]
        ):
            # launch the self-test
            client = JClient()
            response = client.post(f'/api/tasks/launch-self-test/', {})
            self.assertEqual(response.status_code, 403)

    @override_settings(CELERY_ALWAYS_EAGER=True)
    def test_task_launch_self_testing_requires_admin_auth(self):
        '''
        Self testing API call should require an authenticated admin user
        '''
        # authenticate as self.admin_user
        client = JClient()
        client.authenticate(
            settings.ADMIN_AUTH_ID,
            test_data.auth_email_default
        )

        # make this user not part of the admins
        self.admin_user.userdata.event_id = None
        self.admin_user.userdata.save()

        # execute the task with the TASK_SELF_TEST_COMMAND being a simple "echo
        # hello", because testing the TASK_SELF_TEST_COMMAND is not the
        # objective of this test.
        with self.settings(
            TASK_SELF_TEST_COMMAND=["echo", "hello"]
        ):
            # launch the self-test
            response = client.post(f'/api/tasks/launch-self-test/', {})
            self.assertEqual(response.status_code, 403)
