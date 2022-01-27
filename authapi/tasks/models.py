# This file is part of authapi.
# Copyright (C) 2022 Sequent Tech Inc <legal@sequentech.io>

# authapi is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License.

# authapi  is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.

# You should have received a copy of the GNU Affero General Public License
# along with authapi.  If not, see <http://www.gnu.org/licenses/>.

from select import select
import sys
import time
import subprocess

from django.db import models
from django.conf import settings
from django.contrib.auth.models import User
from django.contrib.postgres import fields
from django.utils import timezone
from celery.utils.log import get_task_logger

logger = get_task_logger(__name__)

TASK_STATUSES = (
    ('created', 'created'),
    ('pending', 'pending'),
    ('running', 'running'),
    ('success', 'success'),
    ('cancelling', 'cancelling'),
    ('cancelled', 'cancelled'),
    ('error', 'error'),
    ('timedout', 'timedout')
)

class Task(models.Model):
    '''
    Model used to store information about asynchronous tasks being run in the
    background, launched via celery api/tasks.py:
    - 'tasks.self_testing'
    '''
    CREATED = 'created'
    PENDING = 'pending'
    RUNNING = 'running'
    SUCCESS = 'success'
    CANCELLING = 'cancelling'
    CANCELLED = 'cancelled'
    ERROR = 'error'
    TIMEDOUT = 'timedout'

    # user that executed the task
    executer = models.ForeignKey(
        User,
        models.CASCADE,
        related_name="executed_tasks",
        db_index=True,
        null=True
    )

    # status of the task
    status = models.CharField(
        max_length=255,
        db_index=True,
        choices=TASK_STATUSES
    )

    # Contains the information about the task:
    # {
    #       "created_date": <datetime>,
    #       "started_date": <datetime> | null,
    #       "finished_date": <datetime> | null,
    #       "process_id": <int> | null,
    #       "command": <string> | null,
    #       "command_return_code": <int> | null,
    #       "last_update": <datetime>
    # }
    metadata = fields.JSONField(default=dict, db_index=True)

    # Task name
    name = models.CharField(max_length=255, db_index=True)

    # Task input data
    input = fields.JSONField(default=dict)

    # Task output data
    output = fields.JSONField(default=dict)

    def _error_task(self, error_text, status=None):
        logger.error(
            f"Task({self.id}).run_command(): error_text={error_text}, "
            f"new_status={status}"
        )
        self.status = Task.ERROR if status is None else status
        self.output['error'] = error_text
        self.save()

    def run_command(
        self,
        command,
        timeout_secs=settings.TASK_DEFAULT_TIMEOUT_SECS
    ):
        logger.info(
            f"Task({self.id}).run_command(command={command})"
        )
        if self.status != Task.PENDING:
            return self._error_task(
                f"Tried to run a command with status='{self.status}' but "
                "it should be 'pending' instead"
            )

        self.status = Task.RUNNING
        self.metadata['command'] = command
        self.metadata['started_time'] = timezone.now().isoformat()
        self.metadata['last_update'] = self.metadata['started_time']
        self.save()

        current_time = time.perf_counter()
        start_time = current_time
        logger.debug(
            f"{current_time}: Task({self.id}).run_command(): "
            "calling subprocess.Poppen.."
        )
        try:
            process = subprocess.Popen(
                command,
                shell=False,
                encoding='utf-8',
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT
            )
        except Exception as error:
            logger.error(
                f"{current_time}: Task({self.id}).run_command(): "
                f"exception {error}"
            )
            self.metadata['last_update'] = timezone.now().isoformat()
            self.metadata['finished_date'] = self.metadata['last_update']
            self.metadata['command_return_code'] = None

            # self.save() will be performed by self._error_task()
            exc_info = sys.exc_info()[1]
            self._error_task(
                f"ERROR while running '{command}':\n{exc_info}"
            )
            return

        self.metadata['last_update'] = timezone.now().isoformat()
        self.metadata["process_id"] = process.pid
        self.metadata['command_return_code'] = None
        self.output["stdout"] = ""
        self.save()
        stdout = ""
        debounce_secs = settings.TASK_PROCESS_UPDATE_DEBOUNCE_SECS

        # Read stdout line by line
        while True:
            logger.debug(
                f"{current_time}: Task({self.id}).run_command(): "
                f"running select on stdout for pid={process.pid} with "
                f"timeout={debounce_secs}"
            )

            has_stdout, _, _ = select(
                [process.stdout],
                [],
                [],
                debounce_secs
            )
            current_time = time.perf_counter()
            if not has_stdout:
                logger.debug(
                    f"{current_time}: Task({self.id}).run_command(): "
                    "select timedout with no output"
                )
            else:
                logger.debug(
                    f"{current_time}: Task({self.id}).run_command(): "
                    "select indicated there is output in stdout"
                )
                stdout += process.stdout.readline()
                current_time = time.perf_counter()
                logger.debug(
                    f"{current_time}: Task({self.id}).run_command(): "
                    f"stdout='''{stdout}'''"
                )

            # refresh the model from the database before writing, because
            # status might have been updated
            self.refresh_from_db()
            self.metadata['last_update'] = timezone.now().isoformat()
            if stdout != "":
                self.output["stdout"] += stdout
            stdout = ""

            # if the task has finished, then save and break the loop
            if process.poll() is not None:
                self.save()
                break

            # if the status has been update to cancelling (meaning, the
            # task has been requested to be cancelled), then it's time to
            # cancel it. Note that we did before the self.refresh_from_db() so
            # that's why the model's status might have changed.
            if (
                self.status == Task.CANCELLING or
                current_time - start_time >= timeout_secs
            ):
                if self.status == Task.CANCELLING:
                    error = (
                        f"{current_time}: Task({self.id}).run_command(): "
                        "CANCELLING task -> KILLING process with "
                        f"pid={process.pid}"
                    )
                    self.status = Task.CANCELLED
                else:
                    error = (
                        f"{current_time}: Task({self.id}).run_command(): "
                        "task TIMEDOUT -> KILLING process with "
                        f"pid={process.pid}"
                    )
                    self.status = Task.TIMEDOUT
                logger.error(error)
                process.kill()
                self.metadata['last_update'] = timezone.now().isoformat()
                self.metadata['finished_date'] = self.metadata['last_update']
                self.output['error'] = error
                self.save()
                return
            else:
                self.save()

        # refresh the model from the database before writing
        self.refresh_from_db()
        self.metadata['last_update'] = timezone.now().isoformat()
        self.metadata['finished_date'] = self.metadata['last_update']
        self.output["stdout"] += stdout
        ret_code = process.poll()
        self.metadata['command_return_code'] = ret_code
        if ret_code == 0:
            self.status = Task.SUCCESS
            logger.debug(
                f"{current_time}: Task({self.id}).run_command(): "
                f"process with pid={process.pid} finished SUCCESSFULLY, "
                f"return_code={ret_code}, and last stdout='''{stdout}'''"
            )
        else:
            self.status = Task.ERROR
            error = (
                f"{current_time}: Task({self.id}).run_command(): "
                f"ERROR: process with pid={process.pid} finished with NON-ZERO "
                f"return-code: return_code={ret_code}, "
                f"and last stdout='''{stdout}'''"
            )

        self.save()

    def serialize(self):
        return dict(
            id=self.id,
            executer_username=self.executer.username,
            status=self.status,
            metadata=self.metadata,
            name=self.name,
            input=self.input,
            output=self.output
        )

    def __str__(self):
        return "%d: %s - %s - %s" % (
            self.id,
            self.name,
            self.status,
            self.user.username
        )
