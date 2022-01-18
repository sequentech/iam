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

import json
import sys
import time
import subprocess

from django.db import models
from django.conf import settings
from django.contrib.auth.models import User
from django.contrib.postgres import fields
from django.utils import timezone

TASK_STATUSES = (
    ('created', 'created'),
    ('pending', 'pending'),
    ('running', 'running'),
    ('success', 'success'),
    ('cancelling', 'cancelling'),
    ('cancelled', 'cancelled'),
    ('error', 'error'),
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
        self.status = Task.ERROR if status is None else status
        self.output['error'] = error_text
        self.save()

    def run_command(self, command):
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

        last_write_time = time.perf_counter()
        try:
            process = subprocess.Popen(
                command,
                shell=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT
            )
        except:
            self.metadata['last_update'] = timezone.now().isoformat()
            self.metadata['finished_date'] = self.metadata['last_update']
            self.metadata['command_return_code'] = None

            # self.save() will be performed by self._error_task()
            exc_info = sys.exc_info()[1]
            self._error_task(
                f"Error while running '{command}':\n{exc_info}"
            )
            return

        self.metadata['last_update'] = timezone.now().isoformat()
        self.metadata["process_id"] = process.pid
        self.metadata['command_return_code'] = None
        self.output["stdout"] = ""
        self.save()
        stdout = ""

        # Read stdout line by line
        while True:
            stdout += process.stdout.readline().decode('utf-8')

            # update the task model in the database in a debounced way to
            # prevent too many updates
            current_time = time.perf_counter()
            debounce_secs = settings.TASK_PROCESS_UPDATE_DEBOUNCE_SECS
            if current_time - last_write_time > debounce_secs:
                # refresh the model from the database before writing, because
                # status might have been updated
                self.refresh_from_db()
                self.metadata['last_update'] = timezone.now().isoformat()
                self.output["stdout"] += stdout
                stdout = ""
                last_write_time = current_time

                # if the status has been update to cancelling (meaning, the
                # task has been requested to be cancelled), then it's time to
                # cancel it.
                if self.status == Task.CANCELLING:
                    process.kill()
                    self.metadata['last_update'] = timezone.now().isoformat()
                    self.metadata['finished_date'] = self.metadata['last_update']
                    return self._error_task(
                        f"Tried to run a command with status='{self.status}' but "
                        "it should be 'pending' instead",
                        status=Task.CANCELLED
                    )
                else:
                    self.save()

            if process.poll() is not None:
                break

        # refresh the model from the database before writing
        self.refresh_from_db()
        self.status = Task.SUCCESS
        self.metadata['last_update'] = timezone.now().isoformat()
        self.metadata['finished_date'] = self.metadata['last_update']
        self.output["stdout"] += stdout
        self.metadata['command_return_code'] = process.poll()
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
