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
from django.db import models
from django.conf import settings
from django.contrib.auth.models import User
from django.contrib.postgres import fields

TASK_STATUSES = (
    ('created', 'created'),
    ('pending', 'pending'),
    ('running', 'running'),
    ('success', 'success'),
    ('error', 'error'),
)

class Task(models.Model):
    '''
    Model used to store information about asynchronous tasks being run in the
    background, launched via celery api/tasks.py:
    - 'tasks.self_testing'
    '''

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
    #       "last_update": <datetime>
    # }
    metadata = fields.JSONField(default=dict, db_index=True)

    # Task name
    name = models.CharField(max_length=255, db_index=True)

    # Task input data
    input = fields.JSONField(default=dict)

    # Task output data
    output = fields.JSONField(default=dict)

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
