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

from django.conf import settings
from celery.utils.log import get_task_logger
from celery import shared_task

from tasks.models import Task

logger = get_task_logger(__name__)

@shared_task(name='tasks.self_test_task')
def self_test_task(task_id):
    '''
    Launches an end-to-end self-test.
    '''
    logger.info(f"tasks.self_test_task(task_id = {task_id})")
    task = Task.objects.get(pk=task_id)
    task.run_command(command=settings.TASK_SELF_TEST_COMMAND)