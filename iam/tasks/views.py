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

from django.conf import settings
from django.db.models import Q
from django.shortcuts import get_object_or_404
from django.views.generic import View
from api.decorators import login_required
import logging

from tasks.models import Task
from utils import paginate, json_response
from tasks.tasks import self_test_task

LOGGER = logging.getLogger('iam')


class TaskView(View):
    '''
    List user's Tasks.
    '''

    def get(self, request, pk=None):
        # only admins can do this
        if request.user.userdata.event_id != settings.ADMIN_AUTH_ID:
            return json_response(dict(), status=403)

        # Either get a specific task if given its id (`pk`) or just the user's
        # tasks
        params = Q(
            executer=request.user
        )
        if pk is not None:
            params &= Q(pk=pk)
        query = Task\
            .objects\
            .filter(params)\
            .order_by('-id')

        # paginate results
        tasks = paginate(
            request,
            query,
            serialize_method='serialize',
            elements_name='tasks'
        )

        # Return the list of tasks
        data = dict(
            status='ok',
            tasks=[]
        )
        data.update(tasks)
        return json_response(data)

task = login_required(TaskView.as_view())

class TaskCancelView(View):
    '''
    Cancels an user task.
    '''

    def post(self, request, pk=None):
        # only admins can do this
        if request.user.userdata.event_id != settings.ADMIN_AUTH_ID:
            return json_response(dict(), status=403)

        # get the task. Can only cancel the user's tasks that are in a specific
        # set of states
        task = get_object_or_404(
            Task,
            pk=pk,
            executer=request.user,
            status__in=[
                Task.CREATED,
                Task.PENDING,
                Task.RUNNING,
            ]
        )

        # Mark the task for cancelling
        task.status = Task.CANCELLING
        task.save()

        # Return
        data = dict(
            status='ok',
            task=task.serialize()
        )
        return json_response(data)

task_cancel = login_required(TaskCancelView.as_view())

class TaskLaunchSelfTestView(View):
    '''
    Launches an end-to-end self-test with a celery task.
    '''
    def post(self, request):
        # only admins can do this
        if request.user.userdata.event_id != settings.ADMIN_AUTH_ID:
            return json_response(dict(), status=403)

        # can't have multiple self-tests running for the same user at once
        existing_count = Task\
            .objects\
            .filter(
                executer=request.user,
                status__in=[
                    Task.CREATED,
                    Task.PENDING,
                    Task.RUNNING,
                ]
            )\
            .count()
        if existing_count > 0:
            return json_response(
                dict(
                    error="Already running or pending self-tests for this user",
                    error_codename="PENDING"
                ),
                status=403
            )

        # Create and send the self_test_task to celery
        task = Task(
            executer=request.user,
            name="self_test_task",
            status=Task.PENDING
        )
        task.save()
        self_test_task.apply_async(
            args=[task.id]
        )

        # Return the task data
        data = dict(
            status='ok',
            task=task.serialize()
        )
        return json_response(data)

task_launch_self_test = login_required(TaskLaunchSelfTestView.as_view())
