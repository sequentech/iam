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

from django.db.models import Q
from django.views.generic import View
from api.decorators import login_required
import logging

from tasks.models import Task
from utils import paginate, json_response, permission_required

LOGGER = logging.getLogger('authapi')


class TaskView(View):
    '''List the user Tasks'''

    def get(self, request, pk=None):
        data = dict(
            status='ok',
            tasks=[]
        )
        params = Q(
            executer=request.user
        )

        if pk is not None:
            params &= Q(pk=pk)
        
        query = Task\
            .objects\
            .filter(params)\
            .order_by('-id')

        tasks = paginate(
            request,
            query,
            serialize_method='serialize',
            elements_name='tasks'
        )
        data.update(tasks)
        return json_response(data)

task = login_required(TaskView.as_view())
