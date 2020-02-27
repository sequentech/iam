# This file is part of authapi.
# Copyright (C) 2014-2020  Agora Voting SL <contact@nvotes.com>

# authapi is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License.

# authapi  is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.

# You should have received a copy of the GNU Affero General Public License
# along with authapi.  If not, see <http://www.gnu.org/licenses/>.

import os
from importlib import import_module
from django.apps import AppConfig


class AuthmethodsConfig(AppConfig):
    name = 'authmethods'

    def ready(self):
        files = os.listdir(os.path.dirname(__file__))
        for f in files:
            if f.startswith('m_'):
                import_module('authmethods.' + f.split('.')[0])

