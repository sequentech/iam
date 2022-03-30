# This file is part of iam.
# Copyright (C) 2014-2020  Sequent Tech Inc <legal@sequentech.io>

# iam is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License.

# iam  is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.

# You should have received a copy of the GNU Affero General Public License
# along with iam.  If not, see <http://www.gnu.org/licenses/>.

import string
from authmethods.utils import dni_constraint


def lugo(arg):
    ident = ''
    l = None

    if not arg:
        return ident, l

    if arg[0].upper() in string.ascii_uppercase:
        # is NIE
        ident = arg[0:-1]
        l = arg[-1]
    elif dni_constraint(arg):
        # is DNI
        ident = '0' + arg[0:-1]
        l = arg[-1]
    else:
        # passport?
        ident = arg

    return ident, l
