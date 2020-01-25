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
from django.db import models
from django.conf import settings


class Captcha(models.Model):
    code = models.CharField(max_length=10)
    path = models.CharField(max_length=100)
    challenge = models.CharField(max_length=4)
    used = models.BooleanField(default=False)
    created = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.code

    def delete(self):
        image_path = settings.STATIC_ROOT + '/captcha/'
        path = str(os.path.join(image_path, '%s.png' % self.code))
        os.unlink(path)
        super(Captcha, self).delete()
