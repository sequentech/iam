# This file is part of iam.
# Copyright (C) 2022  Sequent Tech Inc <legal@sequentech.io>

# iam is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License.

# iam  is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.

# You should have received a copy of the GNU Affero General Public License
# along with iam.  If not, see <http://www.gnu.org/licenses/>.

from django.core.management.base import BaseCommand
from api.models import AuthEvent

class Command(BaseCommand):
    help = 'Enable/Disable showing a PDF after login for an election'

    def add_arguments(self, parser):
        parser.add_argument(
            'election-id',
            help='Election id',
            nargs=1,
            type=str)

        parser.add_argument(
            '--show-pdf',
            help=(
                'Enable showing the PDF'
            ),
            action="store_true",
            default=False
        )

    def handle(self, *args, **kwargs):
        election_id = kwargs["election-id"][0]
        show_pdf = kwargs["show_pdf"]

        auth_event = AuthEvent.objects.get(pk=election_id)
        current_value = auth_event.auth_method_config.get("show_pdf", False)
        print("Current show_pdf value for election: ", current_value)
        print("New show_pdf value for election: ", show_pdf)
        auth_event.auth_method_config["show_pdf"] = show_pdf
        auth_event.save()
