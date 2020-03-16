# This file is part of authapi.
# Copyright (C) 2020  Agora Voting SL <agora@agoravoting.com>

# authapi is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License.

# authapi  is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.

# You should have received a copy of the GNU Affero General Public License
# along with authapi.  If not, see <http://www.gnu.org/licenses/>.

from api.models import AuthEvent

from django.core.management.base import BaseCommand, CommandError
from prettytable import PrettyTable
import tempfile
import json
import subprocess

RST_STYLE = """
styles:
    subtitle:
        fontSize: 10
        alignment: TA_CENTER

    table:
        spaceBefore:6
        spaceAfter:0
        alignment: TA_CENTER
        commands: []
            [VALIGN, [ 0, 0 ], [ -1, -1 ], TOP ]
            [INNERGRID, [ 0, 0 ], [ -1, -1 ], 3, white ]
            [ROWBACKGROUNDS, [0, 0], [-1, -1], [white,#E0E0E0]]
            [BOX, [ 0, 0 ], [ -1, -1 ], 0.25, white ]

        borderColor: null

    table-heading:
        parent : heading
        textColor: #FFFFFF
        backColor : #D01D00
"""

# The send_report Django manage command for Authapi generates a PDF document and
# sends it to a specific given email address.
# 
# This command requires the config argument, which is the path to a text file
# with the following JSON format:
#
# {
#   "email": {
#     "subject": "Informe diario __DATETIME__",
#     "body": "Informe diario __DATETIME__",
#     "to": ["whatever@example.com"]
#   },
#   "title": "Elecciones 2020 a Órganos de Gobierno del CICCP",
#   "subtitle": "Número de votos electrónicos acumulado a día __DATETIME__",
#   "logo_path": "/tmp/logo.png",
#   "table_headers": [ "Votación", "Votos", "% censo", "# Electores" ]
#   "groups": [
#       {
#           "auth_event_ids": [24, 25, 26],
#           "title": "Junta de gobierno"
#       },
#       {
#           "auth_event_ids": [27, 28, 29],
#           "title": "Candidatos para Consejeros por Sector 1"
#       },
#       {
#           "auth_event_ids": [27, 28, 29],
#           "title": "Candidatos para Consejeros por Sector 2"
#       }
#   ]
# }

class Command(BaseCommand):
    help = 'sends an election PDF report'

    def add_arguments(self, parser):
        parser.add_argument(
            'config',
            nargs=1,
            type=str
        )

    def handle(self, *args, **options):
        config = json.loads(open(options['config'][0], 'r').read())

        rst_file = tempfile.NamedTemporaryFile(delete=False)
        rst_path = rst_file.name

        # write title
        rst_file.write(config["title"] + "\n")
        rst_file.write("=" * len(config["title"]) + "\n\n")

        # write subtitle
        rst_file.write(
            ".. class:: subtitle\n    \n    %s\n\n" % config['subtitle']
        )

        # table header
        table = PrettyTable(config['table_headers'])
        table.padding_width = 1
        for group in config['groups']:
            census = 0
            votes = 0
            for auth_event_id in group['auth_event_ids']:
                auth_event = AuthEvent.objects.get(pk=election_id)
                census += auth_event.get_census_query().count()
                votes += auth_event.get_num_votes()

            table.add_row([
                group['title'],
                "{:,}".format(votes),
                "{:,.2f}%".format(votes*100.0/census) if census > 0 else "-",
                "{:,}".format(census),
            ])
        
        rst_file.write(str(table))
        rst_file.close()
        print("generated rst file at %s" % rst_path)

        style_file = tempfile.NamedTemporaryFile(delete=False)
        style_path = style_file.name
        style_file.write(RST_STYLE)
        style_file.close()
        print("generated style file at %s" % style_path)


        pdf_file = tempfile.NamedTemporaryFile(delete=False)
        pdf_path = pdf_file.name

        command = [
            'rst2pdf',
            rst_file,
            '-s',
            style_path,
            '-o',
            pdf_path
        ]
        print("executing %s" % ' '.join(command))
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT
        )
        stdout, stderr = process.communicate()
        print(stdout)
