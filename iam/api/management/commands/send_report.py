# This file is part of iam.
# Copyright (C) 2020  Sequent Tech Inc <legal@sequentech.io>

# iam is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License.

# iam  is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.

# You should have received a copy of the GNU Affero General Public License
# along with iam.  If not, see <http://www.gnu.org/licenses/>.

# Install rst2pdf for python3 support with:
# pip install git+https://github.com/rst2pdf/rst2pdf.git --ignore-requires-python

from api.models import AuthEvent

from django.utils import timezone
from django.db.models import Count
from django.core.mail import send_mail, EmailMessage
from django.core.management.base import BaseCommand, CommandError
import tempfile
import json
import subprocess
import datetime

from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, 
    Paragraph, 
    Spacer, 
    Table, 
    TableStyle, 
    Image
)
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.enums import TA_RIGHT, TA_LEFT, TA_CENTER
from reportlab.pdfgen import canvas
from reportlab.lib.units import mm

def write(file, string):
    file.write(string.encode('utf-8'))

def replace_date(text, date):
    _datetime = date.strftime("%Y-%m-%d, %H:%M")
    _date = date.strftime("%Y-%m-%d")
    text2 = text.replace("__DATE__", _date)
    text3 = text2.replace("__DATETIME__", _date)
    return text3

def gen_text(
    text, 
    size=None, 
    bold=False, 
    align=None, 
    color='black', 
    fontName=None
):
    if not isinstance(text, str):
        text = text.__str__()
    p = ParagraphStyle('test')
    if fontName:
        p.fontName = fontName
    if size:
        p.fontSize = size
        p.leading = size * 1.2
    if bold:
        text = '<b>%s</b>' % text
    p.textColor = color
    if align:
        p.alignment = align
    return Paragraph(text, p)

# The send_report Django manage command for Authapi generates a PDF document and
# sends it to a specific given email address.
# 
# This command requires the config argument, which is the path to a text file
# with the following JSON format:
#
# {
#   "email": {
#     "subject": "Informe diario __DATE__",
#     "body": "Informe diario __DATETIME__",
#     "to": ["whatever@example.com"]
#   },
#   "title": "Elecciones 2020 a Órganos de Gobierno del CICCP",
#   "subtitle": "Número de votos electrónicos acumulado a día __DATETIME__",
#   "logo_path": "/tmp/logo.png",
#   
#   # this is optional, by default it will be 488 x 130
#   "logo_size": { "width": 488, "height": 130 },

#   "table_headers": [ "Votación", "Medida", "Valor", "% censo", "# Electores" ],
#   "default_measurement_name": "Votos",
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
#       },
#       {
#           "auth_event_ids": [27, 28, 29],
#           "title": "Candidatos para Consejeros por Sector 2 - young",
#           "extra_filters": {"user__metadata__age__lt": 18}
#       },
#       {
#           "auth_event_ids": [27, 28, 29],
#           "title": "Candidatos para Consejeros por Sector 2 - adult",
#           "extra_filters": {"user__metadata__age__gte": 18}
#       },
#       {
#           "auth_event_ids": [27, 28, 29],
#           "title": "Candidatos para Consejeros por Sector 2 - adult - registrados",
#           "extra_filters": {"user__metadata__age__gte": 18}
#           "measurement_name": "Registrados",
#           "measurement_query_base": "active"
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
        parser.add_argument(
            'path',
            nargs=1,
            type=str
        )

    def handle(self, *args, **options):
        config = json.loads(open(options['config'][0], 'r').read())

        pdf_path = options['path'][0]

        now = timezone.now()
        styleSheet = getSampleStyleSheet()
        doc = SimpleDocTemplate(
            pdf_path, 
            rightMargin=50,
            leftMargin=50, 
            topMargin=35,
            bottomMargin=80
        )
        elements = []

        # header image
        default_height = 130
        default_width = 488

        header_image = Image(
            config['logo_path'],
            height=config.get(
                'logo_size', 
                dict(height=default_height)
            )['height'],
            width=config.get(
                'logo_size',
                dict(width=default_width)
            )['width']
        )
        header_image.hAlign = 'CENTER'
        elements.append(header_image)

        # title
        elements.append(Spacer(0, 15))
        title = replace_date(config["title"], now)
        elements.append(
            gen_text(
                title, 
                size=20, 
                bold=True, 
                align=TA_CENTER
            )
        )

        # subtitle
        subtitle = replace_date(config['subtitle'], now)
        elements.append(Spacer(0, 15))
        elements.append(
            gen_text(
                subtitle, 
                size=12, 
                bold=False, 
                align=TA_CENTER
            )
        )

        # table header
        elements.append(Spacer(0, 15))
        table_elements = []
        table_elements.append([
            gen_text(
                header_text, 
                bold=True,
                size=12,
                align=TA_CENTER, 
                color="white"
            )
            for header_text in config['table_headers']
        ])

        default_measurement_name = config.get(
            'default_measurement_name',
            'Votes'
        )

        # generate rows
        for group in config['groups']:
            census = 0
            # usually measurement is "Votes", but it can be customized to be
            # something else
            measurement_value = 0
            for auth_event_id in group['auth_event_ids']:
                auth_event = AuthEvent.objects.get(pk=auth_event_id)

                census_query = auth_event.get_census_query()
                if 'extra_filters' in group:
                    census_query = census_query.filter(
                        **group['extra_filters']
                    )
                census += census_query.count()

                # Note that because the base query starts from the census query
                # as it is in the case of measurement_query_base being 'census'
                # or 'active', we apply the same extra_filters as the
                # census_query variable.
                #
                # When measurement_query_base is 'votes' (the default), the
                # selected table is different. This makes same extra_filters not
                # work with the vote counting query even if they do work in the
                # census query. For this reason, if measurement_query_base is
                # 'votes' and measurement_extra_filters is set, we don't apply
                # the extra_filters to the votes query. In all other cases, we
                # do.
                measurement_query_base = group.get(
                    'measurement_query_base',
                    'votes'
                )
                if measurement_query_base == 'census':
                    measurement_query = auth_event.get_census_query()
                    if 'extra_filters' in group:
                        census_query = census_query.filter(
                            **group['extra_filters']
                        )
                    if 'measurement_extra_filters' in group:
                        measurement_query = measurement_query.filter(
                            **group['measurement_extra_filters']
                        )
                # 'active' means the user has more than 0 actions executed by
                # the user in the activity log.
                elif measurement_query_base == 'active':
                    measurement_query = auth_event.get_census_query()

                    measurement_query = measurement_query\
                        .annotate(
                            actions_count=Count("user__user__executed_actions")
                        )\
                        .filter(actions_count__gt=0)

                    if 'extra_filters' in group:
                        census_query = census_query.filter(
                            **group['extra_filters']
                        )

                    if 'measurement_extra_filters' in group:
                        measurement_query = measurement_query.filter(
                            **group['measurement_extra_filters']
                        )
                # meaning the default, 'votes'
                elif measurement_query_base == 'votes':
                    measurement_query = auth_event.get_num_votes_query()
                    if 'measurement_extra_filters' in group:
                        measurement_query = measurement_query.filter(
                            **group['measurement_extra_filters']
                        )
                    elif 'extra_filters' in group:
                        measurement_query = measurement_query.filter(
                            **group['extra_filters']
                        )
                else:
                    raise Exception(
                        'invalid measurement_query_base: %r' % ( 
                            measurement_query_base
                        )
                    )

                measurement_value += measurement_query.count()

            row = [
                group['title'],
                group.get('measurement_name', default_measurement_name),
                "{:,}".format(measurement_value),
                (
                    "{:,.2f}%".format(measurement_value*100.0/census) 
                    if census > 0
                    else "-"
                ),
                "{:,}".format(census),
            ]

            table_elements.append([
                gen_text(cell_text, align=TA_CENTER, size=12)
                for cell_text in row
            ])
        
        main_table = Table(
            table_elements,
            colWidths=[
                250,
                80,
                60,
                80,
                80
            ]
        )
        main_table_style = TableStyle([
            # general styling
            ('INNERGRID', (0,0), (-1,-1), 5, colors.white),
            ('TOPPADDING', (0,0), (-1,-1), 8),
            ('BOTTOMPADDING', (0,0), (-1,-1), 8),

            # header
            ('BACKGROUND',(0,0), (-1,0), '#d01d00'),
            
            # body
            ('ROWBACKGROUNDS', (0,1), (-1,-1), ['#efefef', colors.white])
        ])
        main_table.setStyle(main_table_style)
        elements.append(main_table)
        doc.build(elements)

        email = EmailMessage(
            subject=replace_date(config['email']['subject'], now),
            body=replace_date(config['email']['body'], now),
            to=config['email']['to']
        )
        email.attach_file(pdf_path)
        email.send()

