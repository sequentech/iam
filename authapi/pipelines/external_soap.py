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

from suds.client import Client
from xml.dom.minidom import parseString


def xml_text(node):
    return node.firstChild.data


def xml_get_node(dom, tag):
    for n in dom.childNodes:
        if n.nodeType == n.TEXT_NODE:
            continue
        if n.tagName.lower() == tag:
            return n
        else:
            found = xml_get_node(n, tag)
            if found:
                return found
    return None


def api_call(baseurl='',
        check_field='empadronado', store_fields=None,
        query='', args=None, **kwargs):

    if not args:
        args = []

    client = Client(baseurl)
    method = getattr(client.service, query)
    resp = method(*args)

    check = getattr(resp, check_field)

    data = {}
    if check and store_fields:
        for k in store_fields:
            data[k] = str(getattr(resp, k))

    return check, data
