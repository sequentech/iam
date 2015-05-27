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
