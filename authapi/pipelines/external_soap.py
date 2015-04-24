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


def api_call(dni, baseurl='', user='', password=''):
    if not baseurl.endswith('/'):
        baseurl = baseurl + '/'
    login = 'TAOWebService?wsdl'
    queries = 'Poblacion?wsdl'

    #client1 = Client(baseurl + login)
    #client2 = Client(baseurl + queries)

    #resp = client1.service.login(user, password)
    #resp = parseString(resp)
    #token = xml_text(xml_get_node(resp, "token"))
    #date = xml_text(xml_get_node(resp, "fechasistema"))

    #resp = client2.service.getHabitanteByDNI(dni)

    data = {'custom': True}
    return False, data
