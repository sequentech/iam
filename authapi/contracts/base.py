from collections import defaultdict
from contracts import CheckException
from pipelines import PipeReturnvalue

__all__ = ['check_contract']

def check_contract(contract, data):
    '''
    Raises an Exception if the contract is breached.

    Contracts are used to check dicts  and lists to conform with a defined
    format. A contract is defined declaratively. For example, to check that our
    data is a list of integers, we can use the following contract:

    [
      {
        'check': 'isinstance',
        'type': list
      },
      {
        'check': "iterate-list",
        'check-list': [
          {
            'check': 'isinstance',
            'type': int
          }
        ]
      }
    ]
    '''
    check_list(contract, data)
    return PipeReturnvalue.CONTINUE

#------------------------ private functions ------------------------------------

def check_isinstance(contract, data):
    if not isinstance(data, contract['type']):
        raise CheckException(
            key="invalid-check",
            context={
                "contract":contract,
                "data":data,
                "checked-type":contract['type'],
                "data-type": type(data)})

def check_length(contract, data):
    l = len(data)
    if l > contract['range'][1] or l < contract['range'][0]:
        raise CheckException(
            key="invalid-data-length",
            context={
                "contract":contract,
                "data":data,
                "data-length": l})

def check_lambda(contract, data):
    try:
        ret = contract['lambda'](data)
    except:
        ret = False

    if ret is False:
        raise CheckException(
            key="invalid-check-lambda",
            context={
                "contract":contract,
                "data":data})

def check_iterate_list(contract, data):
    for el_data in data:
        check_list(contract['check-list'], el_data)

def check_list_index_check_list(contract, data):
    check_list(contract['check-list'], data[contract['index']])

def check_item(contract, data):
    try:
        {
            "isinstance": check_isinstance,
            "iterate-list": check_iterate_list,
            "length": check_length,
            "lambda": check_lambda,
            "list-index-check-list": check_list_index_check_list
        }[contract['check']](contract, data)
    except CheckException as e:
        raise e
    except Exception as e:
        raise CheckException(
            key="invalid-check",
            context=contract)

def check_list(contract_list, data):
    for item in contract_list:
        check_item(item, data)