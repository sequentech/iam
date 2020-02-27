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

from collections import defaultdict
from contracts import CheckException
from pipelines import PipeReturnvalue
import json

__all__ = ['check_contract']

class JsonTypeEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, type):
            return str(obj)

        # Let the base class default method raise the TypeError
        return json.JSONEncoder.default(self, obj)

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
# All the following private function work in a similar way: the receive a
# contract and the data that is bound to that contract, and if the function
# detects that the contract is not being satisfied, an exception is raised.

def check_isinstance(contract, data):
    '''
    Examples of valid input:

        check_isinstance({"type": str}, "my-string")
        check_isinstance({"type": int}, 78)
        check_isinstance({"type": Foo}, Foo())

    Examples of invalid input (raises an Exception):

        check_isinstance({"type": str}, 78)
        check_isinstance({"type": int}, "my-string")
        check_isinstance({"type": Foo}, Bar())
    '''
    if not isinstance(data, contract['type']):
        raise CheckException(
            key="invalid-check",
            context={
                "contract":contract,
                "data":data,
                "checked-type":contract['type'],
                "data-type": type(data)})

def check_length(contract, data):
    '''
    Examples of valid input:

        check_length({"range": [2,4]}, "123")
        check_length({"range": [3,5]}, [1,2,3])

    Examples of invalid input (raises an Exception):

        check_length({"range": [2,4]}, "12345")
        check_length({"range": [3,5]}, [1,2])
    '''
    l = len(data)
    if l > contract['range'][1] or l < contract['range'][0]:
        raise CheckException(
            key="invalid-data-length",
            context={
                "contract":contract,
                "data":data,
                "data-length": l})

def check_lambda(contract, data):
    '''
    The lambda fails when it raises an Exception or if return value is False.
    Note that it does NOT fail if the return value is None.

    Examples of valid input:

        check_lambda({"lambda": lambda data: re.match("^[0-9]+$") is not None}, "123")
        check_lambda({"lambda": lambda data: data in ["aa", "bb"]}, "aa")

    Examples of invalid input (raises an Exception):

        check_lambda({"lambda": lambda data: re.match("^[0-9]+$") is not None}, "123a")
        check_lambda({"lambda": lambda data: data in ["aa", "bb"]}, "cc")
    '''
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
    '''
    All the elements of the list must validate the check list.

    Examples of valid input:

        check_iterate_list(
          {"check-list": [{"check:" "isinstance", "type": str}]},
          ["a", "foo", "bar"])

    Examples of invalid input (raises an Exception):

        check_iterate_list(
          {"check-list": [{"check:" "isinstance", "type": str}]},
          ["a", "foo", "bar", 145])
    '''
    for el_data in data:
        check_list(contract['check-list'], el_data)

def check_index_check_list(contract, data):
    '''
    The specific index of the list must validate the check list.

    Examples of valid input:

        check_index_check_list(
          {"index": 0, "check-list": [{"check:" "isinstance", "type": str}]},
          ["a", 1, 5.6])

    Examples of invalid input (raises an Exception):

        check_index_check_list(
          {"index": 1, "check-list": [{"check:" "isinstance", "type": str}]},
          ["a", 1, 5.6])
    '''
    check_list(contract['check-list'], data[contract['index']])

def check_dict_keys_exist(contract, data):
    '''
    The list of keys must exist in the dictionary.

    Examples of valid input:

        check_dict_keys_exist(
          {"keys": ["key1", "key3"]},
          {"key1": None, "key2": "foo", "key3": ["bar"]})

    Examples of invalid input (raises an Exception):

        check_dict_keys_exist(
          {"keys": ["key1", "key4"]},
          {"key1": None, "key2": "foo", "key3": ["bar"]})
    '''
    for key in contract['keys']:
        if key not in data:
            raise CheckException(
                key="dict-keys-not-found",
                context={
                    "contract":contract,
                    "data":data})


def check_dict_keys_exact(contract, data):
    '''
    The list of keys must exist in the dictionary, and there are none other.

    Examples of valid input:

        check_dict_keys_exist(
          {"keys": ["key1", "key2"]},
          {"key1": None, "key2": "foo"})

    Examples of invalid input (raises an Exception):

        check_dict_keys_exist(
          {"keys": ["key1", "key2"]},
          {"key1": None, "key2": "foo", "key3": ["bar"]})
    '''

    if set(contract['keys']) != set(data.keys()):
        raise CheckException(
            key="dict-keys-not-exact",
            context={
                "contract":contract,
                "data":data})

def check_switch_contract(contract, data):
    '''
    Sepcify depending on a dict key value on a contract for the value of a dict
    key. The switch-key must be a string value.

    Examples of valid input:

        check_switch_contract(
          {
            "switch-key": "mode",
            "contract-key": "mode-data",
            "contracts": {
              "str-mode": [
                {'check': 'isinstance', 'type': str}
              ],
              "int-mode": [
                {'check': 'isinstance', 'type': int}
              ]
            }
          },
          {"mode": "str", "mode-data": "foo"})

    Examples of invalid input (raises an Exception):

        check_switch_contract(
          {
            "switch-key": "mode",
            "contract-key": "mode-data",
            "contracts": {
              "str-mode": [
                {'check': 'isinstance', 'type': str}
              ],
              "int-mode": [
                {'check': 'isinstance', 'type': int}
              ]
            }
          },
          {"mode": "str", "mode-data": 452453})
    '''
    switch_key = contract['switch-key']
    contract_key = contract['contract-key']

    key_val = data[switch_key]
    contracts = contract['contracts']
    if key_val not in contracts:
        raise CheckException(
            key="unknown-key-contract",
            context={
                "contract":contract,
                "data":data})
    check_list(contracts[key_val], data[contract_key])

def check_item(contract, data):
    try:
        {
            "isinstance": check_isinstance,
            "iterate-list": check_iterate_list,
            "length": check_length,
            "lambda": check_lambda,
            "index-check-list": check_index_check_list,
            "dict-keys-exist": check_dict_keys_exist,
            "dict-keys-exact": check_dict_keys_exact,
            "switch-contract-by-dict-key": check_switch_contract
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
