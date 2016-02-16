#!/bin/bash

cd authapi
python manage.py migrate --settings=authapi.test_settings
python manage.py loaddata --settings=authapi.test_settings initial
python manage.py test --settings=authapi.test_settings
