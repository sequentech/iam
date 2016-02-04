#!/bin/bash

cd authapi
python manage.py migrate --settings=authapi.settings
python manage.py loaddata --settings=authapi.settings initial
python manage.py test --settings=authapi.settings
