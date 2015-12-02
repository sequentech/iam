#!/bin/bash

cd authapi
python manage.py migrate
python manage.py loaddata initial
python manage.py test
