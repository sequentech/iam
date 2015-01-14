#!/bin/bash

cd authapi
python manage.py syncdb --noinput
python manage.py test
