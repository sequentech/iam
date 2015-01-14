#!/bin/bash

cd authapi
python manage.py syncdb
python manage.py test
