#!/bin/bash

python3 -m pip install virtualenv
virtualenv venv
source venv/bin/activate
python3 -m pip install --upgrade pip
python -m pip install -r requirements.txt
