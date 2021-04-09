FROM python:latest

RUN apt-get update -y && apt-get upgrade -y
RUN python3 -m pip install --upgrade pip

ADD ./requirements.txt /tmp/requirements.txt
RUN python3 -m pip install -r /tmp/requirements.txt && rm -f /tmp/requirements.txt
