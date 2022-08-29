FROM python:3.8-bullseye

WORKDIR /sliver-py
RUN apt-get update -y && apt-get upgrade -y  && apt-get install curl -y 


# Configure hatch
RUN python3 -m pip install --upgrade pip hatch
RUN hatch config set dirs.env.virtual .venv && hatch config update


# This is a little backwards than usual since we need the dynamic version for 'hatch env' so we copy everything
COPY . .
RUN hatch env create dev