FROM ubuntu:latest
COPY . /opt/scoring
WORKDIR /opt/scoring
RUN apt-get update && apt-get install -y \
    python3-pip
RUN python3 -m pip install -r requirements.txt