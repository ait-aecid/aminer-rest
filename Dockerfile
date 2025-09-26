# NOTE: This Dockerfile does not work on it's own and must be adapted so the aminer remote control socket is exposed and running.
# Also volumes need to be mounted for the aminer imports to work.
# This Dockerfile is meant to be used in a docker compose configuration.

# sudo docker build -f Dockerfile -t aminer-rest .
# sudo docker run -p 8000:8000 --rm aminer-rest

# Pull base image.
FROM debian:trixie
ARG UNAME=aminer
ARG UID=1000
ARG GID=1000

# allow the system to use two package managers (apt and pip), as we do it intentionally (needed since Debain Bookworm - see PEP 668
ENV PIP_BREAK_SYSTEM_PACKAGES=1

RUN groupadd -g $GID $UNAME && useradd -m -u $UID -g $GID -s /bin/bash $UNAME

ARG varbranch="main"
ENV BRANCH=$varbranch

# Set local timezone
ENV TZ=Europe/Vienna
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

LABEL maintainer="wolfgang.hotwagner@ait.ac.at"

# Install necessary debian packages
ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends apt-utils
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    sudo

ADD . /home/aminer/aminer-rest
RUN cd /home/aminer/aminer-rest && pip install -r requirements.txt

# For Docs
RUN mkdir /docs
ADD README.md /docs
ADD LICENSE /docs/LICENSE.md

# Prepare the system and link all python-modules
RUN chown $UID.$GID -R /docs

RUN PACK=$(find /usr/lib/python3/dist-packages -name posix1e.cpython\*.so) && FILE=$(echo $PACK | awk -F '/' '{print $NF}') ln -s $PACK /usr/lib/logdata-anomaly-miner/$FILE

USER aminer
WORKDIR /home/aminer/aminer-rest

EXPOSE 8000
ENTRYPOINT ["uvicorn", "RemoteControlApi:app", "--host", "0.0.0.0", "--port", "8000"]
