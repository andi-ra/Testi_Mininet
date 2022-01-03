#CONTROLLER DOCKERFILE
# ipyton is only available in "edge"
# Ryu SDN Framework
#
# VERSION 0.0.1

FROM python:3.8-slim-buster


ENV HOME /root
WORKDIR /root

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    sudo \
    python3-setuptools \
    python3-pip \
    python3-eventlet \
    python3-lxml \
    python3-msgpack \
    iproute2 \
    procps \
    lldpd \
 && rm -rf /var/lib/apt/lists/* \
 && curl -kL https://github.com/osrg/ryu/archive/master.tar.gz | tar -xvz \
 && mv ryu-master ryu \
 && cd ryu \
 && python3 -m pip install -r tools/pip-requires \
 && python3 setup.py install
#RUN python -m pip install --upgrade pip
ADD simple_switch_Dulla.py /usr/local/lib/python3.8/site-packages/ryu/app/simple_switch_Dulla.py
ADD shortest_path.py /usr/local/lib/python3.8/site-packages/ryu/app/shortest_path.py
RUN python3 -m pip install nose eventlet==0.31.1 scapy networkx importlib-metadata
RUN apt-get update && apt-get -o Dpkg::Options::="--force-confmiss" install -y --reinstall netbase




