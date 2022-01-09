FROM travelping/scapy
RUN apk add iptables nano git
RUN git clone https://github.com/kytos/python-openflow.git
RUN cd python-openflow && python3 setup.py install
ADD pkt_generator.py /pkt_generator.py
ADD openflow.pcapng /openflow.pcapng