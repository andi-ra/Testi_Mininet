FROM travelping/scapy
RUN apk add iptables nano git
RUN git clone https://github.com/kytos/python-openflow.git
RUN cd python-openflow && python3 setup.py install
RUN python3 -m pip install requests
ADD pkt_generator.py /pkt_generator.py
ADD TCP_OFPTxx.py /TCP_OFPTxx.py
ADD openflow.pcapng /openflow.pcapng
ADD rest_client.py /rest_client.py