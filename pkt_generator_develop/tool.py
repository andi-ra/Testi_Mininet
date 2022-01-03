#!/usr/bin/python
'''
Created on Jun 20, 2013

@author: Alexandru Nicolae
'''
from sys import argv
from Packet_Generator import *

if __name__ == '__main__':

    length = len(argv)
    if length < 3:
        message1()
        exit(0)

    packet = None
    interface = None

    result = create_packet(argv)  # create packet based on CLI informations
    # if the interface is not specified, eth0 is considered default

    packet = result[0]
    interface = result[1]
    print
    "Output interface: " + interface

    # packet.show() #uncomment this for debugging a packet

    # ans,unans = srp(packet,verbose=1,iface=interface) #send and receive answers
    sendp(packet, verbose=1, iface=interface)  # only send