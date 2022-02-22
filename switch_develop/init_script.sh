#!/bin/sh

ovs-vsctl list-br
ovs-vsctl add-br br0
ovs-vsctl add-port eth1 br0
ovs-vsctl add-port  br0 eth1
ovs-ofctl dump-ports br0
ovs-vsctl show
ovs-vsctl set interface br0 lldp:enable=true
#ovs-ofctl add-flow br0 dl_dst=01:80:c2:00:00:0e,dl_type=0x88cc,actions=controller
ovs-vsctl set-controller br0 tcp:172.21.156.60:6633
sleep 5
ovs-vsctl list controller
