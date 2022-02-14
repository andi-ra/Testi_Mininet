'''
RestClient is an open source script that depends on requests library
it was developed in 2012 and updated in 2014 by @Khalid Al-hussayen
the script was used for my owen projects so it is limited to my use any one is welcome to update and fix the script.
'''
import json
import subprocess
from random import random
from time import sleep

import requests
from scapy.config import conf
from scapy.layers.inet import IP, ICMP
from scapy.sendrecv import sr1

'''
RestClient class is the only class :) it have the four popular http methods (GET,POST,PUT,DELETE) ,
to use the RestClient you need to declare object from it inilize the host with the base url and resource with your url resource , 
Then you can call any methods get or post etc.. the http response will be hold in the reponce object 
call response.json() if you want the data parce to json or response.text for the plain data and res.response.status_code.
response is an requests response object for more information you can see this url http://docs.python-requests.org/en/latest/user/quickstart/#response-content
'''


def ping(host):
    """
    Returns True if host (str) responds to a ping request.
    Remember that a host may not respond to a ping (ICMP) request even if the host name is valid.
    """

    # Building the command. Ex: "ping -c 1 google.com"
    command = ['ping', "-c", '1', host]

    return subprocess.call(command) == 0


class RestClient:
    User_Agent = 'ubuntu'
    host = 'http://172.21.156.60'
    Content_Type = 'Application/json'
    resource = ''
    Date = ''
    headers = {}
    data = []
    status_code = ''
    url = ''
    text = ''
    response = None
    username = ''
    password = ''

    def put_header(self, key, value):
        self.headers[key] = value

    def get(self, append_url='', params={}, is_auth=False):
        if is_auth:
            self.response = requests.get(self.host + self.resource + append_url, headers=self.headers, params=params,
                                         auth=(self.username, self.password))
        else:
            self.response = requests.get(self.host + self.resource + append_url, headers=self.headers, params=params)

    def post(self, params={}, append_url='', is_auth=False):
        if is_auth:
            self.response = requests.post(self.host + self.resource + append_url, data=params, headers=self.headers,
                                          auth=(self.username, self.password))
        else:
            self.response = requests.post(self.host + self.resource + append_url, data=params, headers=self.headers)

    def put(self, params={}, append_url='', is_auth=False):
        if is_auth:
            self.response = requests.put(self.host + self.resource + append_url, data=params, headers=self.headers,
                                         auth=(self.username, self.password))
        else:
            self.response = requests.put(self.host + self.resource + append_url, data=params, headers=self.headers)

    def delete(self, append_url='', params={}, is_auth=False):
        if is_auth:
            self.response = requests.delete(self.host + self.resource + append_url, params=params, headers=self.headers,
                                            auth=(self.username, self.password))
        else:
            self.response = requests.delete(self.host + self.resource + append_url, params=params, headers=self.headers)


if __name__ == '__main__':
    api = RestClient()
    ping_list = ["172.21.156.60", "172.21.156.20", "172.21.156.7", "172.21.156.2"]
    TIMEOUT = 2
    conf.verb = 0
    for ip in ping_list:
        packet = IP(dst=ip, ttl=2) / ICMP()
        reply = sr1(packet, timeout=TIMEOUT)
        if not (reply is None):
            print(reply.dst, "is online")

        else:
            print("Timeout waiting for %s" % packet[IP].dst)
    api.get(append_url=":8080/v1.0/topology/switches", params=None)
    json_resp = json.loads(api.response.content)
    print(json.dumps(json_resp, indent=2))
