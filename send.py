#!/usr/bin/env python3

import sys
from scapy.all import sr1, IP, ICMP

if len(sys.argv) < 3:
    print('Usage: {} IP "command"'.format(sys.argv[0]))
    exit(0)

p = sr1(IP(dst=sys.argv[1])/ICMP()/"run:{}".format(sys.argv[2]))
if p:
    p.show()
