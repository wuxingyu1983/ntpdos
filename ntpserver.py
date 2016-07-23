#!/usr/bin/env python
from scapy.all import *
import sys


def printhelp():
	print "Get NTP Server from cap file"
	print "By leowu"
	print "Usage ntpserver.py <cap file> <output file>"
	exit(0);

if len(sys.argv) < 3:
	printhelp()

cap_file = sys.argv[1];
output_file = sys.argv[2];

packets = rdpcap(cap_file)

ret = {}

for packet in packets:
     if (packet.haslayer(UDP)):
         if (123 == packet.getlayer(UDP).sport):
             if (ret.get(packet.getlayer(IP).src)):
                 ret[packet.getlayer(IP).src] += 1
             else:
                 ret[packet.getlayer(IP).src] = 1

output = open(output_file, 'w')
for k in ret.keys():
    output.write(k + "\n")

output.close()
