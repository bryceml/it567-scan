#!/usr/bin/python3

import argparse
import sys
import subprocess

parser = argparse.ArgumentParser()
parser.add_argument("ip", metavar="<IP Address>", type=str, help="One ip address to scan")
parser.add_argument("ports", metavar="<Ports>", type=str, help="Comma Separated list of ports")
args = parser.parse_args()
print("Arguments: " + str(args))
print("IP Address: " + str(args.ip))
print("Ports: " + str(args.ports))

from scapy.all import *

portlist = args.ports.split(",")

fileoutput = open('/tmp/scan-output.md', 'w')

for port in portlist:

  dst_ip=args.ip
  src_port=RandShort()
  dst_port=int(port)

  tcp_connect_scan_resp = sr1(IP(dst=dst_ip)/TCP(sport=src_port,dport=dst_port,flags="S"),timeout=3)
  if(str(type(tcp_connect_scan_resp))=="<type 'NoneType'>"):
    fileoutput.write("Port " + str(port) + ": Closed\n\n")
    print("Port " + str(port) + ": Closed\n\n")
  elif(tcp_connect_scan_resp.haslayer(TCP)):
    if(tcp_connect_scan_resp.getlayer(TCP).flags == 0x12):
      send_rst = sr(IP(dst=args.ip)/TCP(sport=src_port,dport=dst_port,flags="AR"),timeout=3)
      fileoutput.write("Port " + str(port) + ": Open\n\n")
      print("Port " + str(port) + ": Open\n\n")
    elif (tcp_connect_scan_resp.getlayer(TCP).flags == 0x14):
      fileoutput.write("Port " + str(port) + ": Closed\n\n")
      print("Port " + str(port) + ": Closed\n\n")

fileoutput.close()
print("\n\nYour report is in /tmp/scan-output.pdf")
subprocess.call(['pandoc', '-o', '/tmp/scan-output.pdf', '/tmp/scan-output.md'])
