#!/usr/bin/python3

import argparse
import sys
import subprocess

parser = argparse.ArgumentParser(description="This scans an address for open tcp ports using scapy.  It outputs a pdf report in /tmp/scan-output.pdf Example: python3 scan.py 192.168.0.1,192.168.0.2 22,25")
parser.add_argument("ips", metavar="<IP Address>", type=str, help="Comma separated list of ip addresses")
parser.add_argument("ports", metavar="<Ports>", type=str, help="Comma separated list of ports")
args = parser.parse_args()
print("Arguments: " + str(args))
print("IP Address: " + str(args.ips))
print("Ports: " + str(args.ports))

from scapy.all import *

portlist = args.ports.split(",")
hostlist = args.ips.split(",")

fileoutput = open('/tmp/scan-output.md', 'w')
fileoutput.write("# Report of scanning IPs " + str(args.ips) + " with tcp ports " + str(args.ports) + "\n\n")

for host in hostlist:
  for port in portlist:

    dst_ip=host
    src_port=RandShort()
    dst_port=int(port)
    fileoutput.write("IP: " + str(host))
    print("IP: " + host)
    tcp_connect_scan_resp = sr1(IP(dst=dst_ip)/TCP(sport=src_port,dport=dst_port,flags="S"),timeout=3)
    if(str(type(tcp_connect_scan_resp))=="<type 'NoneType'>"):
      fileoutput.write("Port " + str(port) + ": Closed\n\n")
      print("Port " + str(port) + ": Closed\n\n")
    elif(tcp_connect_scan_resp.haslayer(TCP)):
      if(tcp_connect_scan_resp.getlayer(TCP).flags == 0x12):
        send_rst = sr(IP(dst=dst_ip)/TCP(sport=src_port,dport=dst_port,flags="AR"),timeout=3)
        fileoutput.write("Port " + str(port) + ": Open\n\n")
        print("Port " + str(port) + ": Open\n\n")
      elif (tcp_connect_scan_resp.getlayer(TCP).flags == 0x14):
        fileoutput.write("Port " + str(port) + ": Closed\n\n")
        print("Port " + str(port) + ": Closed\n\n")

fileoutput.close()
print("\n\nYour report is in /tmp/scan-output.pdf")
subprocess.call(['pandoc', '-o', '/tmp/scan-output.pdf', '/tmp/scan-output.md'])
