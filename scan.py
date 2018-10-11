#!/usr/bin/python3

import argparse
import sys
import subprocess

parser = argparse.ArgumentParser(description="This scans an address for open tcp ports using scapy.  It outputs a pdf report in /tmp/scan-output.pdf.  Note that it must be run with root privileges. Example: python3 scan.py 192.168.0.1,192.168.0.2 22,25")
parser.add_argument("ips", metavar="<IP Address>", type=str, help="Comma separated list of ip addresses")
parser.add_argument("ports", metavar="<Ports>", type=str, help="Comma separated list of ports")
args = parser.parse_args()
print("Arguments: " + str(args))
print("IP Address: " + str(args.ips))
print("Ports: " + str(args.ports))

from scapy.all import *

# get comma list of ips and ports from comma-separated list
portlist = args.ports.split(",")
hostlist = args.ips.split(",")

# output file
fileoutput = open('/tmp/scan-output.md', 'w')
fileoutput.write("# Report of scanning IPs " + str(args.ips) + " with tcp ports " + str(args.ports) + "\n\n")

for host in hostlist:
  fileoutput.write("\n\nIP: " + str(host) + "\n\n")
  print("\n\nIP: " + host + "\n\n")
  for port in portlist:

    # some of the code from https://resources.infosecinstitute.com/port-scanning-using-scapy/ was used as a resource

    dst_ip=host
    src_port=RandShort()
    dst_port=int(port)
    # Connect to ip with syn
    tcp_connect_scan_resp = sr1(IP(dst=dst_ip)/TCP(sport=src_port,dport=dst_port,flags="S"),timeout=3)
    # If no response after 3 seconds assume it's closed
    if(str(type(tcp_connect_scan_resp))=="<type 'NoneType'>"):
      fileoutput.write("Port " + str(port) + ": Closed\n\n")
      print("Port " + str(port) + ": Closed\n\n")
    # if there is a tcp response
    elif(tcp_connect_scan_resp.haslayer(TCP)):
      # if the response has a syn+ack then it's open
      if(tcp_connect_scan_resp.getlayer(TCP).flags == 0x12):
        send_rst = sr(IP(dst=dst_ip)/TCP(sport=src_port,dport=dst_port,flags="AR"),timeout=3)
        fileoutput.write("Port " + str(port) + ": Open\n\n")
        print("Port " + str(port) + ": Open\n\n")
      # if the response has a ack+reset then it's closed
      elif (tcp_connect_scan_resp.getlayer(TCP).flags == 0x14):
        fileoutput.write("Port " + str(port) + ": Closed\n\n")
        print("Port " + str(port) + ": Closed\n\n")

fileoutput.close()
subprocess.call(['pandoc', '-o', '/tmp/scan-output.pdf', '/tmp/scan-output.md'])
print("\n\nYour report is in /tmp/scan-output.pdf")
