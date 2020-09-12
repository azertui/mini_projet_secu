import pyshark
import sys
import argparse
from datetime import timedelta

# Parser for arguments
parser = argparse.ArgumentParser()
parser.add_argument("-f", "--file", type=str, default="03.pcap", help="pcap file to analyze (default: 03.pcap)")
parser.add_argument("-s", "--scan", help="show the type of scan", action="store_true")
args = parser.parse_args()

file = pyshark.FileCapture(args.file, display_filter='udp or (tcp.flags.syn==1 and tcp.flags.ack==0)')

dico = dict()
#  [compteur,[ports],dernier_temps]
ignored_ips = []
delta = timedelta(milliseconds=10)

def scan_type(filter):
    sS = False
    sT = False
    dico_scan = dict()
    for ip in ignored_ips:
        file = pyshark.FileCapture(args.file, display_filter=filter + " and ip.src==" + ip)
        for p in file:
            if (int(p.tcp.flags_syn)==1 and int(p.tcp.flags_ack)==0 and int(p.tcp.flags_reset)==0):
                dico_scan[(p.tcp.srcport, p.tcp.dstport)] = "syn"
            elif (int(p.tcp.flags_ack)==1 and int(p.tcp.flags_syn)==0 and int(p.tcp.flags_reset)==0):
                if ((p.tcp.srcport, p.tcp.dstport) in dico_scan.keys()):
                    if (dico_scan[(p.tcp.srcport, p.tcp.dstport)] == "syn"):
                        dico_scan[(p.tcp.srcport, p.tcp.dstport)] = "ack"
                    else:
                        continue
                else:
                    continue
            elif (int(p.tcp.flags_ack)==1 and int(p.tcp.flags_reset)==1):
                if ((p.tcp.srcport, p.tcp.dstport) in dico_scan.keys()):
                    if (dico_scan[(p.tcp.srcport, p.tcp.dstport)] == "ack"):
                        sT = True
                    else:
                        continue
                else:
                    continue
            elif (int(p.tcp.flags_reset)==1 and int(p.tcp.flags_ack)==0):
                if ((p.tcp.srcport, p.tcp.dstport) in dico_scan.keys()):
                    if (dico_scan[(p.tcp.srcport, p.tcp.dstport)] == "syn"):
                        sS = True
                    else:
                        continue
                else:
                    continue
            else:
                continue
        if (sT):
            print(p.ip.src, " uses TCP connect() scan!")
        if (sS):
            print(p.ip.src, " uses SYN Stealth scan!")
        if (sT == False and sS == False):
            print("Unable to identify the scan used by ", p.ip.src)
        sT = False
        sS = False

for p in file:
    ip = p.ip.src
    if ip in ignored_ips:
        continue
    port = 0
    if hasattr(p,'udp'):
        port = p.udp.port
    elif hasattr(p,'tcp'):
        port = p.tcp.port
    else:
        continue
    if p.ip.src not in dico.keys():
        dico[p.ip.src] = [0,[port], p.sniff_time]
    else:
        if port in dico[p.ip.src][1]:
            continue
        if p.sniff_time - dico[p.ip.src][2] < delta:
            dico[p.ip.src][1].append(port)
            dico[p.ip.src][0]+=1
            if dico[p.ip.src][0] == 50:
                print("Warning! ", p.ip.src, " is scanning you")
                ignored_ips.append(p.ip.src)
        dico[p.ip.src][2]=p.sniff_time

if args.scan:
    scan_type('tcp') # sT and sS
