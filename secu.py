# Eloïse Stein
# Arthur Rauch
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
ignored_ips = [] # allows you to banish ips already detected as malicious
delta = timedelta(milliseconds=10) # threshold

# function to determine the type of scans used by the attacker
# when we enter in this function we already know the malicious ip so we simply
# analyze the type of packets sent to see which scan was used,
# we don't need to check how often the attacker has sent these packets
def scan_type(filter):
    sS = False
    sT = False
    sN = False
    sF = False
    sX = False
    dico_scan = dict()
    for ip in ignored_ips:
        file = pyshark.FileCapture(args.file, display_filter=filter + " and ip.src==" + ip)
        for p in file:
            if (p.tcp.flags.raw_value=="2"): # SYN
                dico_scan[(p.tcp.srcport, p.tcp.dstport)] = "syn"
            elif (p.tcp.flags.raw_value=="10"): # ACK
                if ((p.tcp.srcport, p.tcp.dstport) in dico_scan.keys()):
                    if (dico_scan[(p.tcp.srcport, p.tcp.dstport)] == "syn"):
                        dico_scan[(p.tcp.srcport, p.tcp.dstport)] = "ack"
                    else:
                        continue
                else:
                    continue
            elif (p.tcp.flags.raw_value=="14"): # RST, ACK
                if ((p.tcp.srcport, p.tcp.dstport) in dico_scan.keys()):
                    if (dico_scan[(p.tcp.srcport, p.tcp.dstport)] == "ack"):
                        sT = True
                    else:
                        continue
                else:
                    continue
            elif (p.tcp.flags.raw_value=="4"): # RST
                if ((p.tcp.srcport, p.tcp.dstport) in dico_scan.keys()):
                    if (dico_scan[(p.tcp.srcport, p.tcp.dstport)] == "syn"):
                        sS = True
                    else:
                        continue
                else:
                    continue
            elif (p.tcp.flags.raw_value=="0"): # NULL
                sN = True
            elif (p.tcp.flags.raw_value=="1"): # FIN
                sF = True
            elif (p.tcp.flags.raw_value=="29"): # FIN, PSH, URG
                sX = True
            else:
                continue
        if (sT):
            print(p.ip.src, " uses TCP connect() scan!")
        if (sS):
            print(p.ip.src, " uses SYN Stealth scan!")
        if (sN):
            print(p.ip.src, " uses NULL scan!")
        if (sF):
            print(p.ip.src, " uses FIN scan!")
        if (sX):
            print(p.ip.src, " uses Xmas scan!")
        if (sT==False and sS==False and sN==False and sF==False and sX==False):
            print("Unable to identify the scan used by ", p.ip.src)
        sT = False
        sS = False
        sN = False
        sF = False
        sX = False

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
    scan_type('tcp') # sT, sS, sN, sF, sX
