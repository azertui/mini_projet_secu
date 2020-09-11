import pyshark
from datetime import timedelta
file = pyshark.FileCapture('03.pcap')

dico = dict()
# tuple (compteur,[ports],dernier_temps)
delta = timedelta(milliseconds=10)
for p in file:
    ip = p.ip.src
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
                print("Warning! ",p.ip.src," is scanning you")
        dico[p.ip.src][2]=p.sniff_time
