import pyshark
file = pyshark.FileCapture('03.pcap')

dico = dict()
# tuple (compteur,[ports],dernier_temps)
for p in file:
    print(p)
    ip = p.ip.src
    port = 0
    if hasattr(p,'udp'):
        port = p.udp.port
    elif hasattr(p,'tcp'):
        port = p.tcp.port
    else:
        continue
    if p.ip.src not in dico.keys():
        dico[p.ip.src] = (0,[port], p.sniff_timestamp)
    else:
        if port in dico[p.ip.src][1]:
            continue
        if float(p.sniff_timestamp) - float(dico[p.ip.src][2]) < 10:
            dico[p.ip.src][1].append(port)
            dico[p.ip.src][0]+=1
            if dico[p.ip.src][0] == 50:
                print("SCAN!!!!!")
