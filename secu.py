import pyshark
file = pyshark.FileCapture('03.pcap')

dico = dict()
# tuple (compteur,[ports],dernier_temps)
for p in file:
    var ip = p['ip'].src
    var port = 0
    if hasattr(p,'icmp'):
        port = p.icmp.port
        pass
    elif hasattr(p,'udp'):
        port = p.udp.port
    elif hasattr(p,'tcp'):
        port = p.tcp.port
    else:
        continue
    if p['ip'].src not in dico.keys():
        dico[p['ip'].src] = (0,[port],p.time)
    else:
        if port in dico[p['ip'].src][1]:
            continue
        if p.time - dico[p['ip'].src][2] < 0.01:
            dico[p['ip'].src][1].append(port)
            dico[p['ip'].src][0]+=1
            if dico[p['ip'].src][0] == 50:
                print("SCAN!!!!!")

        
    
