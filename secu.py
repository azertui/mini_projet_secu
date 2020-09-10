import pyshark
file = pyshark.FileCapture('03.pcap')

dico = dict()
# tuple (compteur,[ports],dernier_temps)
for p in file:
    #dico[p['ip'].src] = ()
    if hasattr(p,'icmp'):
        print('icmp')
        pass
    else if hasattr(p,'udp'):
        pass
    else if hasattr(p,'tcp'):
        print ('tcp')
        pass
