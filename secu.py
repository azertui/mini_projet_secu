import pyshark
file = pyshark.FileCapture('03.pcap')

dico = {}
used_ports = []
requests = 0
time = 0

for p in file:
    dico[p['ip'].src] = ()
