import pyshark

file = pyshark.FileCapture("03.pcap")

i = 1
for p in file:
    if (i==150652):
        print(p.tcp.flags.raw_value)
    i+=1
