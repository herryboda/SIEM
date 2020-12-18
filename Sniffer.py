from scapy.all import *
from datetime import datetime

# Getting all interfaces
def getInterfaces():
    """returns a list of available network interfaces"""
    interfaces = []
    for iface_name in sorted(ifaces.data.keys()):
        dev = ifaces.data[iface_name]
        i = str(dev.name).ljust(4)
        interfaces.append(i)
    return interfaces

# Sniffing network packets
def sniffPackets(f):
    print ("SNIFFER STARTED...")
    prn_func = packet2log_with_f(f)
    sniff(iface='Broadcom 802.11n Network Adapter',
                    prn=prn_func,
                    lfilter=lambda pkt: (IP in pkt) and (TCP in pkt))

def packet2log_with_f(f):
    def packet2Log(packet):
        pkt_time = str(datetime.now()).split('.')[0]
        log_line = "{} {} {} {} {}".format(pkt_time,
                                         packet[IP].src,
                                         packet[IP].dst,
                                         packet[TCP].dport,
                                         "PASS")
        print("SNIFFED: {}".format(log_line))
        f.write(log_line + "\n")
        f.flush()
    return packet2Log

# log2File(r'C:\Users\Owner\PycharmProjects\SIEM\Sniff_Log.txt')
# print  getInterfaces()