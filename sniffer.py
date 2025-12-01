#---Networking Libraries---
from scapy.all import *
#--------------------------

class NetworkSniffer():
    def __init__(self, callback, count = 0):
        self.OutputCallback = callback
        if (count < 1): #Indefinite sniffing
            capture = sniff(filter = "ip", prn = self.packetCallback)
        else:
            capture = sniff(filter = "ip", prn = self.packetCallback, count = count)

    def packetCallback(self, packet):
        #Process the sniffed packets
        if (packet.haslayer(IP)):
            sourceIP = packet[IP].src
            destinationIP = packet[IP].dst
            self.OutputCallback(f"Source: {sourceIP} --> Destination: {destinationIP}\n")