#---Networking Libraries---
from scapy.all import *
#--------------------------

class NetworkSniffer():
    def __init__(self, callback, count = 0):
        self.OutputCallback = callback
        self.destList = []
        self.srcList = []

        if (count < 1): #Async sniffing
            self.OutputCallback(f"Running packet sniffer for 20 seconds...\n")
            capture = AsyncSniffer(filter = "ip", prn = self.packetCallback)
            capture.start()
            time.sleep(20)
            capture.stop()
        else: #Sniff n packets
            self.OutputCallback(f"Running packet sniffer for {count} count(s):\n")
            capture = sniff(filter = "ip", prn = self.packetCallback, count = count)

    def packetCallback(self, packet):
        #Process the sniffed packets
        if (packet.haslayer(IP)):
            sourceIP = packet[IP].src
            destinationIP = packet[IP].dst

            self.srcList.append(sourceIP)
            self.destList.append(destinationIP)

            self.OutputCallback(f"Source: {sourceIP} --> Destination: {destinationIP}\n")

    def GetSources(self): return self.srcList
    def GetDestinations(self): return self.destList