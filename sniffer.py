#---Libraries---
from scapy.all import *
import threading
#--------------------------

class NetworkSniffer():
    def __init__(self, callback, count = 0):
        self.OutputCallback = callback
        self.destList = []
        self.srcList = []
        self.count = count

        #Runs on seperate thread so UI doesn't freeze
        if (count < 1): #Async sniffing
            thread = threading.Thread(target = self.RunAsyncSniffer) 
            thread.daemon = True
            thread.start()
        else: #Sniff n packets
            thread = threading.Thread(target = self.RunSniffer)
            thread.daemon = True
            thread.start()
    
    def RunAsyncSniffer(self):
        self.OutputCallback("Running packet sniffer for 10 seconds...\n")
        capture = AsyncSniffer(filter = "ip", prn = self.packetCallback)
        capture.start()
        time.sleep(10)
        capture.stop()
        self.OutputCallback("Sniffing complete.\n")

    def RunSniffer(self):
        self.OutputCallback(f"Running packet sniffer for {self.count} count(s):\n")
        capture = sniff(filter = "ip", prn = self.packetCallback, count = self.count)

    def packetCallback(self, packet):
        #Process the sniffed packets
        if (packet.haslayer(IP)):
            sourceIP = packet[IP].src
            destinationIP = packet[IP].dst

            self.srcList.append(sourceIP)
            self.destList.append(destinationIP)

            self.OutputCallback(f"Source: {sourceIP:<15} --> Destination: {destinationIP}\n")

    def GetSources(self): return self.srcList
    def GetDestinations(self): return self.destList