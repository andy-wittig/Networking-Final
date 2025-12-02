#---Libraries---
import socket
import struct
import time
from scapy.all import *
import argparse
import threading
#--------------------------

class Traceroute():
    def __init__(self, callback, destination, maxHops = 30, timeout = 2):
        self.OutputCallback = callback
        self.addresses = []

        try: #Resolve the destination host to IP address using DNS
            destinationIP = socket.gethostbyname(destination)
        except socket.gaierror:
            self.OutputCallback(f"Cannot resolve host: {destination}\n")
            return
        
        self.thread = threading.Thread(target = self.RunTraceRoute,
                                  args = (destination, destinationIP, maxHops, timeout)) #Runs on seperate thread so UI doesn't freeze
        self.thread.daemon = True
        self.thread.start()

    def IsThreadActive(self):
        return self.thread.is_alive()

    def RunTraceRoute(self, dest, destIP, maxHops, timeout):
        port = 33434 #Default port for traceroute
        ttl = 1
        
        self.OutputCallback(f"Running trace route for address: {destIP}\n")
        while True:
            ipPacket = IP(dst = dest, ttl = ttl)
            udpPacket = UDP(dport = port)

            packet = ipPacket / udpPacket #Combine headers

            startTime = time.time()
            reply = sr1(packet, timeout = timeout, verbose = 0) #Send packet and recieve reply
            endTime = time.time()

            if (reply is None):
                self.OutputCallback(f"{ttl:<3}    * Request timed out.\n")
            elif (reply.haslayer(ICMP)):
                icmpType = reply.getlayer(ICMP).type
                icmpCode = reply.getlayer(ICMP).code

                if (icmpType == 11): #Intermediate router
                    rtt = (endTime - startTime) * 1000
                    self.OutputCallback(f"{ttl:<3}    {reply.src:<15}    {rtt:.2f} ms    TTL expired\n")
                    self.addresses.append(reply.src)
                elif (icmpType == 3 and icmpCode == 3): #Destination reached
                    rtt = (endTime - startTime) * 1000
                    self.OutputCallback(f"{ttl:<3}    {reply.src:<15}    {rtt:.2f} ms    Destination reached\n")
                    self.addresses.append(reply.src)
                    self.OutputCallback("Route complete.\n")
                    break
                else:
                    rtt = (endTime - startTime) * 1000
                    self.OutputCallback(f"{ttl:<3}    {reply.src:<15}    {rtt:.2f} ms    ICMP type: {icmpType}, Code: {icmpCode}\n")
                    self.addresses.append(reply.src)
            else:
                rtt = (endTime - startTime) * 1000
                self.OutputCallback(f"{ttl:<3}    {reply.src:<15}    {rtt:.2f} ms    Unkown reply\n")
                self.addresses.append(reply.src)

            ttl += 1
            if (ttl >= maxHops):
                break


    def GetAddresses(self):
        return self.addresses
