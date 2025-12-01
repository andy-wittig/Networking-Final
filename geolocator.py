#---HTTPS Libraries---
import requests
#---------------------------

class Geolocator():
    def __init__(self):
        pass

    def GetLocationInformation(self, ipv4Address):
        response = requests.get(f"http://ip-api.com/json/{ipv4Address}").json()
        return response
