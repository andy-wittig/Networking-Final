#---Geolocation Libraries---
import requests
#---------------------------

import string

class Geolocator():
    def __init__(self):
        pass

    def GetLocationInformation(self, ipv4Address):
        # Source - https://stackoverflow.com/a
        # Posted by Bilguun
        # Retrieved 2025-11-30, License - CC BY-SA 4.0
        response = requests.get(f"https://geolocation-db.com/json/{ipv4Address}&position=true").json()
        return response
