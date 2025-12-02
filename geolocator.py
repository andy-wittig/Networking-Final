#---HTTPS Libraries---
import requests
#---------------------------

class Geolocator():
    def __init__(self, callback):
        self.OutputCallback = callback

    def GetLocationInformation(self, ipv4Address):
        try:
            response = requests.get(f"https://ip-api.com/json/{ipv4Address}", timeout = 5).json()
        except requests.RequestException as e:
            self.OutputCallback(f"Error locating {ipv4Address:<15}: {e}\n")
            return {'status': 'fail'}
        
        if (response['status'] == 'fail'):
            self.OutputCallback(f"Locating address: {ipv4Address:<15}    "
                                f"Status: {response['status']}    "
                                f"Message: {response['message']}\n")
        else:
            self.OutputCallback(f"Locating address: {ipv4Address:<15}    "
                                f"Status: {response['status']}    "
                                f"Area: {response['regionName']}, {response['city']}    "    
                                f"ISP: {response['isp']}\n")
        return response
