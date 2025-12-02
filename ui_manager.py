#Tkinter Libraries
import tkinter as tk
from tkinter import font
import tkinter.scrolledtext as tkst
#Matplotlib Libraries
import matplotlib.pyplot as plt
from matplotlib.figure import Figure
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.backends.backend_tkagg import NavigationToolbar2Tk
#Mapping Libraries
from geolocator import Geolocator
import smopy
#Math Libraries
import numpy as np
import random
import time
#Networking Libraries
from trace_route import Traceroute
from sniffer import NetworkSniffer
import threading

class UIManager():
    def __init__(self):
        self.root = tk.Tk()

        #---Style Variables---
        applicationName = "Traceroute Geolocator"
        defaultSize = [1280, 720]
        #Global Color Scheme
        self.bgColor      = "#3D3D3D"
        self.highlightRedColor = "#B22222"
        self.highlightGreenColor = "#14d203"
        self.accentColor = "#536878"
        self.titleColor = "#6e7f80"
        self.panelColor   = "#666666"
        self.elementColor = "#898989"
        self.textColor    = "#E0E0E0"
        #Fonts
        self.buttonFont = font.Font(family = "Cascadia Code", size = 12, weight = "bold")
        self.textFont = font.Font(family = "Cascadia Code", size = 14)
        #---------------------

        #---Initialize Tkinter Window---
        self.root.title(applicationName)
        self.root.geometry(f"{defaultSize[0]}x{defaultSize[1]}")
        self.root.configure(bg = self.bgColor)

        self.SetupWidgets()
        #-------------------------------

        #--Variables for Sniffer---
        self.sniffedDests = []
        #--------------------------=

    def SetupWidgets(self):
        self.root.columnconfigure(0, weight = 1)
        self.root.rowconfigure(0, weight = 1)
        self.root.rowconfigure(1, weight = 1)
        self.root.rowconfigure(2, weight = 1)

        self.mapFrame = tk.Frame(self.root, bg = self.bgColor)
        self.mapFrame.grid(row = 0, column = 0, sticky="nsew", padx = 10, pady = 10)

        self.optionsFrame = tk.Frame(self.root, bg = self.panelColor)
        self.optionsFrame.grid(row = 1, column = 0, padx = 10, pady = 10)

        #---Submit IP Address Frame---
        self.submitFrame = tk.Frame(self.optionsFrame, bg = self.bgColor)
        self.submitFrame.pack(side = "left", padx = 10, pady = 10)

        self.traceLabel = tk.Label(self.submitFrame, bg = self.bgColor, fg = self.textColor, font = self.textFont, text = "Trace Route:")
        self.traceLabel.grid(row = 0, column = 0)

        self.entryBox = tk.Entry(self.submitFrame, bg = self.panelColor, fg = self.textColor, font = self.textFont)
        self.entryBox.grid(row = 0, column = 1)
        self.entryBox.insert(0, "Enter destination")

        self.submitButton = tk.Button(self.submitFrame, text = "Submit",
                                      bg = self.accentColor, fg = self.textColor, font = self.buttonFont,
                                      command = lambda: self.SubmitButton())
        self.submitButton.grid(row = 0, column = 2)

        #---Sniffing---
        self.sniffFrame = tk.Frame(self.optionsFrame, bg = self.bgColor)
        self.sniffFrame.pack(side = "left", padx = 10, pady = 10)

        self.sniffLabel = tk.Label(self.sniffFrame, bg = self.bgColor, fg = self.textColor, font = self.textFont, text = "# of Packets:")
        self.sniffLabel.grid(row = 0, column = 0)

        self.sniffCount = tk.Spinbox(self.sniffFrame, from_ = 0, to = 100,
                                     bg = self.panelColor, fg = self.textColor, font = self.textFont)
        self.sniffCount.grid(row = 0, column = 1)

        self.sniffButton = tk.Button(self.sniffFrame, text = 'Sniff Network',
                                      bg = self.accentColor, fg = self.textColor, font = self.buttonFont,
                                      command = lambda: self.SniffButton())
        self.sniffButton.grid(row = 0, column = 2, sticky = "w")

        self.traceButton = tk.Button(self.sniffFrame, text = 'Trace Sniffed Packet Destinations',
                                      bg = self.accentColor, fg = self.textColor, font = self.buttonFont,
                                      command = lambda: self.TraceSniffedPackets())
        self.traceButton.grid(row = 1, column = 2)

        #---Display Traceroute Printout---
        self.scrollText = tkst.ScrolledText(self.root, bg = self.panelColor, fg = self.textColor, font = self.textFont, height = 10)
        self.scrollText.grid(row = 2, column = 0, sticky="nsew", padx = 10, pady = 10)
        self.scrollText.configure(state = "disabled")

    def PrintLine(self, text):
        self.scrollText.configure(state = "normal")
        self.scrollText.insert(tk.END, text)
        self.scrollText.configure(state = "disabled")
        self.scrollText.see(tk.END)

    def TraceSniffedPackets(self):
        def worker():
            if (len(self.sniffedDests) < 1): return #No sniffing results have been generated yet

            addressList = []
            for dest in self.sniffedDests:
                if (dest == "255.255.255.255"): continue #Skip broadcasts

                tr = Traceroute(self.PrintLine, dest)
                while (tr.IsThreadActive()):
                    time.sleep(0.01) 

                addresses = tr.GetAddresses()
                
                if (len(addresses) < 1): continue
                addressList.append(addresses)

            pointGroups = []
            for index, addressGroup in enumerate(addressList):
                self.PrintLine(f"Geographic Iteration: {index}\n") #TODO: Find message to display that is more informative!
                points = []
                for address in addressGroup:
                    locator = Geolocator(self.PrintLine)
                    locationInformation = (locator.GetLocationInformation(address))
                    if (locationInformation['status'] == 'fail'): continue

                    lon, lat = locationInformation['lon'], locationInformation['lat']
                    points.append([lon, lat])
                pointGroups.append(points)
                time.sleep(1.5) #Sleep to avoid overloading server with requests

            self.RenderPointGroupsToMap(pointGroups)
    
        threading.Thread(target = worker, daemon = True).start()
        
    def SniffButton(self):
        count = int(self.sniffCount.get())
        sniffer = NetworkSniffer(self.PrintLine, count)
        self.sniffedDests = sniffer.GetDestinations()
        
    def SubmitButton(self):
        def worker():
            #self.scrollText.configure(state='normal')
            #self.scrollText.delete("1.0", tk.END)
            #self.scrollText.configure(state='disabled')
            dest = self.entryBox.get()

            tr = Traceroute(self.PrintLine, dest)
            while (tr.IsThreadActive()):
                time.sleep(0.01) 
            
            addressList = tr.GetAddresses()
            if (addressList == []): return

            points = []
            for address in addressList:
                locator = Geolocator(self.PrintLine)
                locationInformation = (locator.GetLocationInformation(address))
                if (locationInformation['status'] == 'fail'): continue
                lon, lat = locationInformation['lon'], locationInformation['lat']
                points.append([lon, lat])

            if (points == []): return
            self.RenderPointsToMap(points)
        threading.Thread(target = worker, daemon = True).start()

    def ClearFrame(self, frame):
        for widget in frame.winfo_children():
            widget.destroy()

    def RenderPointsToMap(self, points): #points[lon, lat]
        #Generate map image around points
        points = np.array(points)
        lonMin, lonMax = points[:, 0].min(), points[:, 0].max()
        latMin, latMax = points[:, 1].min(), points[:, 1].max()
        bounds = (
            latMin, lonMin,
            latMax, lonMax
        )
        
        map = smopy.Map(bounds)
        xPx, yPx = map.to_pixels(points[:, 1], points[:, 0]) #point in form (lat, lon)
       
        fig, ax = plt.subplots()
        img = map.to_pil()

        #Setup plot for map and points
        fig.set_facecolor(self.panelColor)
        fig.tight_layout(pad = 0)
        ax.set_axis_off()
        ax.imshow(img)

        ax.scatter(xPx, yPx, c = self.highlightRedColor, s = 40) #c: color, s: size of point
        ax.plot(xPx, yPx, c = self.highlightGreenColor, linewidth = 2)

        #Convert matplotlib plot to tkinter canvas
        self.ClearFrame(self.mapFrame)
        canvas = FigureCanvasTkAgg(fig, master = self.mapFrame)
        canvas.draw()
        canvas.get_tk_widget().pack(fill = tk.BOTH, expand = True)

        toolbar = NavigationToolbar2Tk(canvas, self.mapFrame)
        toolbar.update()
        toolbar.pack(fill = "x")

    def RenderPointGroupsToMap(self, pointGroups): #[points[lon, lat], ...]
        print (pointGroups)
        #Generate map image around points
        flatPointsList = []
        for points in pointGroups:
            for point in points:
                flatPointsList.append(point)

        npPoints = np.array(flatPointsList)
        lonMin, lonMax = npPoints[:, 0].min(), npPoints[:, 0].max()
        latMin, latMax = npPoints[:, 1].min(), npPoints[:, 1].max()
        bounds = (
            latMin, lonMin,
            latMax, lonMax
        )
        
        map = smopy.Map(bounds)
       
        fig, ax = plt.subplots()
        img = map.to_pil()

        #Setup plot for map and points
        fig.set_facecolor(self.panelColor)
        fig.tight_layout(pad = 0)
        ax.set_axis_off()
        ax.imshow(img)

        for points in pointGroups:
            if (len(points) < 1): continue

            points = np.array(points)
            xPx, yPx = map.to_pixels(points[:, 1], points[:, 0]) #point in form (lat, lon)

            r = random.randint(0, 255) / 255
            g = random.randint(0, 255) / 255
            b = random.randint(0, 255) / 255
            randColor = (r, g, b)

            ax.scatter(xPx, yPx, c = randColor, s = 40)
            ax.plot(xPx, yPx, c = randColor, linewidth = 2)

        #Convert matplotlib plot to tkinter canvas
        self.ClearFrame(self.mapFrame)
        canvas = FigureCanvasTkAgg(fig, master = self.mapFrame)
        canvas.draw()
        canvas.get_tk_widget().pack(fill = tk.BOTH, expand = True)

        toolbar = NavigationToolbar2Tk(canvas, self.mapFrame)
        toolbar.update()
        toolbar.pack(fill = "x")
