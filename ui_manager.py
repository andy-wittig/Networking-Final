#Tkinter Libraries
import tkinter as tk
from tkinter import font
import tkinter.scrolledtext as tkst
#Matplotlib Libraries
import matplotlib.pyplot as plt
from matplotlib.figure import Figure
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
#Mapping Libraries
from geolocator import Geolocator
import smopy
#Math Libraries
import numpy as np
#Networking Libraries
from trace_route import Traceroute

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
        self.buttonFont = font.Font(family = "Cascadia Code", size = 14, weight = "bold")
        self.textFont = font.Font(family = "Cascadia Code", size = 14)
        #---------------------

        #---Initialize Tkinter Window---
        self.root.title(applicationName)
        self.root.geometry(f"{defaultSize[0]}x{defaultSize[1]}")
        self.root.configure(bg = self.bgColor)

        self.SetupMapFrame()
        #-------------------------------

    def SetupMapFrame(self):
        self.mapFrame = tk.Frame(self.root, bg = self.bgColor)
        self.mapFrame.pack(anchor = tk.CENTER, fill = "y", expand = True, padx = 10, pady = 10)

        #---Submit IP Address Frame---
        self.submitFrame = tk.Frame(self.root, bg = self.bgColor)
        self.submitFrame.pack(anchor = tk.CENTER, padx = 10, pady = 10)

        self.entryBox = tk.Entry(self.submitFrame, bg = self.elementColor, fg = self.textColor, font = self.textFont)
        self.entryBox.pack(side = "left")
        self.entryBox.insert(0, "23.120.107.159")

        self.submitButton = tk.Button(self.submitFrame, text = "Submit",
                                      bg = self.elementColor, fg = self.textColor, font = self.buttonFont,
                                      command = lambda: self.SubmitButton())
        self.submitButton.pack(side = "right")
        #------------------------------

        #---Display Traceroute Printout---
        self.scrollText = tkst.ScrolledText(self.root, bg = self.panelColor, fg = self.textColor, font = self.textFont)
        self.scrollText.pack(fill = "both", expand = True, padx = 10, pady = 10)
        self.scrollText.configure(state = "disabled")
        #---------------------------------

    def PrintLine(self, text):
        self.scrollText.configure(state = "normal")
        self.scrollText.insert(tk.END, text)
        self.scrollText.configure(state = "disabled")
        
    def SubmitButton(self):
        self.scrollText.configure(state='normal')
        self.scrollText.delete("1.0", tk.END)
        self.scrollText.configure(state='disabled')
        dest = self.entryBox.get()

        tr = Traceroute(self.PrintLine, dest)
        addressList = tr.GetAddresses()
        if (addressList == []): return

        points = []
        for address in addressList:
            locator = Geolocator()
            locationInformation = (locator.GetLocationInformation(address))
            if (locationInformation['IPv4'] == 'Not found'): continue
            
            lon, lat = locationInformation['longitude'], locationInformation['latitude']
            points.append([lon, lat])

        self.RenderPointsToMap(points)

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
        ax.imshow(img)
        ax.scatter(xPx, yPx, c = self.highlightRedColor, s = 40) #c: color, s: size of point

        #Convert matplotlib plot to tkinter canvas
        self.ClearFrame(self.mapFrame)
        canvas = FigureCanvasTkAgg(fig, master = self.mapFrame)
        canvas.draw()
        canvas.get_tk_widget().pack(fill = tk.BOTH, expand = True)
