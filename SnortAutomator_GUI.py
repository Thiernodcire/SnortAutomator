#Import Statements
import tkinter as tk
from tkinter import Button, Label, OptionMenu, Place, StringVar, Toplevel, filedialog
from tkinter import font
from tkinter.constants import GROOVE, SUNKEN
import tkinter.messagebox as tkMessageBox
from typing import Text
import SnortAutomator_backend as sab

#Set variables for the characteristics of GUI interface
Height = 500
Width = 500
#Test Function
def hello_world():
    tkMessageBox.showinfo('Hello World', 'Hello World')
#Function to upload pcap file
def upload_pcap():
    pcap = filedialog.askopenfile(initialdir="/", title='Select File',filetypes = (("All","*.pcap *.pcapng"),("pcap files","*.pcap"),("pcapng files","*.pcapng")))
    label = tk.Label(lower_frame, text='Upload Complete' + str(pcap),anchor='nw', justify='left', bd=4)
    label.place(relwidth=1, relheight=1)
#Create a function to allow the user to get options for the live capture
def live_capture_options():
    interface_options = StringVar()
    interface_options.set('Interface options')
    top = Toplevel()
    top.title("Interface Options")
    top.geometry("%dx%d%+d%+d" % (300, 200, 250, 125))
    drop_menu = OptionMenu(top, interface_options,"option_1", "option_2")
    drop_menu.pack(pady=20)
    exit_button = Button(top, text='Exit Program',command=top.destroy)
    exit_button.pack()
    global chosen_interface 
    chosen_interface = interface_options.get()
#Create a function for the create_rules button
def baseline_options():
    top = Toplevel()
    top.title('Baseline')
    top.geometry("%dx%d%+d%+d" % (350, 250, 250, 125))
    instrc = tk.Label(top, text='Enter the IP address that are vaild on your network')
    instrc.pack()
    entry = tk.Text(top,relief=GROOVE,borderwidth=2)
    entry.place(relx=0.2, rely=0.1, relwidth= .5, relheight=.71)
    start_button = tk.Button(top, text='Create Snort Rules')
    start_button.place(relx= .25, rely= .8, relwidth= .4, relheight=.09, command=lambda:sab.compare_traffic(entry.get()))
    exit_button = tk.Button(top, text='Exit Program', command=top.destroy)
    exit_button.place(relx= .3, rely= .9, relheight= .09 , relwidth=.3)
#Create a fucntion for the save button
def save_file():
    reponse = tkMessageBox.showerror('Error', "There are no rules to save")
#Create the root base for the GUI
root = tk.Tk()

#Set a specfic font size
myFont= font.Font(family='Academy Engraved LET',size='30',weight='bold')
#Create a canvas layer to place on top of the base
canvas = tk.Canvas(root, height=Height, width=Width)
canvas.pack()

#Create a backgroud so programe can look cool
backgroud_label = tk.Label(root, bg ='black',)
backgroud_label.place(relwidth= 1 , relheight= 1)

#Create a Frame to place the buttons, label and textbox on
frame = tk.Frame(root,  bg='#42c2f4', bd=5)
frame.place(relx=0.5, rely=0.15, relwidth=0.86, relheight=.79, anchor='n')

#Create a label for the app
title_label = tk.Label(root,text= 'Snort Automtor', bg='white')
title_label['font']= myFont
title_label.place(rely= .02 ,relx= .5, relwidth= .6, relheight= .1, anchor= 'n')

#Create an Upload  button for pcap uploads
upload_button = tk.Button(frame, text='Upload', command=lambda:upload_pcap())
upload_button.place(relx=.05, relheight= .10, relwidth=.25)

#Create a create rules button to be a to create rules
create_rules_button = tk.Button(frame, text='Create Rules',command=lambda:baseline_options())
create_rules_button.place(relx= .38, relheight= .10 , relwidth=.25)

#Create a live capture button to capture live traffic
live_Capture_button = tk.Button(frame, text='Live Capture',command=lambda:live_capture_options())
live_Capture_button.place(relx = .7, relheight= .10, relwidth=.25)

#Create a save button to save rules
save_button = tk.Button(frame, text = 'Save', command= lambda: save_file())
save_button.place(relx= .7 , rely = .91 , relheight= .08, relwidth= .20)

#Create a lower frame that takes text
lower_frame = tk.Frame(frame, bg="white")
lower_frame.place(relx= .082 , rely= .11 , relheight= .79, relwidth=.82)


root.mainloop()
