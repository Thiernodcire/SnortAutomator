#Import Statements
import tkinter as tk
from tkinter import filedialog
from tkinter import font
import tkinter.messagebox as tkMessageBox

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

#Create a fucntion for teh save button
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
create_rules_button = tk.Button(frame, text='Create Rules')
create_rules_button.place(relx= .38, relheight= .10 , relwidth=.25)

#Create a live capture button to capture live traffic
live_Capture_button = tk.Button(frame, text='Live Capture',)
live_Capture_button.place(relx = .7, relheight= .10, relwidth=.25)

#Create a save button to save rules
save_button = tk.Button(frame, text = 'Save', command= lambda: save_file())
save_button.place(relx= .7 , rely = .91 , relheight= .08, relwidth= .20)

#Create a lower frame that takes text
lower_frame = tk.Frame(frame, bg="white")
lower_frame.place(relx= .082 , rely= .11 , relheight= .79, relwidth=.82)


root.mainloop()
