#!/usr/bin/env python3 
from PIL import Image as Im
from PIL import ImageTk
#Import Statements
import tkinter as tk
from tkinter import Button, Image, Label, OptionMenu, Place, StringVar, Toplevel, filedialog , ttk
from tkinter import font
from tkinter.constants import GROOVE, SUNKEN
import tkinter.messagebox as tkMessageBox
from typing import Text
import pyshark as py
import re
src_dictionary = {}
dst_dictionary = {}
snort_rule_list = []
pcap_file = ''
interfaces = ['eth0', 'any', 'lo']
seconds = [ 20 , 30 , 40 , 50 , 60]

#Set variables for the characteristics of GUI interface
Height = 500
Width = 500
#Test Function
def hello_world():
    tkMessageBox.showinfo('Hello World', 'Hello World')
#Function to upload pcap file
def upload_pcap():
    pcap_file = filedialog.askopenfilename(initialdir="/", title='Select File',filetypes = (("All","*.pcap *.pcapng"),("pcap files","*.pcap"),("pcapng files","*.pcapng")))
    pcap_capture(pcap_file)
    label = tk.Label(lower_frame, text='Upload Complete',anchor='nw', justify='left', bd=4, font=('Sans', 9))
    label.config(background='#201D1C',foreground='white')
    label.place(relwidth=1, relheight=1)
#Create a function to allow the user to get options for the live capture
def live_capture_options():
    timeout_options = StringVar()
    timeout_options.set('Timeout options in seconds')
    interface_options = StringVar()
    interface_options.set('Interface options')
    top = Toplevel()
    top.title("Interface Options")
    top.geometry("%dx%d%+d%+d" % (300, 200, 250, 125))
    drop_menu = OptionMenu(top, interface_options,*interfaces)
    drop_menu.pack(pady=5)
    drop_menu_1 = OptionMenu(top, timeout_options, *seconds )
    drop_menu_1.pack(pady=10)
    activate_button = Button(top, text='Start Live Capture', command=lambda:live_capture(timeout_options.get(),interface_options.get()))
    activate_button.pack()
    exit_button = Button(top, text='Exit Program',command=top.destroy)
    exit_button.pack()
    global chosen_interface 
    chosen_interface = interface_options.get()
#Create a function for the create_rules button
def baseline_options():
    top = Toplevel()
    top.title('Baseline')
    top.geometry("%dx%d%+d%+d" % (350, 250, 250, 125))
    instrc = tk.Label(top, text='Enter the IP address that are vaild on your network', font=('Sans', 9))
    instrc.pack()
    entry = tk.Text(top,relief=GROOVE,borderwidth=2)
    entry.config(background='#201D1C',foreground='white')
    entry.place(relx=0.2, rely=0.1, relwidth= .5, relheight=.71)
    start_button = tk.Button(top, text='Create Snort Rules',command= lambda:compare_traffic(entry.get('1.0', 'end')),font=('Sans', 9))
    start_button.place(relx= .25, rely= .8, relwidth= .4, relheight=.09)
    exit_button = tk.Button(top, text='Exit Program',command=top.destroy, font=('Sans', 9))
    exit_button.place(relx= .3, rely= .9, relheight= .09 , relwidth=.3)
#Create a fucntion for the save button
def save_file(file_rules_set):
    if file_rules_set == '':
        reponse = tkMessageBox.showerror('Error', "There are no rules to save")
    else:
        file = filedialog.asksaveasfile(defaultextension='.txt',filetypes=[
                                        ("Text file",".txt"),
                                        ("HTML file", ".html"),
                                        ("All files", ".*"), ]) 
    if file is None:
        return
    else:
        file.write(file_rules_set)
        file.close()
    exit()
def errors(error_number):
    if error_number == 0:
        response = tkMessageBox.showerror('Error','You entered the IP addresses wrong!')
    elif error_number == 1 :
        response = tkMessageBox.showerror('Error', 'You didn\'t upload a pcap file!')
    elif error_number == 2:
        response = tkMessageBox.showerror('Error', 'You have already uploaded a pcap file!')
    elif error_number == 3:
        response = tkMessageBox.showerror('Error', 'You have no traffic to check')
def pcap_capture(pcap):
    if pcap != '':
        cap = py.FileCapture(pcap)
        for pack in cap:
            try:
                ip_src = pack.ip.src
                ip_dst = pack.ip.dst
                src_port = pack.tcp.srcport
                dst_port = pack.tcp.dstport
            except:
                arp_traffic = pack
            src_dictionary[ip_src] = src_port
            dst_dictionary[ip_dst] = dst_port
    else:
        errors(1)
def live_capture(timeout_n,interface_c):
    print('He')
    if not src_dictionary and not dst_dictionary:
        capture = py.LiveCapture(interface=interface_c)
        capture.sniff(timeout=int(timeout_n))
        for pack in capture.sniff_continuously(packet_count=10):
            try:
                ip_src = pack.ip.src
                ip_dst = pack.ip.dst
                src_port = pack.tcp.srcport
                dst_port = pack.tcp.dstport
            except:
                arp_traffic = pack
            src_dictionary[ip_src] = src_port
            dst_dictionary[ip_dst] = dst_port
    else:
        errors(2)
def compare_traffic(whitelist_ip):
    if src_dictionary and dst_dictionary:
        src_dictionary_list = list(src_dictionary.keys())
        dst_dictionnary_list = list(dst_dictionary.keys())
        regex_ip = re.compile('([0-9]{1,3}\.){3}[0-9]{1,3}')
        whitelist_match = regex_ip.match(whitelist_ip)
        if whitelist_match:
            for idx, ip in enumerate(src_dictionary.keys()):
                if ip not in whitelist_ip:
                    snort_rule = 'alert tcp {bad_src_ip} {bad_src_port} -> {bad_dst_ip} {bad_dst_port}'
                    snort_rule_list.append(snort_rule.format(bad_src_ip=ip,bad_src_port=src_dictionary[ip],bad_dst_ip=dst_dictionnary_list[idx],bad_dst_port=dst_dictionary[dst_dictionnary_list[idx]]))
            rule_generator(snort_rule_list)
        else:
            errors(0)
    else:
        errors(3)
def rule_generator(rules):
    array = []
    sid = 1000000
    output = ''
    for widget in lower_frame.winfo_children():
        widget.destroy()
    for snort_rules in rules:
        sid += 1
        output += snort_rules + '\n' + f'(msg:\'IP address may be malicious attacker\', {sid} )' + '\n'
    label_rules = tk.Label(lower_frame, text=f'Snort Rulez\n{output}', anchor='nw', justify='left', bd=4, font= ('Arial', 10))
    label_rules.config(background='#201D1C',foreground='white')
    label_rules.place(relheight=1,relwidth=1)
    file_rules.set(output)
#Create the root base for the GUI
root = tk.Tk()
file_rules = StringVar()

#Set a specfic font size
myFont= font.Font(family='Sans',size='30',weight='bold')
#Create a canvas layer to place on top of the base
canvas = tk.Canvas(root, height=Height, width=Width)
canvas.pack()

#Create a backgroud so programe can look cool
image = Im.open("SnortAutoBackground.jpeg")
backgroud_image = ImageTk.PhotoImage(image)
backgroud_label = tk.Label(root,image=backgroud_image)
backgroud_label.place(relwidth= 1 , relheight= 1)

#Create a Frame to place the buttons, label and textbox on
frame = tk.Frame(root,  bg='#201D1C', bd=5)
frame.place(relx=0.5, rely=0.15, relwidth=0.86, relheight=.79, anchor='n')

#Create a label for the app
title_label = tk.Label(root,text= 'Snort Automator', bg='#201D1C', font=('Sans', 21))
title_label.config(foreground='white')
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


#Create a lower frame that takes text
lower_frame = tk.Frame(frame, bg="#201D1C")
lower_frame.place(relx= .082 , rely= .11 , relheight= .79, relwidth=.82)

#Create a save button to save rules
save_button = tk.Button(frame, text = 'Save', command= lambda: save_file(file_rules.get()))
save_button.place(relx= .7 , rely = .91 , relheight= .08, relwidth= .20)

#Create a exit program program button
exit_program_button = tk.Button(frame, text= 'Exit Program', command=exit)
exit_program_button.place(relx= .38, rely = .91 , relheight= .08, relwidth= .20)

#Create a button that detects nmap scans
nmap_button = tk.Button(frame, text='Nmap Detector',)
nmap_button.place(relx=.05, rely = .91 , relheight= .08, relwidth= .24)


root.mainloop()
