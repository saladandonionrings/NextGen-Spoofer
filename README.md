# NEXTGEN SPOOFER
![logo](https://user-images.githubusercontent.com/61053314/132832369-540ded53-8aff-4ea7-bcd6-70dbe7109c1a.png)

![PyPI - Python Version](https://img.shields.io/pypi/pyversions/3?style=flat-square)

🥑 A Python ARP and DNS Spoofer CLI and INTERFACE 🥓

#### CLI -> advanced pentesters
#### INTERFACE -> beginners

### Recommanded to run it on Debian 10

# SetUp
##### Make sure you installed Python/Python3
##### Please, install netfilterqueue and scapy as prerequisites

# ARP Spoof 💈
## CLI
		python arp_spoof_nxgenspf.py [-s] [-a]
    
### WARNING : You cannot use both !
[-s] : single target

[-a] : all network is targeted

#### Please, know the IP ADDRESSE(S) of the network/victim you want to attack.


## INTERFACE
#### Example:
		interface = eno1
		@IP TARGET = 192.168.10.9
		
		
# DNS SPOOF 🍔
#### PLS, USE IT RIGHT AFTER YOU LAUNCHED ARP SPOOF
## CLI
	"www." are not ALWAYS useful for the domain name.
	You can edit the file to spoof any domain you want.
## INTERFACE
#### Example
	DNS NAME = google.com
	DNS @IP = <your malicious web server> 
## Contributors 🛹
![GitHub contributors](https://img.shields.io/github/contributors/saladandonionrings/nextgen_spoofer?style=flat-square)

