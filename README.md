# NEXTGEN SPOOFER
![logo](https://user-images.githubusercontent.com/61053314/132832369-540ded53-8aff-4ea7-bcd6-70dbe7109c1a.png)

![PyPI - Python Version](https://img.shields.io/pypi/pyversions/3?style=flat-square)

🥑 A Python ARP and DNS Spoofer CLI and INTERFACE 🥓

#### CLI 🠮 advanced pentesters
#### INTERFACE 🠮 beginners



# SetUp
#### Recommanded to run it on Debian 10
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
#### One target : 
![image](https://user-images.githubusercontent.com/61053314/135092929-215ff14a-efde-4b3d-ba2d-626e6969eaa5.png)

#### All network is targeted : 
![image](https://user-images.githubusercontent.com/61053314/135093020-8ef53716-0be0-4390-bcf1-d27013cf9c47.png)

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
![image](https://user-images.githubusercontent.com/61053314/135093120-b8b36176-fc22-496e-8b93-061b2518dc4f.png)

	DNS NAME = google.com
	DNS @IP = <your malicious web server> 
	
## ABOUT
![image](https://user-images.githubusercontent.com/61053314/135092217-d70b029e-c62c-4fdf-8bc5-95cc09f1c019.png)
## Contributors 🛹
![GitHub contributors](https://img.shields.io/github/contributors/saladandonionrings/nextgen_spoofer?style=flat-square)

