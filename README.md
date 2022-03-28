<div align="center">
  <img alt="logo_nextgen_spoof" src="https://user-images.githubusercontent.com/61053314/132832369-540ded53-8aff-4ea7-bcd6-70dbe7109c1a.png" width="250" />
  <h1>🐱‍💻 Welcome to NextGenSpoofer </h1>
  <p>
    <img alt="Python Version" src="https://img.shields.io/pypi/pyversions/3?style=for-the-badge" />
  </p>
🐍 Python ARP and DNS Spoofer tool
<p> 💻 CLI & Interface </p>
</div>

# ⚙️ SetUp 
#### 🍀 Recommanded to run it on Debian 10 / Kali
##### 📢 Make sure you installed Python/Python3
##### 📢 Please, install *netfilterqueue* and *scapy* as prerequisites :

	apt-get update

	# NETFILTERQUEUE INSTALLATION
	apt-get install build-essential python-dev libnetfilter-queue-dev
	
	# OR :
	pip install NetfilterQueue
	
	# if errors, use this (works perfectly for Kali) :
	sudo pip3 install --upgrade -U git+https://github.com/kti/python-netfilterqueue
	
	# if bugs :
	pip install cython

	# SCAPY INSTALLATION
	pip install scapy


# 💈 ARP Spoof 
## #️⃣ CLI
		python arp_spoof_nxgenspf.py [-s] [-a]
		### ⚠️ WARNING : You cannot use both ! ⚠️
		[-s] : single target
		[-a] : all network is targeted
		
### Single target
https://user-images.githubusercontent.com/61053314/160422041-4de63d8b-7891-41b1-bc8d-aaf7493b0d00.mp4

### All network is targeted
https://user-images.githubusercontent.com/61053314/160422196-dcc8f15a-eac6-4c93-a5ae-f93215b7c124.mp4

#### 📢 PLS, know the IP ADDRESS of the network/victim you want to attack.

## 👨🏽‍💻 INTERFACE
	# you can run it as root ou non-root user
	# !!! Change iface name (line 29 in nextgen_spoofer.py) !!!
	xhost +
	python3 nextgen_spoofer.py
	
#### 1️⃣🎯 One target : 
![image](https://user-images.githubusercontent.com/61053314/135092929-215ff14a-efde-4b3d-ba2d-626e6969eaa5.png)

#### ♾️🎯 All network is targeted : 
![image](https://user-images.githubusercontent.com/61053314/135093020-8ef53716-0be0-4390-bcf1-d27013cf9c47.png)

		
# 🍔 DNS SPOOF 
#### 📢 USE IT RIGHT AFTER YOU LAUNCHED ARP SPOOF
## #️⃣ CLI
	python dns_spoof_nxgenspf.py
	
#### 📝 Note 
	"www." are not ALWAYS useful for the domain name.
	You can edit the file to spoof any domain you want.
	
## 👨🏽‍💻 INTERFACE
![image](https://user-images.githubusercontent.com/61053314/135093120-b8b36176-fc22-496e-8b93-061b2518dc4f.png)
#### Example
	DNS NAME = google.com
	DNS @IP = $malicious_server_ip
	
## 💭 ABOUT
![image](https://user-images.githubusercontent.com/61053314/135092217-d70b029e-c62c-4fdf-8bc5-95cc09f1c019.png)
## Contributors 🛹
![GitHub contributors](https://img.shields.io/github/contributors/saladandonionrings/nextgen_spoofer?style=flat-square)

