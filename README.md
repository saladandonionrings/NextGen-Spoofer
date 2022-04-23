<div align="center">
  <img alt="logo_nextgen_spoof" src="https://user-images.githubusercontent.com/61053314/132832369-540ded53-8aff-4ea7-bcd6-70dbe7109c1a.png" width="250" />
  <h1>🐱‍ Welcome to NextGenSpoofer </h1>
  <p>
    <img alt="Python Version" src="https://img.shields.io/badge/python-%3E%3D3.0-blue?style=for-the-badge" />
  </p>
🐍 Python ARP and DNS Spoofer tool
<p> 💻 CLI & Interface </p>
</div>

# ⚙️ SetUp 
#### 🍀 Recommanded to run it on Debian / Kali
##### 📢 Make sure you installed Python/Python3

	apt-get update

	# Prerequisites
	apt-get install build-essential python-dev libnetfilter-queue-dev
	
	pip install -r requirements.txt
	
	# if errors with Netfilterqueue, use this (works perfectly for debian/kali) :
	sudo pip3 install --upgrade -U git+https://github.com/kti/python-netfilterqueue


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

## 👨🏽‍💻 INTERFACE
	# you can run it as root ou non-root user
	xhost +
	python3 nextgen_spoofer.py
	
#### 1️⃣🎯 One target : 
![arp_one_spoof](https://user-images.githubusercontent.com/61053314/161270810-292725ba-2bb6-4fbb-a005-c98f340b46d2.png)

#### ♾️🎯 All network is targeted : 
https://user-images.githubusercontent.com/61053314/160906537-34b35d9e-a004-4bc5-a0bf-46c919643261.mp4

# 🍔 DNS SPOOF 
#### 📢 USE IT RIGHT AFTER YOU LAUNCHED ARP SPOOF
## #️⃣ CLI
	python dns_spoof_nxgenspf.py
	
#### 📝 Note 
	"www." are not ALWAYS useful for the domain name.
	You can edit the file to spoof any domain you want.
	
## 👨🏽‍💻 INTERFACE
![dns_int](https://user-images.githubusercontent.com/61053314/161272132-5e0a69c5-18fa-4e8a-a6f8-bf14f65cb15f.png)
#### Example
	DNS NAME = google.com
	DNS @IP = $malicious_server_ip
	
## 💭 ABOUT
![about](https://user-images.githubusercontent.com/61053314/161272169-90563473-8233-4988-9ac8-10971d3f19e8.png)
## Contributors 🛹
![GitHub contributors](https://img.shields.io/github/contributors/saladandonionrings/nextgen_spoofer?style=flat-square)

