<div align="center">
  <img alt="logo_nextgen_spoof" src="https://user-images.githubusercontent.com/61053314/132832369-540ded53-8aff-4ea7-bcd6-70dbe7109c1a.png" width="250" />
  <h1> NextGenSpoofer </h1>
  <p>
    <img alt="Python Version" src="https://img.shields.io/badge/python-%3E%3D3.0-blue?style=for-the-badge" />
  </p>
ARP and DNS Spoofers tool
<p> 💻 CLI & Interface </p>
</div>

# ⚙️ SetUp 
Recommanded to run it on **Debian / Kali**
```bash
apt-get update

# Prerequisites
apt-get install build-essential python-dev libnetfilter-queue-dev python3-tk

git clone https://github.com/saladandonionrings/NextGen-Spoofer.git
cd NextGen-Spoofer
pip install -r requirements.txt

# if errors with Netfilterqueue, use this (works perfectly for debian/kali) :
sudo pip3 install --upgrade -U git+https://github.com/kti/python-netfilterqueue
```

# 💈 ARP Spoof 
## #️⃣ CLI
```bash
python arp_spoof_nxgenspf.py [-s] [-a]
# [-s] : single target
# [-a] : all network is targeted
```

### 1️⃣🎯 Single target
<img src="https://user-images.githubusercontent.com/61053314/177129438-1c53cbdd-56df-4713-8651-81c82f3fa2f0.png" />

### ♾️🎯 All network is targeted
<img src="https://user-images.githubusercontent.com/61053314/177128834-9c33b2fe-26f2-47e2-a295-f2db95fc53fe.png"/>

## 👨🏽‍💻 INTERFACE
```bash
# you can run it as root or non-root user
xhost +
python3 nextgen_spoofer.py
```

#### 1️⃣🎯 Single target : 
![arp_one_spoof](https://user-images.githubusercontent.com/61053314/161270810-292725ba-2bb6-4fbb-a005-c98f340b46d2.png)

#### ♾️🎯 All network is targeted : 
https://user-images.githubusercontent.com/61053314/160906537-34b35d9e-a004-4bc5-a0bf-46c919643261.mp4

# 🍔 DNS SPOOF 
#### 📢 USE IT RIGHT AFTER YOU LAUNCHED ARP SPOOF
## #️⃣ CLI
```bash
python dns_spoof_nxgenspf.py -d google.com -s $evil_server_ip
```

## 👨🏽‍💻 INTERFACE
![dns_int](https://user-images.githubusercontent.com/61053314/161272132-5e0a69c5-18fa-4e8a-a6f8-bf14f65cb15f.png)
#### Example
	DNS NAME = google.com
	DNS @IP = $malicious_server_ip
	
## 💭 ABOUT
![about](https://user-images.githubusercontent.com/61053314/161272169-90563473-8233-4988-9ac8-10971d3f19e8.png)
## Contributors 🛹
![GitHub contributors](https://img.shields.io/github/contributors/saladandonionrings/nextgen_spoofer?style=flat-square)

