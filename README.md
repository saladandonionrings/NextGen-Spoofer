<div align="center">

<img alt="logo_nextgen_spoof" src="https://user-images.githubusercontent.com/61053314/132832369-540ded53-8aff-4ea7-bcd6-70dbe7109c1a.png" width="200" />

# NextGenSpoofer
*An educational suite for ARP and DNS Spoofing*

![Python](https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Debian](https://img.shields.io/badge/Debian-A81D33?style=for-the-badge&logo=debian&logoColor=white)

</div>

>**NextGenSpoofer** is a research-oriented tool designed for educational purposes in cybersecurity labs. It provides both a Command Line Interface (CLI) and a Graphical User Interface (GUI) to demonstrate the mechanics of Man-in-the-Middle (MitM) attacks through ARP and DNS spoofing.

## Prerequisites
Tested and optimized for **Debian** and **Kali Linux** environments.

```bash
# Update and install dependencies
sudo apt-get update
sudo apt-get install build-essential python3-dev libnetfilter-queue-dev python3-tk python3-venv -y

# Clone the repository
git clone https://github.com/saladandonionrings/NextGen-Spoofer.git
cd NextGen-Spoofer

# Set up virtual environment
python3 -m venv venv
source venv/bin/activate

# Install required packages
pip install -r requirements.txt

# Netfilterqueue fix
sudo pip3 install --upgrade -U git+https://github.com/kti/python-netfilterqueue
```

## 🛡️ ARP Spoofing
### CLI
```bash
python arp_spoof_nxgenspf.py [-s] [-a]
```

| Flag | Description |
| --- | --- |
| `-s` | Target a single host |
| `-a` | Target the entire network |

### Screenshots

* **Single Target:** :

![single-arp](https://user-images.githubusercontent.com/61053314/177129438-1c53cbdd-56df-4713-8651-81c82f3fa2f0.png)

* **Full Network:** 

![full-arp](https://user-images.githubusercontent.com/61053314/177128834-9c33b2fe-26f2-47e2-a295-f2db95fc53fe.png)


### GUI

```bash
xhost +
python3 nextgen_spoofer.py
```

![gui-arp](https://user-images.githubusercontent.com/61053314/161270810-292725ba-2bb6-4fbb-a005-c98f340b46d2.png)


## 🌐 DNS Spoofing

> **Warning:** Execute this module only after successfully establishing an ARP spoof.

### CLI
```bash
python dns_spoof_nxgenspf.py -d <target_domain> -s <malicious_server_ip>
```

### GUI

![gui-dns](https://user-images.githubusercontent.com/61053314/161272132-5e0a69c5-18fa-4e8a-a6f8-bf14f65cb15f.png)


## ℹ️ About

![about](https://user-images.githubusercontent.com/61053314/161272169-90563473-8233-4988-9ac8-10971d3f19e8.png)

>This tool was developed as a proof-of-concept for academic cybersecurity laboratory exercises.
