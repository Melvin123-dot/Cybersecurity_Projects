# 🔐 HTTP Password Capture via MITM Attack using Ettercap

This project demonstrates how credentials transmitted over unsecured HTTP connections can be intercepted using a Man-in-the-Middle (MITM) attack. The simulation was performed in a **controlled lab environment** using Kali Linux (attacker) and Ubuntu (victim).

## 📌 Objective

To simulate and document how login credentials can be intercepted from an unencrypted HTTP session using **Ettercap** and **Wireshark**.

---

## 🛠 Tools Used

- 🐍 Kali Linux (Attacker)
- 🐧 Ubuntu Linux (Victim)
- 🐙 Ettercap (GUI)
- 🦈 Wireshark
- 🌐 Test HTTP login site: `http://testphp.vulnweb.com` or a local HTTP server

---

## ⚙️ Lab Setup

| Component         | Configuration               |
|------------------|-----------------------------|
| Attacker Machine | Kali Linux on VirtualBox     |
| Victim Machine   | Ubuntu Linux on VirtualBox   |
| Network Type     | Host-Only Adapter            |
| Communication    | HTTP (Unsecured Port 80)     |

---

## 🚀 Attack Procedure

1. ✅ **Enable IP Forwarding**
   ```bash
   echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward
🧠 Start Ettercap GUI


sudo ettercap -G
🎯 Scan for Hosts

Select appropriate interface (e.g., eth0 or ens33)

Use Hosts → Scan for Hosts

Add the victim and gateway IPs to Target 1 and Target 2

🧅 Start ARP Poisoning

Mitm → ARP poisoning → Sniff remote connections

🕵️ Begin Sniffing

Start → Start Sniffing

🔍 Capture Credentials

Let the victim log in to the HTTP site

Ettercap logs will show intercepted data like:


HTTP: User: admin  Pass: 123456
(Optional) 📡 Wireshark

Used to inspect packet-level traffic over port 80

May not show POST if HTTPS is enforced

🧩 Findings
Ettercap successfully intercepted login credentials transmitted over HTTP.

Wireshark offered additional packet inspection but didn’t always show POST if HTTPS was used.

HTTPS mitigates this type of attack effectively.

🛡 Recommendations
Use HTTPS for all login forms and user interactions.

Enforce HSTS (HTTP Strict Transport Security).

Monitor networks for ARP spoofing attacks.

Educate users about secure site practices.

📄 Report
A full test report (.docx) is included in this repo:

Vulnerability_Test_Report.docx

⚠ Disclaimer
This project is for educational purposes only and was conducted in a controlled lab environment. Unauthorized interception of credentials is illegal and unethical.

