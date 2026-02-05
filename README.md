# 🌐 Network Packet Analyzer

![Python Version](https://img.shields.io/badge/python-3.6+-blue.svg)
![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux-lightgrey.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)

A **cross-platform network packet analyzer** built with Python for **educational and learning purposes**.  
This project demonstrates how raw network packets are captured, parsed, and analyzed at a low level.

---

## ⚠️ Legal & Ethical Disclaimer

**This project is strictly for EDUCATIONAL PURPOSES ONLY.**

- ✅ Analyze traffic only on networks you own or have explicit permission to monitor
- ✅ Use this tool to understand networking and cybersecurity concepts
- ❌ Do NOT monitor networks without authorization
- ❌ Do NOT capture or misuse sensitive data
- ❌ Unauthorized packet sniffing may be **illegal** in many regions

**By using this software, you agree to follow all applicable laws and ethical standards.**

---

## 📌 Project Overview

This project demonstrates how network packet sniffers work internally using Python raw sockets.  
It helps learners understand **network protocols, packet structure, and traffic analysis**.

### Key Learning Focus
- Raw socket programming
- Network protocol analysis (TCP, UDP, ICMP)
- Packet header parsing
- Binary data handling
- Cross-platform scripting
- Ethical cybersecurity practices

---

## ✨ Features

- 🌍 Cross-platform support (Windows & Linux)
- 📡 Real-time packet capture
- 🔍 Protocol identification (TCP, UDP, ICMP)
- 🌐 Displays source & destination IP addresses
- 🔢 Shows port numbers and TCP flags
- 📦 Payload inspection (ASCII & Hex)
- 🧹 Protocol-based packet filtering
- 📁 Export captured packets to JSON
- 📊 Packet statistics summary
- ⏱ Timestamped capture sessions

---

## 🔍 How It Works

1. Creates a **raw socket** with elevated privileges
2. Captures incoming and outgoing packets
3. Parses IPv4 headers
4. Routes packets to protocol parsers (TCP / UDP / ICMP)
5. Displays formatted packet details
6. Optionally saves captured data to a file

---

## 📦 Prerequisites

- **OS**: Windows or Linux
- **Python**: 3.6 or higher
- **Privileges**:
  - Administrator (Windows)
  - Root / sudo (Linux)
- **Active network interface**

> Raw sockets require elevated privileges because they can access low-level network traffic.

---

## 🚀 Installation

### Clone the Repository

git clone https://github.com/manividyadhar/internship_1-packet_analyzer.git
cd internship_1-packet_analyzer
Verify Python
python --version
# or
python3 --version
Install Dependencies (Optional)
This project mainly uses standard Python libraries.

pip install -r requirements.txt
💻 Usage
Basic Command
python packet_analyzer.py
Linux (Required)
sudo python3 packet_analyzer.py
Command-Line Options
Option	Description
-c, --count	Number of packets to capture
-f, --filter	Filter by protocol (TCP/UDP/ICMP)
-o, --output	Save packets to JSON file
-i, --interface	Network interface (Linux only)
-h, --help	Show help menu
🧪 Examples
Capture 10 Packets
python packet_analyzer.py -c 10
Capture TCP Packets Only
python packet_analyzer.py -f TCP
Save Output to File
python packet_analyzer.py -c 50 -o packets.json
📊 Understanding the Output
IPv4 Header Details
Source IP

Destination IP

Protocol number

TTL

Header length

Total packet size

TCP Details
Source and destination ports

Sequence & acknowledgment numbers

TCP flags (SYN, ACK, FIN, etc.)

Payload Data
ASCII-readable content (if available)

Raw hexadecimal dump

🛠 Technical Highlights
Raw Socket Usage
Windows uses AF_INET

Linux uses AF_PACKET

Packets are parsed using the struct module

Supported Protocol Numbers
Protocol	Number
ICMP	1
TCP	6
UDP	17
🐛 Troubleshooting
Permission Errors
Windows: Run terminal as Administrator

Linux: Use sudo

No Packets Captured
Generate network traffic (browse, ping, download)

Check firewall settings

Specify correct network interface (Linux)

Encrypted Traffic
HTTPS payloads cannot be read (this is expected)

📈 Learning Outcomes
Network packet structure understanding

Low-level socket programming

TCP/IP protocol behavior

Binary parsing with Python

Ethical hacking awareness

Cybersecurity fundamentals

🔮 Future Enhancements
IPv6 packet support

GUI interface

HTTP/DNS protocol parsing

Advanced filtering (IP / Port)

Real-time statistics graphs

Machine learning traffic analysis

📄 License
This project is licensed under the MIT License.

👤 Author
Manividyadhar

GitHub: https://github.com/manividyadhar

LinkedIn: add-your-linkedin-link

⚖️ Final Legal Notice
This software is provided only for educational purposes.
The author is not responsible for any misuse.
Users are solely responsible for complying with all applicable laws.
