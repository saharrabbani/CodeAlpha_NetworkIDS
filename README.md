# 🛡️ CodeAlpha – Task 4: Network Intrusion Detection System (NIDS)

> **CodeAlpha Cybersecurity Internship** | Task 4 of 4

---

## 📌 Overview

A Python-based **Network Intrusion Detection System** that monitors live
network traffic and raises real-time alerts when suspicious or malicious
activity is detected. All alerts are printed to the terminal and saved to
a structured JSON log file.

---

## ✨ Detection Capabilities

| Threat | Technique | Severity |
|---|---|---|
| **SYN / NULL / XMAS / FIN Scan** | Port probe count in time window | 🔴 HIGH |
| **ICMP Flood (DoS)** | Packet rate threshold | 💀 CRITICAL |
| **SYN Flood (DoS)** | SYN packet rate threshold | 💀 CRITICAL |
| **UDP Flood (DoS)** | UDP packet rate threshold | 💀 CRITICAL |
| **ARP Spoofing / Poisoning** | IP→MAC table consistency | 💀 CRITICAL |
| **DNS Exfiltration** | Abnormally long query names | 🔴 HIGH |
| **SSH / FTP / RDP Brute-force** | Connection attempt rate | 🔴 HIGH |
| **SQL Injection** | Payload pattern matching | 🟠 MEDIUM |
| **XSS** | Payload pattern matching | 🟠 MEDIUM |
| **Shell Injection** | Payload pattern matching | 🟠 MEDIUM |
| **Path Traversal** | Payload pattern matching | 🟠 MEDIUM |

---

## 🛠️ Prerequisites

- Python 3.8+
- Root / Administrator privileges
- Linux / macOS / Windows (with Npcap)

---

## ⚙️ Installation

```bash
git clone https://github.com/YourUsername/CodeAlpha_NetworkIDS
cd CodeAlpha_NetworkIDS
pip install -r requirements.txt
```

---

## 🚀 Usage

### Start the NIDS
```bash
sudo python3 nids.py

# Options
sudo python3 nids.py --iface=eth0          # specific interface
sudo python3 nids.py --filter="tcp"        # BPF filter
sudo python3 nids.py --count=1000          # stop after 1000 packets
sudo python3 nids.py --quiet               # no live packet line
```

### Run the attack simulator (in a second terminal)
```bash
sudo python3 test_attacks.py
```

---

## 📋 Sample Alert Output

```
💀 [2025-01-15 14:33:01] [CRITICAL] SYN Flood (DoS) Detected
   SRC : 192.168.1.200
   INFO: 220 packets in 1s (threshold=200)
   ────────────────────────────────────────────────────────────

🔴 [2025-01-15 14:33:06] [HIGH] Port Scan Detected
   SRC : 192.168.1.200
   INFO: SYN Scan — 15 ports probed in 5s (latest: port 20)
   ────────────────────────────────────────────────────────────

💀 [2025-01-15 14:33:10] [CRITICAL] ARP Spoofing / Poisoning
   SRC : 192.168.1.1
   INFO: IP 192.168.1.1 maps to multiple MACs: {'aa:bb:cc:dd:ee:ff', '11:22:33:44:55:66'}
   ────────────────────────────────────────────────────────────
```

---

## 📁 Alert Log Format (`nids_alerts.json`)

Each line is a JSON object:
```json
{"timestamp": "2025-01-15 14:33:01", "severity": "CRITICAL", "type": "SYN Flood (DoS) Detected", "source": "192.168.1.200", "detail": "220 packets in 1s (threshold=200)"}
```

---

## ⚙️ Customizing Thresholds

Edit the `CONFIG` dictionary at the top of `nids.py`:

```python
CONFIG = {
    "port_scan_threshold": 15,       # unique ports → alert
    "icmp_flood_threshold": 100,     # ICMP pkts/sec → alert
    "syn_flood_threshold": 200,      # SYN pkts/sec → alert
    "dns_query_max_len": 50,         # max DNS hostname length
    "brute_force_threshold": 10,     # auth attempts/5s → alert
    ...
}
```

---

## 📂 Project Structure

```
CodeAlpha_NetworkIDS/
├── nids.py             # Main NIDS engine
├── test_attacks.py     # Attack simulator for demo/testing
├── requirements.txt    # Python dependencies
└── README.md           # This file
```

---

## 🔒 Ethical Notice

For **educational and authorized use only**. Run only on networks you own
or have explicit permission to monitor. Unauthorized network monitoring is
illegal.

---

## 📞 Contact

CodeAlpha — [www.codealpha.tech](https://www.codealpha.tech)