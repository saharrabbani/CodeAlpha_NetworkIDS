#!/usr/bin/env python3
"""
============================================================
  CodeAlpha Internship - Task 4: Network IDS
  GUI Version — Windows 100% Compatible
  Author  : [Your Name]
  Libraries: scapy, tkinter (built-in)
============================================================
"""

import sys
import os
import threading
import ctypes
import json
from datetime import datetime
from collections import defaultdict
import tkinter as tk
from tkinter import ttk, messagebox

# ─── Auto-relaunch as Administrator on Windows ────────────
def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def run_as_admin():
    """Re-launch this script with admin rights automatically."""
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

# Auto-elevate if not already admin
if not is_admin():
    run_as_admin()
    sys.exit(0)

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP, DNS, Raw
except ImportError:
    print("[ERROR] Run: pip install scapy")
    sys.exit(1)

# ─── Config ───────────────────────────────────────────────
CONFIG = {
    "port_scan_threshold": 15,
    "port_scan_window": 5,
    "icmp_flood_threshold": 100,
    "syn_flood_threshold": 200,
    "udp_flood_threshold": 500,
    "flood_window": 1,
    "dns_max_len": 50,
    "brute_threshold": 10,
    "brute_window": 5,
    "brute_ports": {22, 21, 23, 3389, 5900},
}

PAYLOAD_PATTERNS = {
    "SQL Injection":   [b"' OR ", b"1=1", b"UNION SELECT", b"DROP TABLE"],
    "XSS":             [b"<SCRIPT>", b"JAVASCRIPT:", b"ONERROR="],
    "Shell Injection": [b"/BIN/SH", b"/BIN/BASH", b"CMD.EXE", b"POWERSHELL"],
    "Path Traversal":  [b"../", b"..\\", b"%2E%2E"],
}

SEV_COLORS = {"CRITICAL":"#fc8181","HIGH":"#f6ad55","MEDIUM":"#63b3ed","LOW":"#718096"}

# ─── State ────────────────────────────────────────────────
port_tracker   = defaultdict(dict)
icmp_tracker   = defaultdict(list)
syn_tracker    = defaultdict(list)
udp_tracker    = defaultdict(list)
brute_tracker  = defaultdict(lambda: defaultdict(list))
arp_table      = defaultdict(set)
alert_counts   = defaultdict(int)
alerts_log     = []
sniffing       = False
sniff_thread   = None
total_packets  = 0

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        try:
            return os.getuid() == 0
        except:
            return False

# ─── Detection ────────────────────────────────────────────
def raise_alert(sev, atype, src, detail):
    ts = datetime.now().strftime("%H:%M:%S")
    record = {"time":ts,"sev":sev,"type":atype,"src":src,"detail":detail}
    alerts_log.insert(0, record)
    alert_counts[atype] += 1
    with open("nids_alerts.json","a") as f:
        f.write(json.dumps({"timestamp":ts,**record})+"\n")
    app.after(0, lambda r=record: app.add_alert(r))
    app.after(0, app.update_stats)
    app.after(0, app.update_threat_bars)

def detect_port_scan(src, dport, flags, ts):
    t = CONFIG["port_scan_threshold"]
    w = CONFIG["port_scan_window"]
    tracker = port_tracker[src]
    tracker = {p:v for p,v in tracker.items() if ts-v < w}
    tracker[dport] = ts
    port_tracker[src] = tracker
    if len(tracker) >= t:
        scan = "NULL Scan" if flags=="" else "XMAS Scan" if all(f in flags for f in "FPU") else "FIN Scan" if flags=="F" else "SYN Scan"
        raise_alert("HIGH","Port Scan",src,f"{scan} — {len(tracker)} ports in {w}s")
        port_tracker[src].clear()

def detect_flood(src, tracker, threshold, window, name, ts):
    tracker[src].append(ts)
    tracker[src] = [t for t in tracker[src] if ts-t < window]
    if len(tracker[src]) >= threshold:
        raise_alert("CRITICAL",name,src,f"{len(tracker[src])} pkts/s (threshold={threshold})")
        tracker[src].clear()

def detect_arp_spoof(ip, mac):
    arp_table[ip].add(mac)
    if len(arp_table[ip]) > 1:
        raise_alert("CRITICAL","ARP Spoofing",ip,f"Multiple MACs: {arp_table[ip]}")

def detect_dns_exfil(src, qname):
    if len(qname) > CONFIG["dns_max_len"]:
        raise_alert("HIGH","DNS Exfiltration",src,f"Long query ({len(qname)} chars): {qname[:60]}")

def detect_brute(src, dport, ts):
    if dport not in CONFIG["brute_ports"]: return
    w = CONFIG["brute_window"]
    thr = CONFIG["brute_threshold"]
    brute_tracker[src][dport].append(ts)
    brute_tracker[src][dport] = [t for t in brute_tracker[src][dport] if ts-t < w]
    if len(brute_tracker[src][dport]) >= thr:
        svc = {22:"SSH",21:"FTP",23:"Telnet",3389:"RDP",5900:"VNC"}.get(dport,str(dport))
        raise_alert("HIGH",f"{svc} Brute Force",src,f"{len(brute_tracker[src][dport])} attempts in {w}s")
        brute_tracker[src][dport].clear()

def detect_payload(src, dst, payload):
    upper = payload.upper()
    for name, patterns in PAYLOAD_PATTERNS.items():
        for p in patterns:
            if p in upper:
                raise_alert("MEDIUM",name,src,f"Pattern '{p.decode()}' → {dst}")
                break

# ─── Packet handler ───────────────────────────────────────
def process_packet(packet):
    global total_packets
    total_packets += 1
    ts = datetime.now().timestamp()
    app.after(0, lambda: app.pkt_lbl.config(text=f"Packets: {total_packets}"))

    if packet.haslayer(ARP):
        a = packet.getlayer(ARP)
        if a.op == 2:
            detect_arp_spoof(a.psrc, a.hwsrc)
        return

    if not packet.haslayer(IP): return
    ip = packet.getlayer(IP)
    src, dst = ip.src, ip.dst

    if packet.haslayer(ICMP):
        detect_flood(src, icmp_tracker, CONFIG["icmp_flood_threshold"],
                     CONFIG["flood_window"], "ICMP Flood", ts)
        return

    if packet.haslayer(TCP):
        tcp = packet.getlayer(TCP)
        flags = tcp.sprintf("%flags%")
        if "S" in flags and "A" not in flags:
            detect_flood(src, syn_tracker, CONFIG["syn_flood_threshold"],
                         CONFIG["flood_window"], "SYN Flood", ts)
            detect_brute(src, tcp.dport, ts)
        detect_port_scan(src, tcp.dport, flags, ts)
        if packet.haslayer(Raw):
            detect_payload(src, dst, packet.getlayer(Raw).load)

    elif packet.haslayer(UDP):
        detect_flood(src, udp_tracker, CONFIG["udp_flood_threshold"],
                     CONFIG["flood_window"], "UDP Flood", ts)
        if packet.haslayer(DNS):
            d = packet.getlayer(DNS)
            if d.qr == 0 and d.qd:
                detect_dns_exfil(src, d.qd.qname.decode(errors="replace").rstrip("."))
        if packet.haslayer(Raw):
            detect_payload(src, dst, packet.getlayer(Raw).load)

def start_sniffing():
    with open("nids_alerts.json","w") as f: f.write("")
    try:
        sniff(prn=process_packet, store=False, stop_filter=lambda x: not sniffing)
    except Exception as e:
        app.after(0, lambda: messagebox.showerror("Error", str(e)))


# ─── GUI ──────────────────────────────────────────────────
class NIDSApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("🛡️ Network IDS — CodeAlpha Task 4")
        self.geometry("1100x700")
        self.configure(bg="#0f1117")
        self._build_ui()

    def _build_ui(self):
        # Header
        hdr = tk.Frame(self, bg="#161b27", pady=10)
        hdr.pack(fill="x")
        tk.Label(hdr, text="🛡️  Network Intrusion Detection System",
                 font=("Segoe UI",15,"bold"), bg="#161b27", fg="#ffffff").pack(side="left", padx=16)
        tk.Label(hdr, text="CodeAlpha — Task 4", font=("Segoe UI",10),
                 bg="#161b27", fg="#63b3ed").pack(side="left")
        self.status_lbl = tk.Label(hdr, text="⏹ STOPPED",
                 font=("Segoe UI",10,"bold"), bg="#161b27", fg="#718096")
        self.status_lbl.pack(side="right", padx=16)
        self.clock_lbl = tk.Label(hdr, text="", font=("Courier New",10),
                 bg="#161b27", fg="#718096")
        self.clock_lbl.pack(side="right", padx=8)
        self._tick()

        # Stat cards
        sf = tk.Frame(self, bg="#0f1117", pady=8)
        sf.pack(fill="x", padx=12)
        self.stat_vals = {}
        for label, color in [("Critical","#fc8181"),("High","#f6ad55"),
                              ("Medium","#63b3ed"),("Total Alerts","#ffffff")]:
            card = tk.Frame(sf, bg="#161b27", highlightbackground="#2d3748", highlightthickness=1)
            card.pack(side="left", expand=True, fill="x", padx=4)
            v = tk.Label(card, text="0", font=("Segoe UI",22,"bold"), bg="#161b27", fg=color)
            v.pack(pady=(10,2))
            tk.Label(card, text=label.upper(), font=("Segoe UI",9),
                     bg="#161b27", fg="#718096").pack(pady=(0,10))
            self.stat_vals[label] = v

        # Toolbar
        tb = tk.Frame(self, bg="#0f1117", pady=6)
        tb.pack(fill="x", padx=12)
        self.start_btn = tk.Button(tb, text="▶  Start Monitoring",
            font=("Segoe UI",10,"bold"), bg="#276749", fg="white",
            relief="flat", padx=14, pady=5, cursor="hand2", command=self.toggle)
        self.start_btn.pack(side="left", padx=(0,8))
        tk.Button(tb, text="🗑  Clear Alerts",
            font=("Segoe UI",10), bg="#2d3748", fg="#fc8181",
            relief="flat", padx=12, pady=5, cursor="hand2",
            command=self.clear_alerts).pack(side="left")
        self.pkt_lbl = tk.Label(tb, text="Packets: 0", bg="#0f1117",
            fg="#718096", font=("Segoe UI",9))
        self.pkt_lbl.pack(side="right", padx=8)

        # Main area: alerts + modules
        main = tk.Frame(self, bg="#0f1117")
        main.pack(fill="both", expand=True, padx=12, pady=(0,6))

        # Left: alerts table
        left = tk.Frame(main, bg="#0f1117")
        left.pack(side="left", fill="both", expand=True, padx=(0,6))

        tk.Label(left, text="LIVE ALERTS", font=("Segoe UI",9,"bold"),
                 bg="#0f1117", fg="#718096").pack(anchor="w", pady=(0,4))

        cols = ("Time","Severity","Threat","Source","Detail")
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("Dark.Treeview", background="#161b27", foreground="#cbd5e0",
            fieldbackground="#161b27", rowheight=26, font=("Courier New",10))
        style.configure("Dark.Treeview.Heading", background="#1a202c",
            foreground="#718096", font=("Segoe UI",9,"bold"), relief="flat")
        style.map("Dark.Treeview", background=[("selected","#2b6cb0")])

        self.tree = ttk.Treeview(left, columns=cols, show="headings", style="Dark.Treeview")
        widths = {"Time":75,"Severity":75,"Threat":170,"Source":115,"Detail":320}
        for c in cols:
            self.tree.heading(c, text=c)
            self.tree.column(c, width=widths[c], anchor="w")
        for sev,col in SEV_COLORS.items():
            self.tree.tag_configure(sev, foreground=col)

        vsb = ttk.Scrollbar(left, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        self.tree.pack(side="left", fill="both", expand=True)
        vsb.pack(side="right", fill="y")

        # Right panel
        right = tk.Frame(main, bg="#0f1117", width=220)
        right.pack(side="right", fill="y")
        right.pack_propagate(False)

        # Threat bars
        tk.Label(right, text="TOP THREATS", font=("Segoe UI",9,"bold"),
                 bg="#0f1117", fg="#718096").pack(anchor="w", pady=(0,4))
        self.bar_frame = tk.Frame(right, bg="#161b27",
            highlightbackground="#2d3748", highlightthickness=1)
        self.bar_frame.pack(fill="x", pady=(0,12))

        # Modules
        tk.Label(right, text="DETECTION MODULES", font=("Segoe UI",9,"bold"),
                 bg="#0f1117", fg="#718096").pack(anchor="w", pady=(0,4))
        mods = [("🔍","Port Scan"),("💥","DoS / DDoS"),("📡","ARP Spoofing"),
                ("🔎","DNS Exfiltration"),("🔐","Brute Force"),("💉","SQLi / XSS")]
        for icon, name in mods:
            row = tk.Frame(right, bg="#161b27",
                highlightbackground="#2d3748", highlightthickness=1)
            row.pack(fill="x", pady=2)
            tk.Label(row, text=icon, font=("Segoe UI",12), bg="#161b27").pack(side="left", padx=8, pady=6)
            tk.Label(row, text=name, font=("Segoe UI",10), bg="#161b27",
                     fg="#e2e8f0").pack(side="left")
            tk.Label(row, text="● ON", font=("Segoe UI",9,"bold"), bg="#161b27",
                     fg="#68d391").pack(side="right", padx=8)

        # Status bar
        self.statusbar = tk.Label(self, text="Ready — Run PyCharm as Administrator to start",
            bg="#161b27", fg="#718096", font=("Segoe UI",9),
            anchor="w", pady=4, padx=12)
        self.statusbar.pack(fill="x", side="bottom")

    def _tick(self):
        self.clock_lbl.config(text=datetime.now().strftime("%H:%M:%S"))
        self.after(1000, self._tick)

    def toggle(self):
        global sniffing, sniff_thread
        if not sniffing:
            sniffing = True
            self.start_btn.config(text="⏹  Stop Monitoring", bg="#9b2c2c")
            self.status_lbl.config(text="🟢 MONITORING", fg="#68d391")
            self.statusbar.config(text="Monitoring network traffic for intrusions...")
            sniff_thread = threading.Thread(target=start_sniffing, daemon=True)
            sniff_thread.start()
        else:
            sniffing = False
            self.start_btn.config(text="▶  Start Monitoring", bg="#276749")
            self.status_lbl.config(text="⏹ STOPPED", fg="#718096")
            self.statusbar.config(text=f"Stopped. {sum(alert_counts.values())} alerts saved to nids_alerts.json")

    def add_alert(self, r):
        tag = r["sev"]
        self.tree.insert("", 0, values=(r["time"],r["sev"],r["type"],r["src"],r["detail"]), tags=(tag,))
        children = self.tree.get_children()
        if len(children) > 300:
            self.tree.delete(children[-1])

    def update_stats(self):
        crit = sum(1 for a in alerts_log if a["sev"]=="CRITICAL")
        high = sum(1 for a in alerts_log if a["sev"]=="HIGH")
        med  = sum(1 for a in alerts_log if a["sev"]=="MEDIUM")
        self.stat_vals["Critical"].config(text=str(crit))
        self.stat_vals["High"].config(text=str(high))
        self.stat_vals["Medium"].config(text=str(med))
        self.stat_vals["Total Alerts"].config(text=str(len(alerts_log)))

    def update_threat_bars(self):
        for w in self.bar_frame.winfo_children():
            w.destroy()
        top = sorted(alert_counts.items(), key=lambda x:x[1], reverse=True)[:6]
        mx = top[0][1] if top else 1
        for name, count in top:
            row = tk.Frame(self.bar_frame, bg="#161b27")
            row.pack(fill="x", padx=8, pady=3)
            tk.Label(row, text=name[:18], font=("Segoe UI",9), bg="#161b27",
                     fg="#cbd5e0", anchor="w", width=18).pack(side="left")
            track = tk.Frame(row, bg="#2d3748", height=6, width=80)
            track.pack(side="left", padx=4)
            track.pack_propagate(False)
            fill_w = max(4, int(count/mx*80))
            tk.Frame(track, bg="#fc8181", width=fill_w, height=6).place(x=0,y=0)
            tk.Label(row, text=str(count), font=("Courier New",9),
                     bg="#161b27", fg="#718096").pack(side="left")

    def clear_alerts(self):
        global alerts_log
        alerts_log = []
        alert_counts.clear()
        for item in self.tree.get_children():
            self.tree.delete(item)
        self.update_stats()
        self.update_threat_bars()

if __name__ == "__main__":
    app = NIDSApp()
    app.mainloop()