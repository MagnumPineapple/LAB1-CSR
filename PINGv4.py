#!/usr/bin/env python3
import socket
import os
import struct
import time
import sys

def checksum(packet):
    """
    Calcula el checksum (RFC 1071) para el encabezado y data ICMP.
    """
    s = 0
    for i in range(0, len(packet), 2):
        if i + 1 < len(packet):
            w = packet[i] + (packet[i+1] << 8)
        else:
            w = packet[i]
        s = s + w
        s = (s & 0xffff) + (s >> 16)
    s = ~s & 0xffff
    return s

def create_icmp_packet(seq_number, character):
    """
    Crea un paquete ICMP Echo Request con 64 bytes de data.
    Se realizan las siguientes modificaciones en el payload:
      - Los primeros 8 bytes contienen un timestamp actual (manteniendo el timestamp).
      - Los bytes desde el offset 0x10 (16) hasta 0x37 (55) se mantienen sin modificación.
      - El carácter a transmitir se inyecta en el último byte (byte 63).
    Esto permite cumplir con los requerimientos de mantener el timestamp y 
    preservar el bloque de bytes indicado.
    """
    icmp_type = 8   # Echo Request
    code = 0
    chksum = 0
    identifier = os.getpid() & 0xFFFF  # ID basado en el PID del proceso

    # Crear payload de 64 bytes.
    payload = bytearray(64)
    # Inserta timestamp en los primeros 8 bytes (usando double, 8 bytes)
    timestamp = time.time()
    payload[0:8] = struct.pack("!d", timestamp)
    # Los bytes del 8 al 15 y del 16 al 55 se dejan en 0 (como en un ping estándar)
    # Inyecta el carácter en el último byte (byte 63)
    payload[-1] = ord(character)

    # Armar la cabecera ICMP con checksum = 0 inicialmente
    header = struct.pack("!BBHHH", icmp_type, code, chksum, identifier, seq_number)
    packet = header + payload
    calculated_chksum = checksum(packet)
    # Reconstruir la cabecera con el checksum calculado (convertido a orden de red)
    header = struct.pack("!BBHHH", icmp_type, code, socket.htons(calculated_chksum), identifier, seq_number)
    return header + payload

def send_stealth_icmp(message):
    """
    Envía cada carácter del mensaje en un paquete ICMP Echo Request a 8.8.8.8.
    Cada paquete se construye con un payload de 64 bytes que:
      - Contiene un timestamp en los primeros 8 bytes.
      - Preserva el bloque de bytes desde 0x10 hasta 0x37 sin modificar.
      - Inyecta el carácter en el último byte del payload.
    Esto permite simular tráfico de 'ping' estándar mientras se inyecta el
    mensaje cifrado de manera discreta.
    """
    destination_ip = "8.8.8.8"
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    sock.settimeout(1)

    for i, ch in enumerate(message, start=1):
        packet = create_icmp_packet(i, ch)
        sock.sendto(packet, (destination_ip, 0))
        print(f"Sent packet {i} with character '{ch}'")
        time.sleep(0.5)
    sock.close()

if __name__ == "__main__":
    """
    Uso:
        sudo python3 pingv4.py <MENSAJE>
    
    Ejemplo:
        sudo python3 pingv4.py "larycxpajorf h bnpdarnjn mw amnb"
    """
    if len(sys.argv) != 2:
        print(f"Uso: {sys.argv[0]} <MENSAJE>")
        sys.exit(1)
    
    text_to_send = sys.argv[1]
    send_stealth_icmp(text_to_send)
