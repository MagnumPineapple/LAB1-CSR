#!/usr/bin/env python3
import sys
import struct

def caesar_decrypt(ciphertext, shift):
    """
    Desencripta 'ciphertext' aplicando un corrimiento César de 'shift'.
    Solo modifica letras a-z, dejando espacios y otros símbolos sin cambio.
    (Coincide con la lógica del PASO 1).
    """
    plaintext = ""
    for ch in ciphertext:
        if 'a' <= ch <= 'z':
            pos = ord(ch) - ord('a')
            new_pos = (pos - shift) % 26
            plaintext += chr(new_pos + ord('a'))
        else:
            plaintext += ch
    return plaintext

def chi2_score(text):
    """
    Calcula el estadístico chi-cuadrado entre la frecuencia de letras en 'text'
    y las frecuencias esperadas en inglés. Un valor menor indica que la distribución
    de letras se asemeja más a la del inglés típico, lo que sugiere que el texto es
    más probable que sea el mensaje en claro.
    """
    expected_freq = {
        'a': 8.2,  'b': 1.5,  'c': 2.8,  'd': 4.3,  'e': 12.7,
        'f': 2.2,  'g': 2.0,  'h': 6.1,  'i': 7.0,  'j': 0.15,
        'k': 0.77, 'l': 4.0,  'm': 2.4,  'n': 6.7,  'o': 7.5,
        'p': 1.9,  'q': 0.095,'r': 6.0,  's': 6.3,  't': 9.1,
        'u': 2.8,  'v': 0.98, 'w': 2.4,  'x': 0.15, 'y': 2.0, 'z': 0.074
    }
    # Convertir porcentajes a proporciones
    for letter in expected_freq:
        expected_freq[letter] /= 100.0

    counts = {chr(i+97): 0 for i in range(26)}
    total = 0
    for ch in text:
        if 'a' <= ch <= 'z':
            counts[ch] += 1
            total += 1
    if total == 0:
        return float('inf')
    
    chi2 = 0.0
    for letter in counts:
        observed = counts[letter]
        expected = total * expected_freq[letter]
        chi2 += (observed - expected) ** 2 / (expected if expected > 0 else 1)
    return chi2

def process_packet(packet_data, message_bytes):
    """
    Extrae el último byte del payload ICMP si el paquete es
    un ICMP Echo Request (type=8) en IPv4 sobre Ethernet.
    """
    if len(packet_data) < 14:
        return
    try:
        dest_mac, src_mac, ethertype = struct.unpack('!6s6sH', packet_data[:14])
    except struct.error:
        return
    # Solo IPv4
    if ethertype != 0x0800:
        return

    ip_start = 14
    if len(packet_data) < ip_start + 20:
        return
    ver_ihl = packet_data[ip_start]
    ihl = ver_ihl & 0x0F
    ip_header_length = ihl * 4
    if len(packet_data) < ip_start + ip_header_length:
        return

    # Protocolo ICMP = 1
    protocol = packet_data[ip_start + 9]
    if protocol != 1:
        return

    icmp_start = ip_start + ip_header_length
    if len(packet_data) < icmp_start + 8:
        return
    icmp_type = packet_data[icmp_start]
    # Procesamos solo Echo Request (tipo 8)
    if icmp_type != 8:
        return

    # Extraemos el último byte del payload ICMP
    icmp_payload_start = icmp_start + 8
    if len(packet_data) > icmp_payload_start:
        message_bytes.append(packet_data[-1])

def extract_from_pcap(f):
    """
    Lectura básica de un archivo .pcap.
    """
    message_bytes = []
    global_header = f.read(24)
    if len(global_header) < 24:
        print("Archivo pcap demasiado corto o corrupto.")
        return ""
    while True:
        record_header = f.read(16)
        if len(record_header) < 16:
            break
        ts_sec, ts_usec, incl_len, orig_len = struct.unpack('IIII', record_header)
        packet_data = f.read(incl_len)
        if len(packet_data) < incl_len:
            break
        process_packet(packet_data, message_bytes)
    return "".join(chr(b).lower() for b in message_bytes)

def extract_from_pcapng(f):
    """
    Lectura básica de un archivo .pcapng.
    """
    message_bytes = []
    while True:
        block_header = f.read(8)
        if len(block_header) < 8:
            break
        block_type, block_total_length = struct.unpack('<II', block_header)
        if block_total_length < 12:
            break
        block_data = f.read(block_total_length - 8)
        if len(block_data) < block_total_length - 8:
            break
        block_body = block_data[:-4]
        if block_type == 0x00000006:  # Enhanced Packet Block
            if len(block_body) < 20:
                continue
            try:
                interface_id, ts_high, ts_low, cap_len, orig_len = struct.unpack('<IIIII', block_body[:20])
            except struct.error:
                continue
            if len(block_body) < 20 + cap_len:
                continue
            packet_data = block_body[20:20+cap_len]
            process_packet(packet_data, message_bytes)
        elif block_type == 0x00000003:  # Simple Packet Block
            packet_data = block_body
            process_packet(packet_data, message_bytes)
    return "".join(chr(b).lower() for b in message_bytes)

def extract_ciphertext_from_pcap(pcap_file):
    """
    Detecta si el archivo es .pcap o .pcapng y extrae el texto cifrado en minúsculas.
    """
    try:
        with open(pcap_file, 'rb') as f:
            header = f.read(4)
            f.seek(0)
            if header == b'\x0A\x0D\x0D\x0A':  # pcapng
                return extract_from_pcapng(f)
            else:
                return extract_from_pcap(f)
    except Exception as e:
        print(f"Error al leer el archivo: {e}")
        return ""

def main():
    if len(sys.argv) != 2:
        print(f"Uso: {sys.argv[0]} <archivo_pcap>")
        sys.exit(1)

    pcap_file = sys.argv[1]
    ciphertext = extract_ciphertext_from_pcap(pcap_file)
    if not ciphertext:
        print("No se encontró texto cifrado en el pcap.")
        sys.exit(0)

    possibilities = []
    best_shift = None
    best_score = float('inf')
    best_text = ""

    # Generar todas las combinaciones posibles (corrimientos de 0 a 25)
    for shift in range(26):
        decrypted = caesar_decrypt(ciphertext, shift)
        score = chi2_score(decrypted)
        possibilities.append((shift, decrypted, score))
        if score < best_score:
            best_score = score
            best_shift = shift
            best_text = decrypted

    print()
    for shift, text, score in possibilities:
        if shift == best_shift:
            print(f"\033[92m{shift:2d} -> {text}\033[0m")
        else:
            print(f"{shift:2d} -> {text}")

    print("\nPosible mensaje en claro (más probable):")
    print(f"\033[92m{best_text}\033[0m\n")

def chi2_score(text):
    """
    Calcula el valor chi-cuadrado entre la distribución de letras en 'text'
    y la distribución típica en inglés.
    """
    expected_freq = {
        'a': 8.2,  'b': 1.5,  'c': 2.8,  'd': 4.3,  'e': 12.7,
        'f': 2.2,  'g': 2.0,  'h': 6.1,  'i': 7.0,  'j': 0.15,
        'k': 0.77, 'l': 4.0,  'm': 2.4,  'n': 6.7,  'o': 7.5,
        'p': 1.9,  'q': 0.095,'r': 6.0,  's': 6.3,  't': 9.1,
        'u': 2.8,  'v': 0.98, 'w': 2.4,  'x': 0.15, 'y': 2.0, 'z': 0.074
    }
    for letter in expected_freq:
        expected_freq[letter] /= 100.0

    counts = {chr(i+97): 0 for i in range(26)}
    total = 0
    for ch in text:
        if 'a' <= ch <= 'z':
            counts[ch] += 1
            total += 1
    if total == 0:
        return float('inf')
    
    chi2 = 0.0
    for letter in counts:
        observed = counts[letter]
        expected = total * expected_freq[letter]
        chi2 += (observed - expected) ** 2 / (expected if expected > 0 else 1)
    return chi2

if __name__ == "__main__":
    main()
