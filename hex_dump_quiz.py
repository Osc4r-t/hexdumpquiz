#!/usr/bin/env python3
"""
HEX DUMP QUIZ - Practicar lectura de paquetes byte a byte
=========================================================
Versión 2, basada en hex_dump_quiz_levels.py.

La idea central: TODO se responde mirando el volcado hexadecimal. El juego
muestra el hex dump de un paquete real y te pregunta por sus campos, por los
offsets donde viven, por como se decodifican esos bytes y por que significan.

Qué agrega respecto de la versión anterior:
  * Lector de .pcap y .pcapng nativo (struct), sin depender de Scapy.
  * Cada campo parseado recuerda su OFFSET y su TAMAÑO, así que el juego puede
    preguntar en las dos direcciones: campo -> offset y offset -> campo.
  * Preguntas de decodificación: "estos bytes, qué valor representan".
  * Preguntas de cálculo: IHL, longitud de cabecera, tamaño del payload,
    verificación del checksum IPv4.
  * Modo "paquete anotado": el hex dump con cada campo marcado, para estudiar.
  * Secuencias de 3 a 6 paquetes para deducir qué ocurre por contenido y orden.
  * Ventana deslizante, Go-Back-N y Selective Repeat.

Uso:
    python3 hex_dump_quiz.py

Los .pcap se leen de la carpeta 'files' que está junto a este script.
"""

import random
import re
import struct
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

FILES_DIR = Path(__file__).resolve().parent / "files"
RULE = "=" * 74
THIN = "-" * 74


# ---------------------------------------------------------------------------
# Tablas de referencia
# ---------------------------------------------------------------------------

ETHERTYPES = {
    0x0800: "IPv4", 0x0806: "ARP", 0x86DD: "IPv6", 0x8100: "802.1Q VLAN",
    0x8863: "PPPoE Discovery", 0x8864: "PPPoE Session", 0x88CC: "LLDP",
}

IP_PROTOCOLS = {
    1: "ICMP", 2: "IGMP", 6: "TCP", 17: "UDP", 41: "IPv6", 47: "GRE",
    50: "ESP", 51: "AH", 58: "ICMPv6", 89: "OSPF", 132: "SCTP",
}

ICMP_TYPES = {
    0: "Echo Reply", 3: "Destination Unreachable", 4: "Source Quench",
    5: "Redirect", 8: "Echo Request", 9: "Router Advertisement",
    10: "Router Solicitation", 11: "Time Exceeded", 12: "Parameter Problem",
    13: "Timestamp", 14: "Timestamp Reply",
}

ICMP_UNREACH_CODES = {
    0: "red inalcanzable", 1: "host inalcanzable", 2: "protocolo inalcanzable",
    3: "puerto inalcanzable", 4: "hace falta fragmentar pero DF esta activo",
    9: "red prohibida administrativamente",
    10: "host prohibido administrativamente",
    13: "prohibido administrativamente (firewall)",
}

WELL_KNOWN_PORTS = {
    20: "FTP (datos)", 21: "FTP (control)", 22: "SSH", 23: "Telnet",
    25: "SMTP", 53: "DNS", 67: "DHCP servidor", 68: "DHCP cliente",
    69: "TFTP", 80: "HTTP", 110: "POP3", 123: "NTP", 143: "IMAP",
    161: "SNMP", 179: "BGP", 443: "HTTPS", 445: "SMB", 3306: "MySQL",
    3389: "RDP", 5353: "mDNS", 8080: "HTTP alterno",
}

DNS_TYPES = {
    1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT",
    28: "AAAA", 33: "SRV", 255: "ANY",
}

DNS_RCODES = {
    0: "NOERROR (sin error)", 1: "FORMERR (error de formato)",
    2: "SERVFAIL (fallo del servidor)", 3: "NXDOMAIN (dominio inexistente)",
    4: "NOTIMP (no implementado)", 5: "REFUSED (rechazado)",
}

RIP_COMANDOS = {1: "Request (pide la tabla)", 2: "Response (anuncia rutas)",
                3: "Traceon (obsoleto)", 4: "Traceoff (obsoleto)"}

OSPF_TIPOS = {1: "Hello", 2: "Database Description", 3: "Link State Request",
              4: "Link State Update", 5: "Link State Acknowledgment"}

OSPF_AUTH = {0: "sin autenticación", 1: "contraseña en claro", 2: "MD5"}

LSA_TIPOS = {1: "Router-LSA", 2: "Network-LSA", 3: "Summary-LSA (red)",
             4: "Summary-LSA (ASBR)", 5: "AS-external-LSA", 7: "NSSA-external"}

IGMP_TIPOS = {0x11: "Membership Query", 0x12: "Report v1", 0x16: "Report v2",
              0x17: "Leave Group", 0x22: "Report v3"}

MULTICAST_CONOCIDAS = {
    "224.0.0.1": "todos los hosts de la subred",
    "224.0.0.2": "todos los routers de la subred",
    "224.0.0.5": "todos los routers OSPF",
    "224.0.0.6": "el DR y el BDR de OSPF",
    "224.0.0.9": "todos los routers RIPv2",
    "224.0.0.13": "PIM",
    "224.0.0.18": "VRRP",
    "224.0.0.22": "IGMPv3",
    "224.0.0.251": "mDNS",
}

DHCP_MSG_TYPES = {
    1: "Discover", 2: "Offer", 3: "Request", 4: "Decline",
    5: "ACK", 6: "NAK", 7: "Release", 8: "Inform",
}

ARP_OPS = {1: "request (petición)", 2: "reply (respuesta)",
           3: "RARP request", 4: "RARP reply"}

DIFFICULTY_LABELS = {
    "facil": "FÁCIL", "medio": "MEDIO", "dificil": "DIFÍCIL", "mixto": "MIXTA",
}


# ---------------------------------------------------------------------------
# Utilidades de formato
# ---------------------------------------------------------------------------

def mac_to_str(raw: bytes) -> str:
    return ":".join(f"{b:02x}" for b in raw)


def ip_to_str(raw: bytes) -> str:
    return ".".join(str(b) for b in raw)


def ipv6_to_str(raw: bytes) -> str:
    groups = [f"{raw[i] << 8 | raw[i + 1]:x}" for i in range(0, 16, 2)]
    return ":".join(groups)


def safe_ascii(data: bytes) -> str:
    return "".join(chr(b) if 32 <= b <= 126 else "." for b in data)


def hex_bytes(data: bytes) -> str:
    """Bytes separados por espacio, como se ven en el volcado."""
    return " ".join(f"{b:02x}" for b in data)


def hex_dump(data: bytes, with_ascii: bool = True, width: int = 16,
             highlight: Optional[Tuple[int, int]] = None) -> str:
    """Volcado hexadecimal clasico. highlight=(offset, size) marca un rango."""
    lines = []
    hi_start, hi_end = (-1, -1)
    if highlight:
        hi_start = highlight[0]
        hi_end = highlight[0] + highlight[1] - 1

    for base in range(0, len(data), width):
        chunk = data[base:base + width]
        cells = []
        for k, b in enumerate(chunk):
            pos = base + k
            cell = f"{b:02x}"
            if hi_start <= pos <= hi_end:
                cell = f"[{cell}]"
            else:
                cell = f" {cell} "
            cells.append(cell)
        hex_part = "".join(cells)
        if with_ascii:
            lines.append(f"  {base:04x}  {hex_part:<64}  |{safe_ascii(chunk)}|")
        else:
            lines.append(f"  {base:04x}  {hex_part}")
    return "\n".join(lines)


def off(n: int) -> str:
    """Offset en la notación que usa el volcado: 0x001a (26)."""
    return f"0x{n:04x} ({n})"


# ---------------------------------------------------------------------------
# Modelo: cada campo recuerda dónde vive dentro de la trama
# ---------------------------------------------------------------------------

@dataclass
class Field:
    """Un campo de cabecera, con su posición exacta en el volcado hexadecimal."""
    name: str          # clave interna, p.ej. "ttl"
    label: str         # nombre visible, p.ej. "TTL"
    layer: str         # "Ethernet", "IPv4", "TCP", "DNS", ...
    offset: int        # offset absoluto dentro de la trama
    size: int          # tamaño en bytes
    value: Any         # valor ya decodificado
    display: str       # cómo se escribe la respuesta correcta
    kind: str          # "int" | "hex" | "ip" | "mac" | "text" | "bits"
    note: str = ""     # explicación didáctica

    def raw(self, frame: bytes) -> bytes:
        return frame[self.offset:self.offset + self.size]

    def hex(self, frame: bytes) -> str:
        return hex_bytes(self.raw(frame))

    def rango(self) -> str:
        if self.size == 1:
            return f"0x{self.offset:04x}"
        return f"0x{self.offset:04x}-0x{self.offset + self.size - 1:04x}"


@dataclass
class Packet:
    """Un paquete: los bytes crudos más todo lo que supimos interpretar."""
    num: int
    ts: float
    raw: bytes
    fields: List[Field] = field(default_factory=list)
    layers: List[str] = field(default_factory=list)
    info: Dict[str, Any] = field(default_factory=dict)
    payload_offset: int = 0
    payload: bytes = b""
    truncado: bool = False
    linktype: int = 1

    def add(self, name, label, layer, offset, size, value, display=None,
            kind="int", note=""):
        if offset + size > len(self.raw):
            return None
        f = Field(name, label, layer, offset, size, value,
                  str(value) if display is None else display, kind, note)
        self.fields.append(f)
        self.info[name] = value
        return f

    def get(self, name) -> Optional[Field]:
        for f in self.fields:
            if f.name == name:
                return f
        return None

    def has(self, *names) -> bool:
        return all(n in self.info for n in names)

    def resumen(self) -> str:
        """Una línea corta, estilo lista de paquetes de Wireshark."""
        i = self.info
        src = i.get("src_ip") or i.get("arp_spa") or i.get("src_mac", "?")
        dst = i.get("dst_ip") or i.get("arp_tpa") or i.get("dst_mac", "?")
        proto = self.layers[-1] if self.layers else "?"
        det = ""
        if "ARP" in self.layers:
            if i.get("arp_oper") == 1:
                det = f"¿Quién tiene {i.get('arp_tpa')}? Díselo a {i.get('arp_spa')}"
            else:
                det = f"{i.get('arp_spa')} está en {i.get('arp_sha')}"
        elif "TCP" in self.layers:
            det = (f"{i.get('src_port')} -> {i.get('dst_port')} "
                   f"[{i.get('tcp_flags_str', '')}] seq={i.get('tcp_seq')} "
                   f"ack={i.get('tcp_ack')} win={i.get('tcp_window')}")
        elif "ICMP" in self.layers:
            det = (f"{ICMP_TYPES.get(i.get('icmp_type'), '?')} "
                   f"(type={i.get('icmp_type')}, code={i.get('icmp_code')})")
        elif "DHCP" in self.layers:
            det = f"DHCP {i.get('dhcp_msg_name')}"
        elif "DNS" in self.layers:
            if i.get("dns_qr") == 0:
                det = f"Consulta: {i.get('dns_qname')}"
            else:
                det = f"Respuesta: {i.get('dns_qname')}"
        elif "UDP" in self.layers:
            det = f"{i.get('src_port')} -> {i.get('dst_port')}"
        return f"#{self.num:<5} {src:>15} -> {dst:<15} {proto:<6} {det}"


# ---------------------------------------------------------------------------
# Lectura de archivos de captura, byte a byte (sin Scapy)
# ---------------------------------------------------------------------------

class CaptureError(Exception):
    pass


def leer_pcap_clasico(data: bytes) -> Tuple[List[Tuple[float, bytes]], int]:
    """Formato pcap clásico: cabecera global de 24 bytes + N registros."""
    magic = data[:4]
    if magic == b"\xd4\xc3\xb2\xa1":
        endian, div = "<", 1_000_000          # microsegundos, little endian
    elif magic == b"\xa1\xb2\xc3\xd4":
        endian, div = ">", 1_000_000          # microsegundos, big endian
    elif magic == b"\x4d\x3c\xb2\xa1":
        endian, div = "<", 1_000_000_000      # nanosegundos, little endian
    elif magic == b"\xa1\xb2\x3c\x4d":
        endian, div = ">", 1_000_000_000      # nanosegundos, big endian
    else:
        raise CaptureError("no es un pcap clásico")

    linktype = struct.unpack(endian + "I", data[20:24])[0]
    paquetes = []
    pos = 24
    while pos + 16 <= len(data):
        ts_sec, ts_frac, caplen, origlen = struct.unpack(endian + "IIII",
                                                         data[pos:pos + 16])
        pos += 16
        if caplen > len(data) - pos:
            caplen = len(data) - pos
        paquetes.append((ts_sec + ts_frac / div, data[pos:pos + caplen]))
        pos += caplen
    return paquetes, linktype


def leer_pcapng(data: bytes) -> Tuple[List[Tuple[float, bytes]], int]:
    """Formato pcapng: bloques encadenados. Leemos SHB, IDB, EPB y SPB."""
    if data[:4] != b"\x0a\x0d\x0d\x0a":
        raise CaptureError("no es un pcapng")

    endian = "<" if data[8:12] == b"\x4d\x3c\x2b\x1a" else ">"
    paquetes = []
    linktype = 1
    tsresol = 1_000_000
    pos = 0
    while pos + 12 <= len(data):
        btype, blen = struct.unpack(endian + "II", data[pos:pos + 8])
        if blen < 12 or pos + blen > len(data):
            break
        cuerpo = data[pos + 8:pos + blen - 4]

        if btype == 0x00000001 and len(cuerpo) >= 8:            # Interface Desc
            linktype = struct.unpack(endian + "H", cuerpo[:2])[0]
        elif btype == 0x00000006 and len(cuerpo) >= 20:         # Enhanced Packet
            _, ts_hi, ts_lo, caplen, _ = struct.unpack(endian + "IIIII",
                                                       cuerpo[:20])
            ts = ((ts_hi << 32) | ts_lo) / tsresol
            paquetes.append((ts, cuerpo[20:20 + caplen]))
        elif btype == 0x00000003 and len(cuerpo) >= 4:          # Simple Packet
            paquetes.append((0.0, cuerpo[4:]))

        pos += blen
    return paquetes, linktype


def cargar_captura(path: Path) -> List[Packet]:
    data = path.read_bytes()
    if len(data) < 24:
        raise CaptureError("archivo demasiado corto")

    if data[:4] == b"\x0a\x0d\x0d\x0a":
        crudos, linktype = leer_pcapng(data)
        formato = "pcapng"
    else:
        crudos, linktype = leer_pcap_clasico(data)
        formato = "pcap clásico"

    if linktype not in LINKTYPES:
        raise CaptureError(f"link-layer tipo {linktype} no soportado")

    paquetes = []
    for i, (ts, frame) in enumerate(crudos, 1):
        pkt = Packet(num=i, ts=ts, raw=frame, linktype=linktype)
        try:
            parse_frame(pkt)
        except Exception:
            pkt.truncado = True
        paquetes.append(pkt)

    if paquetes:
        paquetes[0].info["_formato"] = formato
    return paquetes


# ---------------------------------------------------------------------------
# Parsers: cada campo se registra con su offset dentro de la trama
# ---------------------------------------------------------------------------

LINKTYPES = {
    1: "Ethernet",
    0: "BSD loopback (NULL)",
    101: "IP crudo (RAW)",
    113: "Linux cooked (SLL)",
    228: "IPv4 crudo",
    229: "IPv6 crudo",
}


def parse_frame(pkt: Packet) -> None:
    """Elige el parser de capa 2 según el link-layer del archivo de captura."""
    lt = pkt.linktype
    if lt == 1:
        parse_ethernet(pkt)
    elif lt == 0:
        parse_loopback(pkt)
    elif lt == 113:
        parse_linux_sll(pkt)
    else:
        parse_ip_crudo(pkt, 0)


def parse_ip_crudo(pkt: Packet, base: int) -> None:
    """Sin cabecera de enlace: el volcado empieza directamente en IP."""
    d = pkt.raw
    if len(d) <= base:
        pkt.truncado = True
        return
    version = d[base] >> 4
    if version == 4:
        parse_ipv4(pkt, base)
    elif version == 6:
        parse_ipv6(pkt, base)
    else:
        pkt.payload_offset = base
        pkt.payload = d[base:]


def parse_loopback(pkt: Packet) -> None:
    """Link-layer NULL: 4 bytes con la familia de direcciones y después IP."""
    d = pkt.raw
    if len(d) < 4:
        pkt.truncado = True
        return
    pkt.layers.append("Loopback")
    familia = struct.unpack("<I", d[:4])[0]
    if familia > 0xFFFF:
        familia = struct.unpack(">I", d[:4])[0]
    pkt.add("loopback_af", "Familia de direcciones", "Loopback", 0, 4, familia,
            note="Esta captura es de la interfaz loopback, que no usa "
                 "Ethernet: en lugar de MACs, los primeros 4 bytes indican la "
                 "familia de direcciones (2 = IPv4, 24/28/30 = IPv6). Por eso "
                 "el volcado NO empieza con una MAC destino.")
    parse_ip_crudo(pkt, 4)


def parse_linux_sll(pkt: Packet) -> None:
    """Linux cooked capture: 16 bytes de cabecera, ethertype al final."""
    d = pkt.raw
    if len(d) < 16:
        pkt.truncado = True
        return
    pkt.layers.append("Linux SLL")
    ethertype = struct.unpack("!H", d[14:16])[0]
    pkt.add("ethertype", "EtherType", "Linux SLL", 14, 2, ethertype,
            display=f"0x{ethertype:04x}", kind="hex",
            note="Captura 'cooked' de Linux (interfaz 'any'): 16 bytes de "
                 "cabecera sintética en vez de la trama Ethernet real.")
    if ethertype == 0x0800:
        parse_ipv4(pkt, 16)
    elif ethertype == 0x86DD:
        parse_ipv6(pkt, 16)
    elif ethertype == 0x0806:
        parse_arp(pkt, 16)


def parse_ethernet(pkt: Packet) -> None:
    d = pkt.raw
    if len(d) < 14:
        pkt.truncado = True
        return
    pkt.layers.append("Ethernet")

    pkt.add("dst_mac", "MAC destino", "Ethernet", 0, 6, mac_to_str(d[0:6]),
            kind="mac",
            note="Los primeros 6 bytes de toda trama Ethernet son la MAC "
                 "destino. Por eso el volcado siempre empieza por ahí. Si vale "
                 "ff:ff:ff:ff:ff:ff es un broadcast: va a todos los hosts del "
                 "segmento.")
    pkt.add("src_mac", "MAC origen", "Ethernet", 6, 6, mac_to_str(d[6:12]),
            kind="mac",
            note="Bytes 6 a 11: la MAC de quien envía. Los 3 primeros bytes son "
                 "el OUI, que identifica al fabricante de la tarjeta de red.")

    ethertype = struct.unpack("!H", d[12:14])[0]
    pkt.add("ethertype", "EtherType", "Ethernet", 12, 2, ethertype,
            display=f"0x{ethertype:04x}", kind="hex",
            note=f"Bytes 12-13. Dice qué protocolo viene encima: 0x0800=IPv4, "
                 f"0x0806=ARP, 0x86dd=IPv6. Aquí vale 0x{ethertype:04x} = "
                 f"{ETHERTYPES.get(ethertype, 'desconocido')}. Es la bifurcación "
                 "que decide cómo leer el resto del volcado.")
    pkt.info["ethertype_name"] = ETHERTYPES.get(ethertype, "desconocido")

    if ethertype == 0x0800:
        parse_ipv4(pkt, 14)
    elif ethertype == 0x86DD:
        parse_ipv6(pkt, 14)
    elif ethertype == 0x0806:
        parse_arp(pkt, 14)
    else:
        pkt.payload_offset = 14
        pkt.payload = d[14:]


def parse_arp(pkt: Packet, base: int) -> None:
    d = pkt.raw
    if len(d) < base + 28:
        pkt.truncado = True
        return
    pkt.layers.append("ARP")

    htype = struct.unpack("!H", d[base:base + 2])[0]
    ptype = struct.unpack("!H", d[base + 2:base + 4])[0]
    hlen, plen = d[base + 4], d[base + 5]
    oper = struct.unpack("!H", d[base + 6:base + 8])[0]

    pkt.add("arp_htype", "Hardware type", "ARP", base, 2, htype,
            display=f"0x{htype:04x}", kind="hex",
            note="0x0001 = Ethernet. Casi siempre vale eso.")
    pkt.add("arp_ptype", "Protocol type", "ARP", base + 2, 2, ptype,
            display=f"0x{ptype:04x}", kind="hex",
            note="0x0800 = está resolviendo direcciones IPv4.")
    pkt.add("arp_hlen", "Hardware size", "ARP", base + 4, 1, hlen,
            note="6 bytes, el tamaño de una MAC.")
    pkt.add("arp_plen", "Protocol size", "ARP", base + 5, 1, plen,
            note="4 bytes, el tamaño de una IPv4.")
    pkt.add("arp_oper", "Operation", "ARP", base + 6, 2, oper,
            note=f"1 = request, 2 = reply. Aquí es {ARP_OPS.get(oper, oper)}. "
                 "Un reply que nadie pidió (gratuitous ARP) es la señal típica "
                 "de un intento de ARP spoofing.")
    pkt.add("arp_sha", "MAC del emisor", "ARP", base + 8, 6,
            mac_to_str(d[base + 8:base + 14]), kind="mac",
            note="Quién dice ser el dueño. En un ataque, esta es la MAC del "
                 "atacante mientras la IP de abajo es la de la víctima.")
    pkt.add("arp_spa", "IP del emisor", "ARP", base + 14, 4,
            ip_to_str(d[base + 14:base + 18]), kind="ip",
            note="La IP que el emisor reclama como suya.")
    pkt.add("arp_tha", "MAC del objetivo", "ARP", base + 18, 6,
            mac_to_str(d[base + 18:base + 24]), kind="mac",
            note="En un request va en ceros: es justo el dato que se pregunta.")
    pkt.add("arp_tpa", "IP del objetivo", "ARP", base + 24, 4,
            ip_to_str(d[base + 24:base + 28]), kind="ip",
            note="La IP por la que se pregunta (o a la que se responde).")

    pkt.info["arp_oper_name"] = ARP_OPS.get(oper, str(oper))
    pkt.payload_offset = base + 28
    pkt.payload = d[base + 28:]


def parse_ipv4(pkt: Packet, base: int) -> None:
    d = pkt.raw
    if len(d) < base + 20:
        pkt.truncado = True
        return
    pkt.layers.append("IPv4")

    primero = d[base]
    version = primero >> 4
    ihl = primero & 0x0F
    hdr_len = ihl * 4

    pkt.add("ip_version", "Versión IP", "IPv4", base, 1, version,
            note=f"Los 4 bits ALTOS del byte 0x{base:04x} "
                 f"(0x{primero:02x}). {primero:#04x} >> 4 = {version}. "
                 "Un 4 aquí significa IPv4; un 6, IPv6.")
    pkt.add("ip_ihl", "IHL", "IPv4", base, 1, ihl,
            note=f"Los 4 bits BAJOS del mismo byte 0x{primero:02x}: "
                 f"0x{primero:02x} & 0x0f = {ihl}. Cuenta palabras de 32 bits, "
                 f"así que la cabecera mide {ihl} x 4 = {hdr_len} bytes. "
                 "El mínimo es 5 (20 bytes); más de 5 significa que hay "
                 "opciones IP.")
    pkt.info["ip_header_len"] = hdr_len

    tos = d[base + 1]
    pkt.add("ip_tos", "TOS / DSCP", "IPv4", base + 1, 1, tos,
            display=f"0x{tos:02x}", kind="hex",
            note="Calidad de servicio. Los 6 bits altos son el DSCP.")

    total_len = struct.unpack("!H", d[base + 2:base + 4])[0]
    pkt.add("ip_total_length", "Longitud total", "IPv4", base + 2, 2, total_len,
            note=f"Bytes {base + 2}-{base + 3}: {hex_bytes(d[base+2:base+4])} = "
                 f"{total_len}. Es la cabecera IP MÁS los datos, sin contar los "
                 "14 bytes de Ethernet. El payload de capa 4 mide "
                 f"{total_len} - {hdr_len} = {total_len - hdr_len} bytes.")

    ident = struct.unpack("!H", d[base + 4:base + 6])[0]
    pkt.add("ip_id", "Identification", "IPv4", base + 4, 2, ident,
            display=f"0x{ident:04x}", kind="hex",
            note="Identifica el datagrama original. Todos los fragmentos de un "
                 "mismo paquete comparten este valor: así el receptor sabe "
                 "cuáles rearmar juntos.")

    flags_frag = struct.unpack("!H", d[base + 6:base + 8])[0]
    flags = (flags_frag >> 13) & 0x7
    frag_off = flags_frag & 0x1FFF
    df = 1 if flags & 0b010 else 0
    mf = 1 if flags & 0b001 else 0

    pkt.add("ip_flags", "Flags IP", "IPv4", base + 6, 1, flags,
            display=f"0b{flags:03b}", kind="bits",
            note=f"Los 3 bits altos de {hex_bytes(d[base+6:base+8])}: "
                 f"bit 0 reservado, bit 1 = DF (no fragmentar) = {df}, "
                 f"bit 2 = MF (vienen más fragmentos) = {mf}.")
    pkt.add("ip_df", "Bit DF", "IPv4", base + 6, 1, df,
            note="DF=1 prohíbe fragmentar. Si un router necesita fragmentar y "
                 "DF está activo, descarta el paquete y responde ICMP type 3 "
                 "code 4. Es la base del descubrimiento de MTU.")
    pkt.add("ip_mf", "Bit MF", "IPv4", base + 6, 1, mf,
            note="MF=1 significa que este NO es el último fragmento. El último "
                 "fragmento lleva MF=0 pero fragment offset distinto de cero.")
    pkt.add("ip_frag_offset", "Fragment offset", "IPv4", base + 6, 2, frag_off,
            note=f"Los 13 bits bajos: {frag_off}. Se mide en unidades de 8 "
                 f"bytes, así que este fragmento empieza en el byte "
                 f"{frag_off * 8} del datagrama original.")

    ttl = d[base + 8]
    pkt.add("ip_ttl", "TTL", "IPv4", base + 8, 1, ttl,
            note=f"Byte 0x{base + 8:04x} = 0x{ttl:02x} = {ttl}. Cada router que "
                 "reenvía el paquete lo baja en 1; al llegar a 0 se descarta y "
                 "se responde ICMP Time Exceeded. Valores iniciales típicos: "
                 "64 (Linux/macOS), 128 (Windows), 255 (equipos de red). "
                 f"Si vale {ttl}, probablemente pasó por "
                 f"{(64 - ttl) if ttl <= 64 else (128 - ttl) if ttl <= 128 else 0} "
                 "saltos desde un origen típico.")

    proto = d[base + 9]
    pkt.add("ip_proto", "Protocolo", "IPv4", base + 9, 1, proto,
            note=f"Byte 0x{base + 9:04x} = {proto} = "
                 f"{IP_PROTOCOLS.get(proto, 'desconocido')}. Es lo que te dice "
                 "cómo interpretar los bytes que siguen a la cabecera IP: "
                 "1=ICMP, 6=TCP, 17=UDP.")
    pkt.info["ip_proto_name"] = IP_PROTOCOLS.get(proto, "desconocido")

    cks = struct.unpack("!H", d[base + 10:base + 12])[0]
    pkt.add("ip_checksum", "Checksum IP", "IPv4", base + 10, 2, cks,
            display=f"0x{cks:04x}", kind="hex",
            note="Suma de verificación SOLO de la cabecera IP (no de los "
                 "datos). Como el TTL cambia en cada salto, cada router debe "
                 "recalcularla.")

    pkt.add("src_ip", "IP origen", "IPv4", base + 12, 4,
            ip_to_str(d[base + 12:base + 16]), kind="ip",
            note=f"4 bytes: {hex_bytes(d[base+12:base+16])}. Cada byte del "
                 "volcado es un número del 0 al 255 de la IP decimal.")
    pkt.add("dst_ip", "IP destino", "IPv4", base + 16, 4,
            ip_to_str(d[base + 16:base + 20]), kind="ip",
            note=f"4 bytes: {hex_bytes(d[base+16:base+20])}. Por ejemplo, "
                 "0xc0 = 192, 0xa8 = 168, así que c0 a8 ... es una 192.168.x.x "
                 "(rango privado).")

    if ihl > 5:
        pkt.add("ip_options", "Opciones IP", "IPv4", base + 20, (ihl - 5) * 4,
                hex_bytes(d[base + 20:base + hdr_len]), kind="hex",
                note="La cabecera mide más de 20 bytes: hay opciones IP "
                     "(record route, timestamp, source routing...).")

    siguiente = base + hdr_len
    pkt.payload_offset = siguiente
    pkt.payload = d[siguiente:]
    if proto == 1:
        parse_icmp(pkt, siguiente)
    elif proto == 6:
        parse_tcp(pkt, siguiente)
    elif proto == 17:
        parse_udp(pkt, siguiente)
    elif proto == 89:
        parse_ospf(pkt, siguiente)
    elif proto == 2:
        parse_igmp(pkt, siguiente)


def parse_ipv6(pkt: Packet, base: int) -> None:
    d = pkt.raw
    if len(d) < base + 40:
        pkt.truncado = True
        return
    pkt.layers.append("IPv6")

    primeros4 = struct.unpack("!I", d[base:base + 4])[0]
    version = (primeros4 >> 28) & 0xF
    tclass = (primeros4 >> 20) & 0xFF
    flow = primeros4 & 0xFFFFF

    pkt.add("ip_version", "Versión IP", "IPv6", base, 1, version,
            note="Los 4 bits altos del primer byte. Un 6 = IPv6.")
    pkt.add("ip6_tclass", "Traffic class", "IPv6", base, 2, tclass,
            display=f"0x{tclass:02x}", kind="hex",
            note="Equivalente al TOS/DSCP de IPv4.")
    pkt.add("ip6_flow", "Flow label", "IPv6", base + 1, 3, flow,
            display=f"0x{flow:05x}", kind="hex",
            note="Etiqueta de flujo: permite tratar todos los paquetes de una "
                 "misma conversación con la misma política, sin mirar puertos.")

    plen = struct.unpack("!H", d[base + 4:base + 6])[0]
    pkt.add("ip6_plen", "Payload length", "IPv6", base + 4, 2, plen,
            note="A diferencia de IPv4, aquí NO se cuenta la cabecera: son solo "
                 "los bytes que vienen después de los 40 fijos.")

    nh = d[base + 6]
    pkt.add("ip_proto", "Next header", "IPv6", base + 6, 1, nh,
            note=f"{nh} = {IP_PROTOCOLS.get(nh, 'desconocido')}. Cumple el mismo "
                 "papel que el campo 'protocolo' de IPv4.")
    pkt.info["ip_proto_name"] = IP_PROTOCOLS.get(nh, "desconocido")

    hop = d[base + 7]
    pkt.add("ip_ttl", "Hop limit", "IPv6", base + 7, 1, hop,
            note="Es el TTL de IPv6, con el nombre que siempre debió tener: "
                 "cuenta saltos, no tiempo.")

    pkt.add("src_ip", "IP origen", "IPv6", base + 8, 16,
            ipv6_to_str(d[base + 8:base + 24]), kind="ip",
            note="16 bytes seguidos del volcado, agrupados de dos en dos.")
    pkt.add("dst_ip", "IP destino", "IPv6", base + 24, 16,
            ipv6_to_str(d[base + 24:base + 40]), kind="ip",
            note="Otros 16 bytes. Una cabecera IPv6 mide 40 bytes fijos, sin "
                 "IHL ni checksum: por eso es más rápida de procesar.")

    siguiente = base + 40
    if nh == 58:
        parse_icmp(pkt, siguiente, ipv6=True)
    elif nh == 6:
        parse_tcp(pkt, siguiente)
    elif nh == 17:
        parse_udp(pkt, siguiente)
    else:
        pkt.payload_offset = siguiente
        pkt.payload = d[siguiente:]


def parse_icmp(pkt: Packet, base: int, ipv6: bool = False) -> None:
    d = pkt.raw
    if len(d) < base + 4:
        pkt.truncado = True
        return
    nombre = "ICMPv6" if ipv6 else "ICMP"
    pkt.layers.append("ICMP")

    tipo, code = d[base], d[base + 1]
    cks = struct.unpack("!H", d[base + 2:base + 4])[0]

    pkt.add("icmp_type", "Tipo ICMP", nombre, base, 1, tipo,
            note=f"Byte 0x{base:04x} = {tipo} = "
                 f"{ICMP_TYPES.get(tipo, 'desconocido')}. 8 = Echo Request "
                 "(ping de ida), 0 = Echo Reply (la vuelta), 3 = destino "
                 "inalcanzable, 11 = TTL agotado.")
    nota_code = ICMP_UNREACH_CODES.get(code, "") if tipo == 3 else ""
    pkt.add("icmp_code", "Código ICMP", nombre, base + 1, 1, code,
            note=f"Precisa el motivo dentro del tipo. "
                 + (f"Con type=3, code={code} significa: {nota_code}."
                    if nota_code else
                    "En Echo Request/Reply siempre vale 0."))
    pkt.add("icmp_checksum", "Checksum ICMP", nombre, base + 2, 2, cks,
            display=f"0x{cks:04x}", kind="hex",
            note="Cubre la cabecera ICMP y sus datos.")

    pkt.info["icmp_type_name"] = ICMP_TYPES.get(tipo, "desconocido")

    if tipo in (0, 8) and len(d) >= base + 8:
        ident = struct.unpack("!H", d[base + 4:base + 6])[0]
        seq = struct.unpack("!H", d[base + 6:base + 8])[0]
        pkt.add("icmp_id", "Identifier", nombre, base + 4, 2, ident,
                note="Identifica la sesión de ping. La respuesta repite el "
                     "mismo valor, y así el emisor empareja ida con vuelta.")
        pkt.add("icmp_seq", "Sequence number", nombre, base + 6, 2, seq,
                note="Va subiendo de a uno en cada ping. Un hueco en esta "
                     "secuencia significa que un paquete se perdió.")
        cuerpo = base + 8
    elif len(d) >= base + 8:
        pkt.add("icmp_rest", "Resto de la cabecera", nombre, base + 4, 4,
                hex_bytes(d[base + 4:base + 8]), kind="hex",
                note="En un 'destino inalcanzable' suele ir en ceros, y después "
                     "vienen la cabecera IP y los 8 primeros bytes del paquete "
                     "original que provocó el error.")
        cuerpo = base + 8
    else:
        cuerpo = base + 4

    pkt.payload_offset = cuerpo
    pkt.payload = d[cuerpo:]


def parse_tcp(pkt: Packet, base: int) -> None:
    d = pkt.raw
    if len(d) < base + 20:
        pkt.truncado = True
        return
    pkt.layers.append("TCP")

    sport, dport = struct.unpack("!HH", d[base:base + 4])
    seq = struct.unpack("!I", d[base + 4:base + 8])[0]
    ack = struct.unpack("!I", d[base + 8:base + 12])[0]
    off_flags = struct.unpack("!H", d[base + 12:base + 14])[0]
    data_offset = (off_flags >> 12) & 0xF
    hdr_len = data_offset * 4
    flags = off_flags & 0x1FF
    window = struct.unpack("!H", d[base + 14:base + 16])[0]
    cks = struct.unpack("!H", d[base + 16:base + 18])[0]
    urg = struct.unpack("!H", d[base + 18:base + 20])[0]

    svc_s = WELL_KNOWN_PORTS.get(sport, "")
    svc_d = WELL_KNOWN_PORTS.get(dport, "")
    pkt.add("src_port", "Puerto origen", "TCP", base, 2, sport,
            note=f"2 bytes: {hex_bytes(d[base:base+2])} = {sport}"
                 + (f" ({svc_s})." if svc_s else ". Un puerto alto suele ser el "
                    "puerto efímero del cliente."))
    pkt.add("dst_port", "Puerto destino", "TCP", base + 2, 2, dport,
            note=f"2 bytes: {hex_bytes(d[base+2:base+4])} = {dport}"
                 + (f" ({svc_d}). Los puertos bien conocidos identifican el "
                    "servicio sin mirar el payload." if svc_d else "."))

    pkt.add("tcp_seq", "Sequence number", "TCP", base + 4, 4, seq,
            note=f"4 bytes: {hex_bytes(d[base+4:base+8])} = {seq}. TCP numera "
                 "BYTES, no paquetes: este es el número del primer byte de "
                 "datos que va en este segmento. En el SYN es el ISN, un valor "
                 "inicial aleatorio (aleatorio para que un atacante no pueda "
                 "predecirlo e inyectar datos en la conexión).")
    pkt.add("tcp_ack", "Acknowledgment number", "TCP", base + 8, 4, ack,
            note=f"4 bytes: {hex_bytes(d[base+8:base+12])} = {ack}. Es el "
                 "número del SIGUIENTE byte que se espera recibir, así que "
                 "confirma de forma acumulativa todo lo anterior. Solo tiene "
                 "sentido si el bit ACK está en 1.")

    pkt.add("tcp_data_offset", "Data offset", "TCP", base + 12, 1, data_offset,
            note=f"Los 4 bits ALTOS del byte 0x{base + 12:04x} "
                 f"(0x{d[base+12]:02x} >> 4 = {data_offset}). Como el IHL de "
                 f"IP, cuenta palabras de 32 bits: la cabecera TCP mide "
                 f"{data_offset} x 4 = {hdr_len} bytes. Si es mayor que 5, hay "
                 "opciones TCP (MSS, window scale, SACK permitted, timestamps).")
    pkt.info["tcp_header_len"] = hdr_len

    nombres = [("fin", 0x001, "FIN"), ("syn", 0x002, "SYN"), ("rst", 0x004, "RST"),
               ("psh", 0x008, "PSH"), ("ack", 0x010, "ACK"), ("urg", 0x020, "URG"),
               ("ece", 0x040, "ECE"), ("cwr", 0x080, "CWR"), ("ns", 0x100, "NS")]
    activos = [txt for _, bit, txt in nombres if flags & bit]
    flags_str = ", ".join(reversed(activos)) if activos else "ninguna"

    pkt.add("tcp_flags", "Flags TCP", "TCP", base + 13, 1, flags & 0xFF,
            display=f"0x{flags & 0xFF:02x}", kind="hex",
            note=f"Byte 0x{base + 13:04x} = 0x{d[base+13]:02x} = "
                 f"0b{d[base+13]:08b}. Cada bit es una flag, de la más baja a "
                 "la más alta: FIN(0x01) SYN(0x02) RST(0x04) PSH(0x08) "
                 f"ACK(0x10) URG(0x20) ECE(0x40) CWR(0x80). Activas: "
                 f"{flags_str}.")
    pkt.info["tcp_flags_str"] = flags_str
    for clave, bit, txt in nombres:
        pkt.info[f"tcp_{clave}"] = 1 if flags & bit else 0

    pkt.add("tcp_window", "Window", "TCP", base + 14, 2, window,
            note=f"2 bytes: {hex_bytes(d[base+14:base+16])} = {window}. Es la "
                 "ventana de recepción (rwnd): cuántos bytes más puede mandarle "
                 "el otro extremo sin esperar confirmación. Es el control de "
                 "flujo, y es una ventana deslizante. Si se negoció window "
                 "scaling en el handshake, el valor real es window x 2^s.")
    pkt.add("tcp_checksum", "Checksum TCP", "TCP", base + 16, 2, cks,
            display=f"0x{cks:04x}", kind="hex",
            note="Cubre la cabecera TCP, los datos y un pseudo-encabezado con "
                 "las IPs. Por eso TCP detecta si alguien alteró las "
                 "direcciones IP.")
    pkt.add("tcp_urgent", "Urgent pointer", "TCP", base + 18, 2, urg,
            note="Solo se usa si la flag URG está activa. En la práctica casi "
                 "nunca se usa.")

    if data_offset > 5 and len(d) >= base + hdr_len:
        pkt.add("tcp_options", "Opciones TCP", "TCP", base + 20, hdr_len - 20,
                hex_bytes(d[base + 20:base + hdr_len]), kind="hex",
                note="Aquí viven MSS (kind 2), Window Scale (kind 3), SACK "
                     "permitted (kind 4) y Timestamps (kind 8). Cada opción es "
                     "kind + length + valor.")
        parse_tcp_options(pkt, base + 20, hdr_len - 20)

    siguiente = base + hdr_len
    pkt.payload_offset = siguiente
    pkt.payload = d[siguiente:]
    detectar_aplicacion(pkt, sport, dport)


def parse_tcp_options(pkt: Packet, base: int, largo: int) -> None:
    """Recorre las opciones TCP; la más interesante es el window scale."""
    d = pkt.raw
    pos = base
    fin = base + largo
    while pos < fin and pos < len(d):
        kind = d[pos]
        if kind == 0:      # End of option list
            break
        if kind == 1:      # NOP de relleno
            pos += 1
            continue
        if pos + 1 >= len(d):
            break
        length = d[pos + 1]
        if length < 2:
            break
        if kind == 2 and length == 4 and pos + 4 <= len(d):
            mss = struct.unpack("!H", d[pos + 2:pos + 4])[0]
            pkt.add("tcp_mss", "MSS (opción TCP)", "TCP", pos + 2, 2, mss,
                    note="Maximum Segment Size: el mayor bloque de datos que "
                         "este extremo acepta por segmento. Se anuncia solo en "
                         "los paquetes SYN.")
        elif kind == 3 and length == 3 and pos + 3 <= len(d):
            shift = d[pos + 2]
            pkt.add("tcp_wscale", "Window scale (opción TCP)", "TCP",
                    pos + 2, 1, shift,
                    note=f"Factor de escala s={shift}: la ventana real es "
                         f"window x 2^{shift} = window x {2 ** shift}. Existe "
                         "porque el campo window es de 16 bits y 65535 bytes no "
                         "alcanzan en enlaces rápidos con latencia alta.")
        pos += length


def parse_udp(pkt: Packet, base: int) -> None:
    d = pkt.raw
    if len(d) < base + 8:
        pkt.truncado = True
        return
    pkt.layers.append("UDP")

    sport, dport, length, cks = struct.unpack("!HHHH", d[base:base + 8])
    svc_s = WELL_KNOWN_PORTS.get(sport, "")
    svc_d = WELL_KNOWN_PORTS.get(dport, "")

    pkt.add("src_port", "Puerto origen", "UDP", base, 2, sport,
            note=f"{hex_bytes(d[base:base+2])} = {sport}"
                 + (f" ({svc_s})." if svc_s else "."))
    pkt.add("dst_port", "Puerto destino", "UDP", base + 2, 2, dport,
            note=f"{hex_bytes(d[base+2:base+4])} = {dport}"
                 + (f" ({svc_d})." if svc_d else "."))
    pkt.add("udp_length", "Longitud UDP", "UDP", base + 4, 2, length,
            note=f"Incluye los 8 bytes de la cabecera UDP, así que los datos "
                 f"miden {length} - 8 = {length - 8} bytes. Ojo con la "
                 "diferencia: la longitud total de IPv4 sí cuenta la cabecera "
                 "IP, y el payload length de IPv6 no cuenta la suya.")
    pkt.add("udp_checksum", "Checksum UDP", "UDP", base + 6, 2, cks,
            display=f"0x{cks:04x}", kind="hex",
            note="En IPv4 es opcional (0x0000 significa 'sin checksum'); en "
                 "IPv6 es obligatorio.")

    siguiente = base + 8
    pkt.payload_offset = siguiente
    pkt.payload = d[siguiente:]
    detectar_aplicacion(pkt, sport, dport)


def detectar_aplicacion(pkt: Packet, sport: int, dport: int) -> None:
    puertos = {sport, dport}
    payload = pkt.payload
    pkt.info["payload_len"] = len(payload)
    pkt.info["payload_ascii"] = safe_ascii(payload)
    pkt.info["payload_hex"] = payload.hex()

    if 520 in puertos:
        parse_rip(pkt, pkt.payload_offset)
    elif 53 in puertos or 5353 in puertos:
        parse_dns(pkt, pkt.payload_offset)
    elif puertos & {67, 68}:
        parse_dhcp(pkt, pkt.payload_offset)
    elif payload[:8].startswith((b"GET ", b"POST ", b"HTTP/", b"PUT ",
                                b"HEAD ", b"DELETE ")):
        parse_http(pkt, pkt.payload_offset)


def parse_dns_name(data: bytes, offset: int) -> Tuple[str, int]:
    """Lee un nombre DNS, siguiendo punteros de compresión (0xC0)."""
    etiquetas = []
    salto = False
    fin_real = offset
    vistos = set()
    while offset < len(data):
        if offset in vistos:
            break
        vistos.add(offset)
        largo = data[offset]
        if largo == 0:
            offset += 1
            break
        if largo & 0xC0 == 0xC0:
            if offset + 1 >= len(data):
                break
            puntero = ((largo & 0x3F) << 8) | data[offset + 1]
            if not salto:
                fin_real = offset + 2
            offset = puntero
            salto = True
            continue
        offset += 1
        etiquetas.append(data[offset:offset + largo].decode(errors="replace"))
        offset += largo
    return ".".join(etiquetas), (fin_real if salto else offset)


def parse_dns(pkt: Packet, base: int) -> None:
    d = pkt.raw
    if len(d) < base + 12:
        return
    pkt.layers.append("DNS")

    txid = struct.unpack("!H", d[base:base + 2])[0]
    flags = struct.unpack("!H", d[base + 2:base + 4])[0]
    qd, an, ns, ar = struct.unpack("!HHHH", d[base + 4:base + 12])
    qr = (flags >> 15) & 1
    opcode = (flags >> 11) & 0xF
    aa = (flags >> 10) & 1
    tc = (flags >> 9) & 1
    rd = (flags >> 8) & 1
    ra = (flags >> 7) & 1
    rcode = flags & 0xF

    pkt.add("dns_txid", "Transaction ID", "DNS", base, 2, txid,
            display=f"0x{txid:04x}", kind="hex",
            note="Identificador de 16 bits que empareja la consulta con su "
                 "respuesta. Es la pieza clave del DNS spoofing: quien quiera "
                 "falsificar una respuesta tiene que acertar este número (y el "
                 "puerto origen) antes de que llegue la respuesta legítima.")
    pkt.add("dns_flags", "Flags DNS", "DNS", base + 2, 2, flags,
            display=f"0x{flags:04x}", kind="hex",
            note=f"0x{flags:04x} = 0b{flags:016b}. Bit 15 = QR ({qr}: 0 "
                 f"consulta, 1 respuesta), bits 11-14 opcode, bit 10 AA "
                 f"(autoritativa={aa}), bit 9 TC (truncada={tc}), bit 8 RD "
                 f"(recursión deseada={rd}), bit 7 RA (recursión "
                 f"disponible={ra}), bits 0-3 rcode={rcode}.")
    pkt.add("dns_qr", "Bit QR", "DNS", base + 2, 1, qr,
            note="0 = es una consulta, 1 = es una respuesta. Es el bit más "
                 "alto del primer byte de flags.")
    pkt.add("dns_rcode", "Response code", "DNS", base + 3, 1, rcode,
            note=f"{rcode} = {DNS_RCODES.get(rcode, 'desconocido')}. Son los 4 "
                 "bits bajos del segundo byte de flags.")
    pkt.add("dns_qdcount", "Questions", "DNS", base + 4, 2, qd,
            note="Cuántas preguntas trae la sección de consultas.")
    pkt.add("dns_ancount", "Answer RRs", "DNS", base + 6, 2, an,
            note="Cuántos registros de respuesta vienen. En una consulta vale "
                 "0; en la respuesta, uno o más.")
    pkt.add("dns_nscount", "Authority RRs", "DNS", base + 8, 2, ns)
    pkt.add("dns_arcount", "Additional RRs", "DNS", base + 10, 2, ar)

    pkt.info["dns_qr"] = qr
    pos = base + 12
    if qd > 0 and pos < len(d):
        nombre, fin = parse_dns_name(d, pos)
        largo_nombre = fin - pos
        if largo_nombre > 0:
            pkt.add("dns_qname", "Nombre consultado", "DNS", pos, largo_nombre,
                    nombre, kind="text",
                    note="En el volcado NO aparece con puntos: se codifica como "
                         "una serie de etiquetas 'longitud + texto'. Por "
                         "ejemplo 07 65 78 61 6d 70 6c 65 03 63 6f 6d 00 es "
                         "7,'example',3,'com',0 -> example.com. El 00 final "
                         "cierra el nombre.")
        if fin + 4 <= len(d):
            qtype, qclass = struct.unpack("!HH", d[fin:fin + 4])
            pkt.add("dns_qtype", "QTYPE", "DNS", fin, 2, qtype,
                    note=f"{qtype} = {DNS_TYPES.get(qtype, 'desconocido')}. "
                         "1=A (IPv4), 28=AAAA (IPv6), 5=CNAME, 15=MX, 12=PTR.")
            pkt.add("dns_qclass", "QCLASS", "DNS", fin + 4 - 2, 2, qclass,
                    note="1 = IN (Internet). Prácticamente siempre es 1.")


def parse_dhcp(pkt: Packet, base: int) -> None:
    d = pkt.raw
    if len(d) < base + 240:
        return
    pkt.layers.append("DHCP")

    op = d[base]
    pkt.add("dhcp_op", "Message op code", "DHCP/BOOTP", base, 1, op,
            note="1 = BOOTREQUEST (lo manda el cliente), 2 = BOOTREPLY (lo "
                 "manda el servidor).")
    xid = struct.unpack("!I", d[base + 4:base + 8])[0]
    pkt.add("dhcp_xid", "Transaction ID", "DHCP/BOOTP", base + 4, 4, xid,
            display=f"0x{xid:08x}", kind="hex",
            note="Empareja los cuatro mensajes del ciclo DORA entre sí.")
    pkt.add("dhcp_ciaddr", "Client IP", "DHCP/BOOTP", base + 12, 4,
            ip_to_str(d[base + 12:base + 16]), kind="ip",
            note="La IP que el cliente ya tenía. En un Discover va en 0.0.0.0, "
                 "porque justamente todavía no tiene ninguna.")
    pkt.add("dhcp_yiaddr", "Your IP", "DHCP/BOOTP", base + 16, 4,
            ip_to_str(d[base + 16:base + 20]), kind="ip",
            note="La IP que el servidor le ASIGNA al cliente. Es el dato más "
                 "importante del Offer y del ACK.")
    pkt.add("dhcp_siaddr", "Server IP", "DHCP/BOOTP", base + 20, 4,
            ip_to_str(d[base + 20:base + 24]), kind="ip")
    pkt.add("dhcp_chaddr", "MAC del cliente", "DHCP/BOOTP", base + 28, 6,
            mac_to_str(d[base + 28:base + 34]), kind="mac",
            note="El servidor identifica al cliente por esta MAC, no por su IP "
                 "(que aún no tiene).")

    magic = d[base + 236:base + 240]
    pkt.add("dhcp_magic", "Magic cookie", "DHCP/BOOTP", base + 236, 4,
            hex_bytes(magic), kind="hex",
            note="Siempre vale 63 82 53 63. Es lo que distingue a un DHCP de un "
                 "BOOTP antiguo, y marca dónde empiezan las opciones.")

    pos = base + 240
    while pos + 1 < len(d):
        code = d[pos]
        if code == 255:
            break
        if code == 0:
            pos += 1
            continue
        largo = d[pos + 1]
        if code == 53 and largo >= 1 and pos + 2 < len(d):
            tipo = d[pos + 2]
            pkt.add("dhcp_msg_type", "Tipo de mensaje DHCP", "DHCP", pos + 2, 1,
                    tipo,
                    note=f"Opción 53. {tipo} = "
                         f"{DHCP_MSG_TYPES.get(tipo, 'desconocido')}. Es lo que "
                         "convierte al paquete en Discover, Offer, Request o "
                         "ACK dentro del ciclo DORA.")
            pkt.info["dhcp_msg_name"] = DHCP_MSG_TYPES.get(tipo, str(tipo))
        pos += 2 + largo


def parse_http(pkt: Packet, base: int) -> None:
    pkt.layers.append("HTTP")
    datos = pkt.payload
    corte = datos.find(b"\r\n")
    linea = datos[:corte if corte > 0 else min(len(datos), 80)]
    pkt.add("http_line", "Primera línea HTTP", "HTTP", base, len(linea),
            linea.decode(errors="replace"), kind="text",
            note="HTTP es texto plano: en la columna ASCII del volcado se lee "
                 "directamente. Por eso una captura de HTTP sin TLS expone "
                 "rutas, cabeceras, cookies y credenciales.")


def checksum_ipv4(cabecera: bytes) -> int:
    """Calcula el checksum de una cabecera IPv4 (complemento a uno de 16 bits)."""
    if len(cabecera) % 2:
        cabecera += b"\x00"
    total = 0
    for i in range(0, len(cabecera), 2):
        total += (cabecera[i] << 8) | cabecera[i + 1]
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def checksum_valido(pkt: Packet) -> Optional[bool]:
    """Verifica el checksum de la cabecera IPv4 del paquete, si la tiene."""
    f = pkt.get("ip_checksum")
    if f is None or "IPv4" not in pkt.layers:
        return None
    inicio = pkt.get("ip_version").offset
    largo = pkt.info.get("ip_header_len", 20)
    cab = bytearray(pkt.raw[inicio:inicio + largo])
    if len(cab) < largo:
        return None
    cab[10] = 0
    cab[11] = 0
    return checksum_ipv4(bytes(cab)) == f.value


# ---------------------------------------------------------------------------
# Motor del quiz
# ---------------------------------------------------------------------------

def normalizar(texto: str) -> str:
    return " ".join(str(texto).strip().lower().split())


def a_entero(valor: Any) -> Optional[int]:
    """Acepta 26, 0x1a, 1a o 0b1010. None si no es un número reconocible."""
    if isinstance(valor, int):
        return valor
    v = str(valor).strip().lower().replace(" ", "").replace("_", "")
    if not v:
        return None
    for prefijo, base in (("0x", 16), ("0b", 2), ("0o", 8)):
        if v.startswith(prefijo):
            try:
                return int(v[2:], base)
            except ValueError:
                return None
    try:
        return int(v, 10)
    except ValueError:
        pass
    try:
        return int(v, 16)          # hex escrito sin el prefijo 0x
    except ValueError:
        return None


def coincide(respuesta: str, esperado: Any, kind: str = "int") -> bool:
    """Compara con la tolerancia adecuada según el tipo de campo."""
    r = str(respuesta).strip()
    if not r:
        return False

    if kind in ("int", "hex", "bits"):
        # el mismo número vale en decimal, en hex (0x1a o 1a) o en binario
        real = a_entero(esperado)
        dado = a_entero(r)
        if dado is not None and real is not None and dado == real:
            return True
        if kind == "hex" and real is not None:
            # en un campo hexadecimal, "0800" se lee como hex, no como 800
            try:
                if int(re.sub(r"[^0-9a-f]", "", r.lower()) or "z", 16) == real:
                    return True
            except ValueError:
                pass
        if dado is not None and real is not None:
            return False
        return normalizar(r) == normalizar(esperado)

    if kind == "mac":
        limpio = re.sub(r"[^0-9a-f]", "", r.lower())
        return limpio == re.sub(r"[^0-9a-f]", "", str(esperado).lower())

    if kind == "bytes":
        limpio = re.sub(r"[^0-9a-f]", "", r.lower())
        return limpio == re.sub(r"[^0-9a-f]", "", str(esperado).lower())

    return normalizar(r) == normalizar(esperado)


COMANDOS_AYUDA = ("form", "formulario", "guia", "guía", "ayuda", "?")


def _consultar_guia(argumento: str = "") -> None:
    """Abre la guía de referencia sin perder la pregunta en curso."""
    if not argumento:
        abrir_panel_referencia()
        return
    # con un nombre de sección detrás, se imprime aquí mismo sin abrir ventana
    import subprocess
    if not RUTA_REFERENCIA.exists():
        print(f"  No encuentro '{RUTA_REFERENCIA.name}'.")
        return
    r = subprocess.run([sys.executable, str(RUTA_REFERENCIA), argumento],
                       capture_output=True, text=True)
    print(r.stdout or r.stderr)


def leer_respuesta(prompt: str) -> str:
    """Pide la respuesta, atendiendo antes los comandos de ayuda.

    Escribir «form» abre la guía en una ventana aparte; «form tcp» imprime esa
    sección aquí mismo. La pregunta sigue esperando después.
    """
    while True:
        bruto = input(prompt).strip()
        partes = bruto.lower().split(None, 1)
        if partes and partes[0] in COMANDOS_AYUDA:
            _consultar_guia(partes[1].strip() if len(partes) > 1 else "")
            continue
        return bruto


@dataclass
class Question:
    prompt: str
    kind: str                       # "mcq" | "text"
    answer: Any
    options: List[str] = field(default_factory=list)
    explain: str = ""
    difficulty: str = "facil"
    category: str = "general"
    answer_kind: str = "int"        # solo para las de texto
    dump: str = ""                  # volcado que se muestra antes del enunciado

    def preguntar(self) -> bool:
        print("\n" + THIN)
        etiqueta = DIFFICULTY_LABELS.get(self.difficulty, self.difficulty.upper())
        print(f"[{etiqueta} | {self.category}]")
        if self.dump:
            print(self.dump)
        print(self.prompt)

        if self.kind == "mcq":
            letras = "ABCDEFGH"
            for i, opt in enumerate(self.options):
                print(f"  {letras[i]}) {opt}")
            bruto = leer_respuesta("Tu respuesta (letra): ").upper()
            ok = (bruto in letras[:len(self.options)]
                  and letras.index(bruto) == self.answer)
            correcta = f"{letras[self.answer]}) {self.options[self.answer]}"
        else:
            bruto = leer_respuesta("Tu respuesta: ")
            ok = coincide(bruto, self.answer, self.answer_kind)
            correcta = str(self.answer)

        if ok:
            print(">> Correcto.")
        else:
            print(f">> Incorrecto. Respuesta correcta: {correcta}")
        if self.explain:
            print(f"   {self.explain}")
        return ok


def mcq_opciones(correcta: str, incorrectas: List[str], n: int = 4
                 ) -> Tuple[List[str], int]:
    """Arma las opciones de una pregunta de selección múltiple."""
    vistos = {normalizar(correcta)}
    limpias = []
    for x in incorrectas:
        if normalizar(x) not in vistos:
            vistos.add(normalizar(x))
            limpias.append(x)
    opts = [correcta] + limpias[:n - 1]
    random.shuffle(opts)
    return opts, opts.index(correcta)


def bloque_dump(pkt: Packet, ascii_on: bool = True,
                highlight: Optional[Field] = None, titulo: str = "") -> str:
    """El volcado hexadecimal del paquete, listo para imprimir."""
    hi = (highlight.offset, highlight.size) if highlight else None
    cab = titulo or (f"Paquete #{pkt.num}  ({len(pkt.raw)} bytes capturados"
                     f"  |  {' / '.join(pkt.layers) or 'sin identificar'})")
    partes = ["", RULE, cab, RULE,
              hex_dump(pkt.raw, with_ascii=ascii_on, highlight=hi), RULE]
    return "\n".join(partes)


# ---------------------------------------------------------------------------
# Generadores de preguntas sobre el volcado hexadecimal
# ---------------------------------------------------------------------------

# Qué campos entran en cada nivel de dificultad
NIVEL_CAMPOS = {
    "facil": {
        "dst_mac", "src_mac", "ethertype", "src_ip", "dst_ip", "ip_ttl",
        "ip_proto", "ip_version", "src_port", "dst_port", "icmp_type",
        "icmp_code", "arp_oper", "arp_spa", "arp_tpa", "udp_length",
        "dns_qname", "http_line", "loopback_af",
        "rip_command", "rip_version", "ospf_type", "ospf_version", "igmp_type",
        "rip0_red", "ospf_router_id",
    },
    "medio": {
        "ip_ihl", "ip_total_length", "ip_id", "ip_checksum", "ip_tos",
        "tcp_window", "tcp_flags", "tcp_checksum", "udp_checksum",
        "icmp_id", "icmp_seq", "icmp_checksum", "arp_sha", "arp_tha",
        "arp_htype", "arp_ptype", "arp_hlen", "arp_plen",
        "dns_txid", "dns_qr", "dns_qtype", "dns_qdcount", "dns_ancount",
        "ip6_plen", "dhcp_msg_type", "dhcp_yiaddr", "dhcp_chaddr",
        "rip0_metrica", "rip0_mascara", "rip0_nexthop", "rip1_red",
        "rip1_metrica", "ospf_area", "ospf_length", "ospf_hello_interval",
        "ospf_dead_interval", "ospf_priority", "ospf_netmask", "igmp_grupo",
    },
    "dificil": {
        "ip_flags", "ip_df", "ip_mf", "ip_frag_offset", "ip_options",
        "tcp_seq", "tcp_ack", "tcp_data_offset", "tcp_urgent", "tcp_options",
        "tcp_mss", "tcp_wscale", "dns_flags", "dns_rcode", "dns_qclass",
        "dns_nscount", "dns_arcount", "ip6_tclass", "ip6_flow",
        "dhcp_xid", "dhcp_magic", "dhcp_ciaddr", "dhcp_siaddr", "dhcp_op",
        "rip0_afi", "rip0_tag", "rip1_mascara", "rip1_nexthop", "rip2_red",
        "rip2_metrica", "ospf_checksum", "ospf_autype", "ospf_options",
        "ospf_dr", "ospf_bdr", "ospf_neighbor", "ospf_n_lsa", "ospf_lsa_tipo",
    },
}


def nivel_de(nombre: str) -> str:
    for nivel, claves in NIVEL_CAMPOS.items():
        if nombre in claves:
            return nivel
    return "medio"


def q_valor(pkt: Packet, f: Field, ascii_on: bool) -> Question:
    """Leer el valor de un campo directamente del volcado."""
    return Question(
        prompt=f"Mirando el volcado, ¿cuál es el valor de «{f.label}» "
               f"({f.layer})?",
        kind="text", answer=f.display, answer_kind=f.kind,
        explain=f"Está en {f.rango()}: los bytes {f.hex(pkt.raw)}. {f.note}",
        difficulty=nivel_de(f.name), category=f"Hex - {f.layer}",
        dump=bloque_dump(pkt, ascii_on),
    )


def q_offset_de_campo(pkt: Packet, f: Field, ascii_on: bool) -> Question:
    """Campo -> offset: ¿dónde empieza este campo?"""
    return Question(
        prompt=f"¿En qué OFFSET empieza el campo «{f.label}» ({f.layer})? "
               "Responde en hexadecimal (0x1a) o en decimal (26).",
        kind="text", answer=f.offset, answer_kind="int",
        explain=f"Empieza en {off(f.offset)} y ocupa {f.size} byte(s): "
                f"{f.hex(pkt.raw)} -> {f.display}. {f.note}",
        difficulty="medio" if nivel_de(f.name) == "facil" else "dificil",
        category=f"Hex - offsets",
        dump=bloque_dump(pkt, ascii_on),
    )


def solapa(a: Field, b: Field) -> bool:
    """¿Los dos campos comparten algún byte del volcado?"""
    return a.offset < b.offset + b.size and b.offset < a.offset + a.size


def campo_exclusivo(pkt: Packet, f: Field) -> bool:
    """True si f es el único campo que ocupa esos bytes.

    Versión e IHL comparten un byte, igual que Flags/DF/MF: en esos casos no se
    puede preguntar '¿qué campo son estos bytes?' porque hay varias respuestas
    correctas, ni '¿qué bytes forman el campo?' porque el campo no ocupa el byte
    entero.
    """
    return not any(x is not f and solapa(f, x) for x in pkt.fields)


def q_campo_en_offset(pkt: Packet, f: Field, ascii_on: bool) -> Question:
    """Offset -> campo: ¿qué campo vive en estos bytes?"""
    otros = [x.label for x in pkt.fields
             if x.label != f.label and x.layer == f.layer and not solapa(f, x)]
    if len(otros) < 3:
        otros += [x.label for x in pkt.fields
                  if x.label != f.label and not solapa(f, x)]
    random.shuffle(otros)
    opts, idx = mcq_opciones(f.label, otros)
    return Question(
        prompt=f"Los bytes marcados con corchetes, en {f.rango()} "
               f"({f.hex(pkt.raw)}), ¿qué campo son?",
        kind="mcq", answer=idx, options=opts,
        explain=f"Son «{f.label}» de {f.layer}, y valen {f.display}. {f.note}",
        difficulty=nivel_de(f.name), category="Hex - offsets",
        dump=bloque_dump(pkt, ascii_on, highlight=f),
    )


def q_decodificar(pkt: Packet, f: Field, ascii_on: bool) -> Question:
    """Bytes crudos -> valor, sin ver el resto del paquete."""
    pistas = {
        "ip": "Cada byte es un número del 0 al 255 separado por puntos.",
        "mac": "Seis bytes en hexadecimal separados por dos puntos.",
        "int": "Es un entero sin signo en orden de red (big endian): el byte "
               "más significativo va primero.",
        "hex": "Escríbelo en hexadecimal.",
    }
    return Question(
        prompt=f"En {f.rango()} de este paquete están los bytes "
               f"«{f.hex(pkt.raw)}», que son el campo «{f.label}». "
               f"¿Qué valor representan?\n"
               f"   Pista: {pistas.get(f.kind, 'Decodifícalos según el campo.')}",
        kind="text", answer=f.display, answer_kind=f.kind,
        explain=f"{f.hex(pkt.raw)} = {f.display}. {f.note}",
        difficulty="medio" if f.size <= 2 else "dificil",
        category="Hex - decodificar",
        dump="",
    )


def q_bytes_del_campo(pkt: Packet, f: Field, ascii_on: bool) -> Question:
    """Campo -> bytes: escribir el hexadecimal exacto."""
    return Question(
        prompt=f"Escribe los BYTES en hexadecimal que forman el campo "
               f"«{f.label}» ({f.layer}) en este paquete. "
               f"Son {f.size} byte(s); puedes escribirlos con o sin espacios.",
        kind="text", answer=f.hex(pkt.raw), answer_kind="bytes",
        explain=f"Están en {f.rango()}: {f.hex(pkt.raw)}, que equivale a "
                f"{f.display}. {f.note}",
        difficulty="medio" if f.size <= 4 else "dificil",
        category="Hex - decodificar",
        dump=bloque_dump(pkt, ascii_on),
    )


GENERADORES_CAMPO = [q_valor, q_offset_de_campo, q_campo_en_offset,
                     q_decodificar, q_bytes_del_campo]


def preguntas_de_campos(pkt: Packet, ascii_on: bool, dificultad: str,
                        cuantas: int) -> List[Question]:
    """Mezcla los cinco tipos de pregunta sobre los campos del paquete."""
    candidatos = [f for f in pkt.fields
                  if dificultad == "mixto" or nivel_de(f.name) == dificultad]
    if not candidatos:
        candidatos = list(pkt.fields)
    random.shuffle(candidatos)

    salida = []
    for f in candidatos:
        gen = random.choice(GENERADORES_CAMPO)
        exclusivo = campo_exclusivo(pkt, f)
        # un campo que no ocupa bytes enteros para él solo (versión/IHL, flags/DF)
        # solo admite preguntas por su valor o por su offset
        if not exclusivo and gen in (q_campo_en_offset, q_decodificar,
                                     q_bytes_del_campo):
            gen = random.choice([q_valor, q_offset_de_campo])
        # decodificar y escribir bytes no tienen sentido en campos de texto largos
        if f.kind == "text" and gen in (q_decodificar, q_bytes_del_campo):
            gen = q_valor
        if f.size > 8 and gen is q_bytes_del_campo:
            gen = q_valor
        salida.append(gen(pkt, f, ascii_on))
        if len(salida) >= cuantas:
            break
    return salida


# ---------------------------------------------------------------------------
# Preguntas de cálculo e interpretación a partir del volcado
# ---------------------------------------------------------------------------

def preguntas_calculadas(pkt: Packet, ascii_on: bool) -> List[Question]:
    """Lo que no se lee directo: hay que calcularlo o razonarlo."""
    qs = []
    i = pkt.info
    dump = bloque_dump(pkt, ascii_on)

    # ---- IHL -> longitud de cabecera y payload ----
    if pkt.has("ip_ihl", "ip_total_length"):
        ihl = i["ip_ihl"]
        hdr = ihl * 4
        total = i["ip_total_length"]
        f = pkt.get("ip_ihl")
        qs.append(Question(
            prompt=f"El campo IHL vale {ihl}. ¿Cuántos BYTES mide la cabecera "
                   "IP de este paquete?",
            kind="text", answer=hdr, answer_kind="int",
            explain=f"IHL cuenta palabras de 32 bits, o sea de 4 bytes: "
                    f"{ihl} x 4 = {hdr} bytes. Por eso el valor mínimo válido "
                    "es 5 (los 20 bytes de cabecera sin opciones)"
                    + (f". Aquí vale {ihl}, así que hay "
                       f"{(ihl - 5) * 4} bytes de opciones IP."
                       if ihl > 5 else ", y es justo lo que vale aquí."),
            difficulty="medio", category="Hex - cálculo",
            dump=bloque_dump(pkt, ascii_on, highlight=f),
        ))
        qs.append(Question(
            prompt=f"La longitud total IP es {total} y la cabecera IP mide "
                   f"{hdr} bytes. ¿Cuántos bytes de datos lleva encima de IP "
                   "(el payload de capa 4 completo, con su cabecera)?",
            kind="text", answer=total - hdr, answer_kind="int",
            explain=f"{total} - {hdr} = {total - hdr} bytes. La longitud total "
                    "de IPv4 SÍ incluye la cabecera IP, pero NO los 14 bytes de "
                    "Ethernet; por eso una trama de "
                    f"{len(pkt.raw)} bytes en el volcado lleva un campo de "
                    f"longitud total de {total}.",
            difficulty="dificil", category="Hex - cálculo",
            dump=dump,
        ))

    # ---- Ethernet + IP: por qué el volcado es más grande ----
    if pkt.has("ip_total_length") and "Ethernet" in pkt.layers:
        total = i["ip_total_length"]
        qs.append(Question(
            prompt=f"El volcado tiene {len(pkt.raw)} bytes, pero el campo "
                   f"«longitud total» de IP dice {total}. ¿Por qué no "
                   "coinciden?",
            kind="mcq", answer=0,
            options=[
                f"Porque la longitud total de IP no cuenta los 14 bytes de la "
                f"cabecera Ethernet ({total} + 14 = {total + 14})",
                "Porque el campo longitud total está corrupto",
                "Porque el volcado incluye el checksum al final",
                "Porque IP mide la longitud en palabras de 32 bits"],
            explain=f"Los primeros 14 bytes del volcado (MAC destino, MAC "
                    f"origen y EtherType) son de capa 2, y el campo de IP solo "
                    f"mide desde el byte 14 en adelante: {total} + 14 = "
                    f"{total + 14}"
                    + (f", que coincide con los {len(pkt.raw)} bytes "
                       "capturados." if total + 14 == len(pkt.raw) else
                       f". Si aún así no llega a los {len(pkt.raw)} bytes "
                       "capturados, la diferencia es relleno (padding) que "
                       "Ethernet agrega para alcanzar el mínimo de 60 bytes."),
            difficulty="medio", category="Hex - cálculo",
            dump=dump,
        ))

    # ---- TCP data offset -> cabecera y payload ----
    if pkt.has("tcp_data_offset"):
        do = i["tcp_data_offset"]
        hdr = do * 4
        f = pkt.get("tcp_data_offset")
        qs.append(Question(
            prompt=f"El «data offset» de TCP vale {do}. ¿Cuántos BYTES mide la "
                   "cabecera TCP?",
            kind="text", answer=hdr, answer_kind="int",
            explain=f"{do} x 4 = {hdr} bytes. Igual que el IHL de IP, cuenta "
                    "palabras de 32 bits. El mínimo es 5 (20 bytes)"
                    + (f"; aquí hay {hdr - 20} bytes de opciones TCP "
                       "(MSS, window scale, SACK, timestamps)." if hdr > 20
                       else ", así que este segmento no lleva opciones."),
            difficulty="dificil", category="Hex - cálculo",
            dump=bloque_dump(pkt, ascii_on, highlight=f),
        ))
        if pkt.has("ip_total_length"):
            datos = i["ip_total_length"] - i["ip_header_len"] - hdr
            qs.append(Question(
                prompt="¿Cuántos bytes de DATOS de aplicación transporta este "
                       "segmento TCP? (longitud total IP, menos la cabecera IP, "
                       "menos la cabecera TCP)",
                kind="text", answer=max(0, datos), answer_kind="int",
                explain=f"{i['ip_total_length']} - {i['ip_header_len']} - "
                        f"{hdr} = {datos} bytes."
                        + (" Un segmento con 0 bytes de datos es puro control: "
                           "un ACK, un SYN o un FIN." if datos == 0 else
                           " Esos bytes son los que ves al final del volcado, "
                           "y en la columna ASCII se leen si el protocolo es "
                           "texto plano."),
                difficulty="dificil", category="Hex - cálculo",
                dump=dump,
            ))

    # ---- flags TCP bit a bit ----
    if pkt.has("tcp_flags"):
        f = pkt.get("tcp_flags")
        byte = f.value
        activas = i.get("tcp_flags_str", "ninguna")
        qs.append(Question(
            prompt=f"El byte de flags TCP en {f.rango()} vale 0x{byte:02x} "
                   f"(0b{byte:08b}). ¿Qué flags están activas?",
            kind="mcq",
            answer=0,
            options=[activas,
                     "SYN, ACK" if activas != "SYN, ACK" else "FIN, ACK",
                     "RST" if activas != "RST" else "PSH",
                     "FIN, PSH" if activas != "FIN, PSH" else "URG, ACK"],
            explain=f"Cada bit del byte es una flag: FIN=0x01, SYN=0x02, "
                    f"RST=0x04, PSH=0x08, ACK=0x10, URG=0x20, ECE=0x40, "
                    f"CWR=0x80. Haciendo AND de 0x{byte:02x} con cada máscara "
                    f"quedan activas: {activas}. Con solo SYN es el primer "
                    "paquete de un handshake; SYN+ACK es la respuesta del "
                    "servidor; RST es un rechazo.",
            difficulty="dificil", category="Hex - bits",
            dump=bloque_dump(pkt, ascii_on, highlight=f),
        ))

    # ---- primer byte de IPv4: dos campos en un byte ----
    if pkt.has("ip_version", "ip_ihl") and "IPv4" in pkt.layers:
        f = pkt.get("ip_version")
        b = pkt.raw[f.offset]
        qs.append(Question(
            prompt=f"El byte en {off(f.offset)} vale 0x{b:02x}. Ese único byte "
                   "contiene DOS campos. ¿Cuáles son y cuánto valen?",
            kind="mcq", answer=0,
            options=[f"Versión = {b >> 4} (4 bits altos) e IHL = {b & 0x0F} "
                     f"(4 bits bajos)",
                     f"TTL = {b} completo",
                     f"Versión = {b & 0x0F} (4 bits bajos) e IHL = {b >> 4} "
                     f"(4 bits altos)",
                     f"Longitud total = {b}"],
            explain=f"0x{b:02x} = 0b{b:08b}. Los 4 bits altos son la versión "
                    f"(0x{b:02x} >> 4 = {b >> 4}, o sea IPv4) y los 4 bajos son "
                    f"el IHL (0x{b:02x} & 0x0f = {b & 0x0F}, o sea "
                    f"{(b & 0x0F) * 4} bytes de cabecera). Meter dos campos en "
                    "un byte es habitual en las cabeceras de red: por eso hay "
                    "que saber leer nibbles, no solo bytes.",
            difficulty="medio", category="Hex - bits",
            dump=bloque_dump(pkt, ascii_on, highlight=f),
        ))

    # ---- checksum IPv4: verificarlo de verdad ----
    valido = checksum_valido(pkt)
    if valido is not None:
        f = pkt.get("ip_checksum")
        if f.value == 0:
            qs.append(Question(
                prompt=f"El checksum de la cabecera IP en {f.rango()} vale "
                       "0x0000 y no cuadra con el contenido de la cabecera. "
                       "¿Cuál es la explicación más probable?",
                kind="mcq", answer=0,
                options=["Checksum offloading: la tarjeta de red lo calcula al "
                         "transmitir, y la captura se tomó antes de eso",
                         "El paquete viajó por la red con el checksum roto y "
                         "aun así fue aceptado",
                         "IPv4 permite dejar el checksum en cero como en UDP",
                         "El archivo de captura está corrupto"],
                explain="Es un caso clásico al capturar en el propio host que "
                        "envía: el sistema entrega el paquete a la NIC con el "
                        "checksum sin calcular, la NIC lo completa por hardware "
                        "y el sniffer ya lo copió antes. Wireshark lo marca "
                        "como 'maybe caused by IP checksum offload'. En los "
                        "paquetes que este host RECIBE el checksum sí cuadra. "
                        "Ojo: a diferencia de UDP en IPv4, en IP el checksum "
                        "no es opcional.",
                difficulty="dificil", category="Hex - checksum",
                dump=bloque_dump(pkt, ascii_on, highlight=f),
            ))
        else:
            qs.append(Question(
                prompt=f"El checksum de la cabecera IP declarado en {f.rango()} "
                       f"es 0x{f.value:04x}. Recalculándolo sobre los "
                       f"{i.get('ip_header_len', 20)} bytes de la cabecera, "
                       "¿es correcto?",
                kind="mcq",
                answer=0 if valido else 1,
                options=["Sí, cuadra: la cabecera llegó íntegra",
                         "No, no cuadra: la cabecera fue alterada o el "
                         "checksum no se calculó"],
                explain="El cálculo es: poner el campo checksum en cero, sumar "
                        "toda la cabecera en palabras de 16 bits, plegar el "
                        "acarreo sobre los 16 bits bajos y hacer el complemento "
                        "a uno. Solo cubre la CABECERA IP, no los datos; y como "
                        "el TTL baja en cada salto, cada router tiene que "
                        f"recalcularlo. Aquí el resultado es "
                        f"{'correcto' if valido else 'incorrecto'}.",
                difficulty="dificil", category="Hex - checksum",
                dump=bloque_dump(pkt, ascii_on, highlight=f),
            ))

    # ---- EtherType decide cómo seguir leyendo ----
    if pkt.has("ethertype"):
        f = pkt.get("ethertype")
        et = f.value
        nombre = ETHERTYPES.get(et, "desconocido")
        otros = [v for k, v in ETHERTYPES.items() if v != nombre]
        opts, idx = mcq_opciones(nombre, otros)
        qs.append(Question(
            prompt=f"El EtherType en {f.rango()} vale 0x{et:04x}. ¿Qué "
                   "protocolo viene a continuación en el volcado?",
            kind="mcq", answer=idx, options=opts,
            explain=f"0x{et:04x} = {nombre}. Este campo es la bifurcación que "
                    "te dice cómo interpretar el byte 14 en adelante: con "
                    "0x0800 lo que sigue es una cabecera IPv4 (y el byte 14 "
                    "empieza con 0x45); con 0x0806 es ARP; con 0x86dd, IPv6.",
            difficulty="facil", category="Hex - Ethernet",
            dump=bloque_dump(pkt, ascii_on, highlight=f),
        ))

    # ---- el campo protocolo decide la capa 4 ----
    if pkt.has("ip_proto"):
        f = pkt.get("ip_proto")
        nombre = i.get("ip_proto_name", "desconocido")
        otros = [v for v in IP_PROTOCOLS.values() if v != nombre]
        opts, idx = mcq_opciones(nombre, otros)
        qs.append(Question(
            prompt=f"El campo «protocolo» en {off(f.offset)} vale {f.value}. "
                   "¿Qué cabecera empieza justo después de la cabecera IP?",
            kind="mcq", answer=idx, options=opts,
            explain=f"{f.value} = {nombre}. Los números que más vas a ver son "
                    "1=ICMP, 6=TCP y 17=UDP. Combinado con el IHL, este campo "
                    "te dice exactamente en qué byte del volcado empieza la "
                    f"capa 4: {off(f.offset - 9 + i.get('ip_header_len', 20))}.",
            difficulty="facil", category="Hex - IPv4",
            dump=bloque_dump(pkt, ascii_on, highlight=f),
        ))

    # ---- broadcast ----
    if pkt.has("dst_mac") and i["dst_mac"] == "ff:ff:ff:ff:ff:ff":
        f = pkt.get("dst_mac")
        qs.append(Question(
            prompt="Los primeros 6 bytes del volcado son ff ff ff ff ff ff. "
                   "¿Qué significa eso?",
            kind="mcq", answer=0,
            options=["Es la MAC de broadcast: la trama va a todos los hosts del "
                     "segmento de red",
                     "Es una MAC inválida y la trama será descartada",
                     "Significa que la trama viene cifrada",
                     "Es la MAC del router por defecto"],
            explain="Todos los bits en 1 es la dirección de broadcast de "
                    "Ethernet. Se usa cuando el emisor todavía no sabe a quién "
                    "dirigirse: un ARP request pregunta a todos '¿quién tiene "
                    "esta IP?', y un DHCP Discover busca cualquier servidor que "
                    "le conteste.",
            difficulty="facil", category="Hex - Ethernet",
            dump=bloque_dump(pkt, ascii_on, highlight=f),
        ))

    # ---- payload ASCII legible ----
    if len(pkt.payload) >= 4:
        texto = safe_ascii(pkt.payload)
        legibles = sum(1 for c in texto if c != ".")
        if legibles >= max(4, len(texto) * 0.6):
            muestra = texto[:40].strip()
            qs.append(Question(
                prompt="Mira la columna ASCII de la derecha, a la altura del "
                       f"payload (desde {off(pkt.payload_offset)}). ¿Qué texto "
                       "se alcanza a leer? Escribe los primeros caracteres.",
                kind="text", answer=muestra, answer_kind="text",
                explain=f"El payload en ASCII es: «{texto[:60]}». La columna "
                        "ASCII del volcado convierte cada byte imprimible "
                        "(0x20 a 0x7e) en su carácter y el resto en un punto. "
                        "Es lo primero que se mira para saber si un protocolo "
                        "va en texto plano: HTTP, FTP, SMTP y Telnet se leen "
                        "enteros, y ahí es donde aparecen las credenciales sin "
                        "cifrar.",
                difficulty="medio", category="Hex - ASCII",
                dump=bloque_dump(pkt, True),
            ))

    return qs


# ---------------------------------------------------------------------------
# Secuencias: 3 a 6 paquetes juntos, para deducir qué ocurre por orden y contenido
# ---------------------------------------------------------------------------

def render_secuencia(pkts: List[Packet], titulo="Secuencia de paquetes") -> str:
    t0 = pkts[0].ts if pkts else 0
    lineas = ["", RULE, f"{titulo}  (# = número real en la captura)", RULE]
    for p in pkts:
        lineas.append(f"  {p.ts - t0:8.4f}s  {p.resumen()}")
    lineas.append(RULE)
    return "\n".join(lineas)


def q_secuencia(pkts, prompt, correcta, incorrectas, explain,
                difficulty="medio", category="Secuencia") -> Question:
    opts, idx = mcq_opciones(correcta, incorrectas)
    return Question(prompt=prompt, kind="mcq", answer=idx, options=opts,
                    explain=explain, difficulty=difficulty, category=category,
                    dump=render_secuencia(pkts))


def _flujo(a, b, inverso=False) -> bool:
    ia, ib = a.info, b.info
    if inverso:
        return (ia.get("src_ip") == ib.get("dst_ip")
                and ia.get("dst_ip") == ib.get("src_ip")
                and ia.get("src_port") == ib.get("dst_port")
                and ia.get("dst_port") == ib.get("src_port"))
    return (ia.get("src_ip") == ib.get("src_ip")
            and ia.get("dst_ip") == ib.get("dst_ip")
            and ia.get("src_port") == ib.get("src_port")
            and ia.get("dst_port") == ib.get("dst_port"))


def _flags(p) -> str:
    return p.info.get("tcp_flags_str", "")


def buscar_handshake(pkts):
    tcp = [p for p in pkts if "TCP" in p.layers]
    for k, syn in enumerate(tcp):
        if _flags(syn) != "SYN":
            continue
        synack = None
        for p in tcp[k + 1:k + 40]:
            if synack is None and _flags(p) == "SYN, ACK" and _flujo(syn, p, True):
                synack = p
            elif synack is not None and _flags(p) == "ACK" and _flujo(syn, p):
                return [syn, synack, p]
    return None


def buscar_cierre(pkts):
    tcp = [p for p in pkts if "TCP" in p.layers]
    for k, fin in enumerate(tcp):
        if "FIN" not in _flags(fin):
            continue
        seq = [fin]
        for p in tcp[k + 1:k + 30]:
            if _flujo(fin, p) or _flujo(fin, p, True):
                seq.append(p)
            if len(seq) == 4:
                return seq
    return None


def buscar_rechazo(pkts):
    tcp = [p for p in pkts if "TCP" in p.layers]
    for k, syn in enumerate(tcp):
        if _flags(syn) != "SYN":
            continue
        for p in tcp[k + 1:k + 15]:
            if "RST" in _flags(p) and _flujo(syn, p, True):
                return [syn, p]
    return None


def buscar_escaneo(pkts):
    syns = [p for p in pkts if _flags(p) == "SYN"]
    grupos = defaultdict(list)
    for p in syns:
        grupos[(p.info.get("src_ip"), p.info.get("dst_ip"))].append(p)
    for _, items in grupos.items():
        puertos = {p.info.get("dst_port") for p in items}
        if len(puertos) >= 4:
            vistos, salida = set(), []
            for p in items:
                dp = p.info.get("dst_port")
                if dp not in vistos:
                    vistos.add(dp)
                    salida.append(p)
                if len(salida) == 5:
                    break
            return salida
    return None


def buscar_ping(pkts):
    icmp = [p for p in pkts if "ICMP" in p.layers]
    seq = []
    for k, req in enumerate(icmp):
        if req.info.get("icmp_type") != 8:
            continue
        for rep in icmp[k + 1:k + 10]:
            if (rep.info.get("icmp_type") == 0
                    and rep.info.get("src_ip") == req.info.get("dst_ip")):
                seq.extend([req, rep])
                break
        if len(seq) >= 4:
            return seq[:4]
    return seq if len(seq) >= 2 else None


def buscar_flood_icmp(pkts):
    grupos = defaultdict(list)
    for p in pkts:
        if p.info.get("icmp_type") == 8:
            grupos[(p.info.get("src_ip"), p.info.get("dst_ip"))].append(p)
    for par, items in grupos.items():
        if len(items) >= 20:
            respuestas = [p for p in pkts if p.info.get("icmp_type") == 0
                          and p.info.get("src_ip") == par[1]]
            if len(respuestas) < len(items) * 0.3:
                return items[:6]
    return None


def buscar_arp(pkts):
    for k, req in enumerate(pkts):
        if req.info.get("arp_oper") != 1:
            continue
        for j, rep in enumerate(pkts[k + 1:k + 12], start=k + 1):
            if (rep.info.get("arp_oper") == 2
                    and rep.info.get("arp_spa") == req.info.get("arp_tpa")):
                seq = [req, rep]
                for nxt in pkts[j + 1:j + 6]:
                    if "ARP" not in nxt.layers:
                        seq.append(nxt)
                        break
                return seq
    return None


def buscar_arp_spoof(pkts):
    replies = [p for p in pkts if p.info.get("arp_oper") == 2]
    por_mac, por_ip = defaultdict(set), defaultdict(set)
    for p in replies:
        por_mac[p.info["arp_sha"]].add(p.info["arp_spa"])
        por_ip[p.info["arp_spa"]].add(p.info["arp_sha"])
    macs = {m for m, ips in por_mac.items() if len(ips) > 1}
    ips = {ip for ip, ms in por_ip.items() if len(ms) > 1}
    if not macs and not ips:
        return None
    seq = [p for p in replies
           if p.info["arp_sha"] in macs or p.info["arp_spa"] in ips]
    return seq[:5] if len(seq) >= 2 else None


def buscar_dns(pkts):
    for k, q in enumerate(pkts):
        if "DNS" not in q.layers or q.info.get("dns_qr") != 0:
            continue
        for j, r in enumerate(pkts[k + 1:k + 20], start=k + 1):
            if ("DNS" in r.layers and r.info.get("dns_qr") == 1
                    and r.info.get("dns_qname") == q.info.get("dns_qname")):
                return [q, r]
    return None


def buscar_dora(pkts):
    orden = ["Discover", "Offer", "Request", "ACK"]
    seq, pos = [], 0
    for p in pkts:
        if p.info.get("dhcp_msg_name") == orden[pos]:
            seq.append(p)
            pos += 1
            if pos == len(orden):
                return seq
    return seq if len(seq) >= 3 else None


def buscar_inalcanzable(pkts):
    for k, p in enumerate(pkts):
        if p.info.get("icmp_type") == 3:
            return pkts[max(0, k - 3):k + 1]
    return None


def preguntas_de_secuencia(pkts: List[Packet]) -> List[Question]:
    qs = []

    hs = buscar_handshake(pkts)
    if hs:
        qs.append(q_secuencia(
            hs, "Estos tres paquetes son del mismo flujo TCP. ¿Qué ocurre?",
            "El establecimiento de una conexión TCP (three-way handshake)",
            ["El cierre ordenado de una conexión ya establecida",
             "Un escaneo de puertos rechazado por el servidor",
             "Una retransmisión por pérdida de paquetes"],
            explain=f"Lee las flags en orden: #{hs[0].num} [SYN] abre, "
                    f"#{hs[1].num} [SYN, ACK] acepta e invierte el sentido, y "
                    f"#{hs[2].num} [ACK] confirma. Fíjate también en los números "
                    f"de secuencia: el ACK de #{hs[1].num} vale "
                    f"{hs[1].info.get('tcp_ack')}, que es el seq del SYN más 1. "
                    "Ese '+1' es porque el SYN consume un número de secuencia "
                    "aunque no lleve datos.",
            difficulty="facil", category="Secuencia - TCP"))

    cierre = buscar_cierre(pkts)
    if cierre:
        qs.append(q_secuencia(
            cierre, "¿Qué representa esta secuencia de paquetes TCP?",
            "El cierre de la conexión: cada extremo manda su FIN y el otro lo confirma",
            ["La apertura de una conexión nueva",
             "Un ataque SYN flood",
             "Una negociación de cifrado TLS"],
            explain="El cierre de TCP es bidireccional: cada lado cierra su "
                    "mitad con un FIN y espera el ACK del otro, de ahí el patrón "
                    "FIN,ACK / ACK repetido en los dos sentidos. Un RST, en "
                    "cambio, corta de golpe sin este intercambio.",
            difficulty="medio", category="Secuencia - TCP"))

    rech = buscar_rechazo(pkts)
    if rech:
        qs.append(q_secuencia(
            rech, "Al SYN le responden con RST. ¿Qué pasa con ese puerto?",
            "Está cerrado: no hay ningún proceso escuchando y el host rechaza la conexión",
            ["Está abierto y la conexión se estableció",
             "El paquete se perdió y se retransmitirá",
             "El servidor pide autenticación antes de responder"],
            explain="Si llega un SYN a un puerto donde nadie escucha, el sistema "
                    "responde RST en lugar de SYN,ACK. Un escáner como nmap usa "
                    "exactamente esto: SYN,ACK = open, RST = closed, silencio = "
                    "filtered (un firewall se lo tragó).",
            difficulty="medio", category="Secuencia - TCP"))

    scan = buscar_escaneo(pkts)
    if scan:
        puertos = ", ".join(str(p.info.get("dst_port")) for p in scan)
        qs.append(q_secuencia(
            scan, f"Todos estos SYN van al mismo destino pero a puertos "
                  f"distintos ({puertos}). ¿Qué es?",
            "Un escaneo de puertos: se prueba puerto por puerto cuáles están abiertos",
            ["Una descarga por HTTP de un archivo grande",
             "Un handshake normal repetido con el mismo servicio",
             "Una consulta DNS recursiva"],
            explain="La firma de un port scan es un mismo origen mandando SYN a "
                    "muchos puertos del mismo destino, casi a la vez y sin "
                    "completar ningún handshake: al atacante solo le interesa "
                    "qué contesta cada puerto.",
            difficulty="dificil", category="Secuencia - Seguridad"))

    ping = buscar_ping(pkts)
    if ping:
        qs.append(q_secuencia(
            ping, "¿Qué ocurre entre estos dos hosts?",
            "Un ping: cada Echo Request recibe su Echo Reply, así que el destino responde",
            ["El destino está caído y no contesta",
             "Se está estableciendo una conexión TCP",
             "Se está resolviendo un nombre de dominio"],
            explain="Echo Request (type=8) seguido de Echo Reply (type=0) con "
                    "los hosts invertidos es la ida y vuelta de un ping. En el "
                    "volcado puedes confirmarlo con los campos identifier y "
                    "sequence: la respuesta repite exactamente los mismos "
                    "valores que la solicitud.",
            difficulty="facil", category="Secuencia - ICMP"))

    flood = buscar_flood_icmp(pkts)
    if flood:
        qs.append(q_secuencia(
            flood, "Esta ráfaga de Echo Request se repite cientos de veces en "
                   "muy poco tiempo y casi no hay respuestas. ¿Qué es?",
            "Un ICMP flood: un DoS que busca saturar al destino",
            ["Un diagnóstico normal con la herramienta ping",
             "Un traceroute descubriendo la ruta",
             "Una transferencia de archivos por ICMP"],
            explain="Un ping de diagnóstico manda un paquete por segundo. Mira "
                    "los tiempos relativos de la izquierda: cientos de paquetes "
                    "en fracciones de segundo es 'hping3 --flood' o 'ping -f', "
                    "buscando consumir ancho de banda o CPU del destino.",
            difficulty="dificil", category="Secuencia - Seguridad"))

    arp = buscar_arp(pkts)
    if arp:
        qs.append(q_secuencia(
            arp, "¿Qué ocurre en esta secuencia?",
            "Una resolución ARP normal: se pregunta por la MAC de una IP y su dueño responde",
            ["Un envenenamiento de la caché ARP (ARP spoofing)",
             "Una consulta DNS para traducir un nombre a una IP",
             "Un intento de conexión a un puerto cerrado"],
            explain="ARP traduce IP (capa 3) a MAC (capa 2). Primero un "
                    "broadcast preguntando, después la respuesta del dueño, y "
                    "recién entonces puede salir el tráfico IP. Lo sospechoso "
                    "sería ver respuestas que nadie pidió.",
            difficulty="facil", category="Secuencia - ARP"))

    spoof = buscar_arp_spoof(pkts)
    if spoof:
        qs.append(q_secuencia(
            spoof, "Mira qué MAC dice ser cada IP en estas respuestas ARP. "
                   "¿Qué ocurre?",
            "ARP spoofing: se anuncian asociaciones IP-MAC falsas para interceptar tráfico",
            ["Una resolución ARP normal entre dos hosts",
             "Un servidor DHCP repartiendo direcciones",
             "Un router anunciando una ruta nueva"],
            explain="En una red sana cada IP corresponde a una sola MAC. Aquí "
                    "hay respuestas contradictorias, que es lo que hacen "
                    "arpspoof o ettercap para que las víctimas manden su "
                    "tráfico al atacante. Wireshark lo marca como 'duplicate "
                    "use of <IP> detected!'.",
            difficulty="dificil", category="Secuencia - Seguridad"))

    dns = buscar_dns(pkts)
    if dns:
        qs.append(q_secuencia(
            dns, "¿Qué relación hay entre estos dos paquetes DNS?",
            "Son la consulta y su respuesta: comparten el mismo Transaction ID",
            ["Son dos consultas independientes al mismo servidor",
             "Son una transferencia de zona entre dos servidores DNS",
             "Son un ataque de amplificación DNS"],
            explain=f"El Transaction ID de los dos es "
                    f"0x{dns[0].info.get('dns_txid', 0):04x}: ese número de 16 "
                    "bits es lo único que empareja una respuesta con su "
                    "consulta. Y es justamente la debilidad que explota el DNS "
                    "spoofing: quien acierte el ID y el puerto origen antes de "
                    "que llegue la respuesta legítima, la suplanta.",
            difficulty="medio", category="Secuencia - DNS"))

    dora = buscar_dora(pkts)
    if dora:
        qs.append(q_secuencia(
            dora, "¿Qué proceso completan estos paquetes?",
            "La asignación de una IP por DHCP (Discover, Offer, Request, ACK)",
            ["Una resolución de nombres contra un servidor DNS",
             "Un handshake TCP de tres pasos",
             "Un envenenamiento de la caché ARP"],
            explain="Es el ciclo DORA. Fíjate en el volcado: el cliente arranca "
                    "desde 0.0.0.0 hacia 255.255.255.255 porque todavía no "
                    "tiene IP, y el servidor le contesta poniendo la IP asignada "
                    "en el campo 'your IP' (yiaddr). Un servidor DHCP falso que "
                    "conteste primero se queda como gateway de la víctima.",
            difficulty="medio", category="Secuencia - DHCP"))

    unre = buscar_inalcanzable(pkts)
    if unre and len(unre) >= 2:
        qs.append(q_secuencia(
            unre, "El último paquete es un ICMP Destination Unreachable. ¿Qué "
                  "dice eso de los anteriores?",
            "No llegaron: un router o el propio destino avisa que no pudo entregarlos",
            ["Llegaron bien y esto es un acuse de recibo",
             "El destino aceptó la conexión y pide más datos",
             "Es un mensaje rutinario sin relación con ellos"],
            explain="ICMP type=3 lo genera un router o el host destino para "
                    "avisar al origen del fallo, y el campo 'code' precisa el "
                    "motivo (red, host o puerto inalcanzable, o prohibido por un "
                    "firewall). En el volcado, después de la cabecera ICMP viene "
                    "copiada la cabecera IP del paquete que falló más sus 8 "
                    "primeros bytes: así el origen sabe exactamente cuál fue.",
            difficulty="medio", category="Secuencia - ICMP"))

    return qs


# ---------------------------------------------------------------------------
# Ventana deslizante: la real del volcado y la teoría de GBN / Selective Repeat
# ---------------------------------------------------------------------------

def preguntas_ventana(pkts: List[Packet], ascii_on: bool) -> List[Question]:
    """La ventana deslizante tal como aparece en los bytes de la captura."""
    tcp = [p for p in pkts if "tcp_window" in p.info]
    if not tcp:
        return []
    qs = []

    p = random.choice(tcp)
    f = p.get("tcp_window")
    qs.append(Question(
        prompt=f"¿Cuántos bytes de ventana anuncia {p.info['src_ip']} en este "
               "paquete? El campo son 2 bytes en la cabecera TCP.",
        kind="text", answer=f.value, answer_kind="int",
        explain=f"Está en {f.rango()}: {f.hex(p.raw)} = {f.value}. Es la "
                "ventana de recepción (rwnd), el control de flujo: cuántos "
                "bytes más puede mandarle el otro extremo sin esperar ACK. "
                "Como es una ventana deslizante, avanza a medida que llegan "
                "los ACK.",
        difficulty="facil", category="Ventana deslizante",
        dump=bloque_dump(p, ascii_on, highlight=f)))

    flujos = defaultdict(list)
    for x in tcp:
        flujos[(x.info.get("src_ip"), x.info.get("src_port"),
                x.info.get("dst_ip"), x.info.get("dst_port"))].append(x)
    mejor = max(flujos.values(), key=len)

    if len(mejor) >= 3:
        seq = mejor[:5]
        ult = seq[-1]
        qs.append(Question(
            prompt=f"Según el último paquete mostrado, ¿cuántos bytes puede "
                   f"tener en vuelo {ult.info['dst_ip']} hacia "
                   f"{ult.info['src_ip']} sin recibir un ACK nuevo?",
            kind="text", answer=ult.info["tcp_window"], answer_kind="int",
            explain=f"La ventana la anuncia quien RECIBE, para limitar a quien "
                    f"ENVÍA. Como #{ult.num} sale de {ult.info['src_ip']}, su "
                    f"win ({ult.info['tcp_window']} bytes) es el techo que le "
                    f"impone a {ult.info['dst_ip']}. Esa es la diferencia con "
                    "stop-and-wait, donde el techo sería siempre un paquete.",
            difficulty="medio", category="Ventana deslizante",
            dump=render_secuencia(seq, "Un mismo flujo TCP")))

        # el win del SYN no es comparable: aún no se aplica el window scaling
        sin_syn = [x for x in seq if "SYN" not in _flags(x)]
        wins = [x.info["tcp_window"] for x in sin_syn]
        if len(wins) >= 2 and len(set(wins)) > 1:
            qs.append(q_secuencia(
                sin_syn,
                f"La ventana anunciada cambia (de {wins[0]} a {wins[-1]}). "
                "¿Qué significa que BAJE?",
                "Que el buffer de recepción se está llenando: la aplicación no "
                "lee tan rápido como llegan los datos, y se frena al emisor",
                ["Que la conexión se está cerrando",
                 "Que el enlace físico perdió velocidad",
                 "Que el emisor está retransmitiendo"],
                explain="La ventana refleja el espacio libre en el buffer del "
                        "receptor. Si la aplicación no consume, el espacio se "
                        "reduce y la ventana encoge: es control de FLUJO "
                        "(proteger al receptor), distinto del control de "
                        "CONGESTIÓN (proteger a la red). Si llegara a 0, el "
                        "emisor debe parar y mandar window probes.",
                difficulty="dificil", category="Ventana deslizante"))

    ceros = [x for x in tcp if x.info["tcp_window"] == 0]
    if ceros:
        z = ceros[0]
        qs.append(q_secuencia(
            [z], f"El paquete #{z.num} anuncia win=0. ¿Qué debe hacer el otro "
                 "extremo?",
            "Dejar de enviar y sondear con window probes hasta que se anuncie espacio",
            ["Seguir enviando al mismo ritmo",
             "Cerrar la conexión con un RST",
             "Retransmitir toda la ventana anterior"],
            explain="win=0 significa buffer lleno. El emisor se detiene, y para "
                    "no quedar bloqueado para siempre si se pierde el anuncio "
                    "de reapertura, manda sondas periódicas preguntando si ya "
                    "hay espacio.",
            difficulty="dificil", category="Ventana deslizante"))

    escala = [x for x in tcp if "tcp_wscale" in x.info]
    if escala:
        x = escala[0]
        s = x.info["tcp_wscale"]
        w = x.info["tcp_window"]
        qs.append(Question(
            prompt=f"Este SYN negocia Window Scale con factor s={s} y anuncia "
                   f"win={w}. Cuando la conexión esté establecida, ¿cuántos "
                   "bytes de ventana representará realmente ese mismo valor?",
            kind="text", answer=w * (2 ** s), answer_kind="int",
            explain=f"win x 2^s = {w} x {2 ** s} = {w * (2 ** s)} bytes. El "
                    "campo window es de 16 bits (máximo 65535), que no alcanza "
                    "en enlaces rápidos con latencia alta; por eso se negocia un "
                    "factor de escala en el handshake. Ojo: la escala NO se "
                    "aplica a los propios paquetes SYN, solo a los posteriores.",
            difficulty="dificil", category="Ventana deslizante",
            dump=bloque_dump(x, ascii_on, highlight=x.get("tcp_wscale"))))

    return qs


def preguntas_gbn_sr() -> List[Question]:
    """Teoría y ejercicios de ventana deslizante, Go-Back-N y Selective Repeat."""
    banco = [
        Question(
            prompt="¿Para qué sirve una ventana deslizante en un protocolo de "
                   "transporte confiable?",
            kind="mcq", answer=0,
            options=["Para tener varios paquetes en vuelo a la vez en lugar de "
                     "esperar el ACK de cada uno, aprovechando el enlace",
                     "Para cifrar los datos antes de enviarlos",
                     "Para dividir el mensaje en fragmentos IP",
                     "Para elegir la ruta más corta al destino"],
            explain="Con stop-and-wait el emisor manda uno y espera un RTT "
                    "entero, así que el enlace pasa casi todo el tiempo ocioso. "
                    "La ventana permite hasta N paquetes sin confirmar, y se "
                    "'desliza' al llegar los ACK. Stop-and-wait es el caso N=1.",
            difficulty="facil", category="Ventana deslizante - teoría"),
        Question(
            prompt="¿Cuál es la diferencia esencial entre Go-Back-N y Selective "
                   "Repeat?",
            kind="mcq", answer=0,
            options=["Ante una pérdida, GBN retransmite el paquete perdido y "
                     "TODOS los posteriores; SR retransmite solo el perdido",
                     "GBN usa ventana deslizante y SR no",
                     "GBN funciona sobre UDP y SR sobre TCP",
                     "SR no necesita números de secuencia"],
            explain="Los dos son de ventana deslizante; cambia la reacción a la "
                    "pérdida. GBN es simple pero derrochador: retrocede al "
                    "primer no confirmado y reenvía desde ahí, incluso lo que ya "
                    "había llegado. SR es eficiente pero más complejo: buffers y "
                    "temporizadores en ambos extremos.",
            difficulty="facil", category="Ventana deslizante - teoría"),
        Question(
            prompt="En Go-Back-N, ¿qué hace el RECEPTOR con un paquete que llega "
                   "fuera de orden?",
            kind="mcq", answer=0,
            options=["Lo descarta y repite el ACK del último recibido en orden "
                     "(ACK acumulativo)",
                     "Lo guarda en un buffer y lo confirma individualmente",
                     "Lo reenvía al emisor para que lo corrija",
                     "Cierra la conexión por error"],
            explain="El receptor de GBN no tiene buffer para el desorden: solo "
                    "recuerda el último número recibido en orden. Esa "
                    "simplicidad es su gran ventaja, y el ancho de banda que "
                    "desperdicia, su gran desventaja.",
            difficulty="medio", category="Go-Back-N"),
        Question(
            prompt="En Selective Repeat, ¿qué hace el RECEPTOR con los paquetes "
                   "fuera de orden que caen dentro de su ventana?",
            kind="mcq", answer=0,
            options=["Los guarda en un buffer y los confirma individualmente, "
                     "hasta poder entregarlos en orden a la aplicación",
                     "Los descarta, igual que Go-Back-N",
                     "Los entrega desordenados a la aplicación",
                     "Los reenvía al emisor pidiendo confirmación"],
            explain="El receptor de SR mantiene su propia ventana y buffer: "
                    "guarda lo adelantado, manda un ACK por cada paquete, y "
                    "entrega a la aplicación solo cuando puede hacerlo en orden. "
                    "Por eso SR necesita ventana también en el receptor.",
            difficulty="medio", category="Selective Repeat"),
        Question(
            prompt="¿Cuántos temporizadores necesita cada protocolo?",
            kind="mcq", answer=0,
            options=["GBN uno solo (para el más antiguo sin confirmar); SR uno "
                     "por cada paquete en vuelo",
                     "GBN uno por paquete y SR uno solo",
                     "Ambos exactamente uno por conexión",
                     "Ninguno de los dos usa temporizadores"],
            explain="GBN siempre reenvía la ventana entera desde el más "
                    "antiguo, así que le basta un temporizador. SR necesita "
                    "saber cuál venció exactamente para reenviar solo ese, así "
                    "que lleva uno por paquete. De ahí su complejidad.",
            difficulty="medio", category="Ventana deslizante - teoría"),
        Question(
            prompt="¿Qué es un ACK acumulativo?",
            kind="mcq", answer=0,
            options=["Un ACK n que confirma TODOS los paquetes hasta el n; lo "
                     "usan Go-Back-N y TCP",
                     "Un ACK que confirma un único paquete concreto",
                     "Un ACK que se envía solo al final de la transferencia",
                     "Un ACK que viaja cifrado"],
            explain="Si llega el ACK 7, el emisor sabe que todo lo anterior "
                    "llegó, aunque se hayan perdido ACK intermedios. En el "
                    "volcado de TCP lo ves en el campo 'acknowledgment number', "
                    "que indica el SIGUIENTE byte esperado. SR usa en cambio ACK "
                    "individuales; TCP se acerca a eso con la opción SACK.",
            difficulty="medio", category="Ventana deslizante - teoría"),
        Question(
            prompt="En Selective Repeat la ventana no puede superar la mitad del "
                   "espacio de números de secuencia. ¿Por qué?",
            kind="mcq", answer=0,
            options=["Porque si no, el receptor no podría distinguir una "
                     "retransmisión de un paquete nuevo: las ventanas vieja y "
                     "nueva se solaparían",
                     "Porque los buffers de red no soportan ventanas grandes",
                     "Porque el temporizador se desbordaría",
                     "Porque el ACK acumulativo solo cubre media ventana"],
            explain="La cota es W <= 2^k / 2. Si se supera, tras un ciclo de "
                    "numeración el receptor podría aceptar como nuevo un "
                    "duplicado retransmitido. En GBN la cota es más holgada "
                    "(W <= 2^k - 1) porque su receptor solo acepta el siguiente "
                    "número en orden.",
            difficulty="dificil", category="Selective Repeat"),
        Question(
            prompt="¿Por qué se dice que TCP es un híbrido de GBN y SR?",
            kind="mcq", answer=0,
            options=["Porque usa ACK acumulativos como GBN, pero el receptor sí "
                     "bufferiza lo que llega fuera de orden y con SACK confirma "
                     "bloques sueltos, como SR",
                     "Porque alterna entre los dos según la congestión",
                     "Porque usa GBN para enviar y SR para recibir",
                     "Porque numera bytes y eso lo deja fuera de ambas familias"],
            explain="TCP numera BYTES y confirma de forma acumulativa (estilo "
                    "GBN), pero ninguna implementación real descarta lo que "
                    "llega adelantado: lo guarda, y con SACK le dice al emisor "
                    "qué bloques tiene para que retransmita solo el hueco. Eso "
                    "último es comportamiento de SR.",
            difficulty="dificil", category="Ventana deslizante - teoría"),
        Question(
            prompt="En TCP, ¿qué diferencia hay entre la ventana de recepción "
                   "(rwnd) y la de congestión (cwnd)?",
            kind="mcq", answer=0,
            options=["rwnd la anuncia el receptor para protegerse (control de "
                     "flujo) y cwnd la calcula el emisor para no saturar la red "
                     "(control de congestión); se usa el mínimo de las dos",
                     "Son dos nombres del mismo campo de la cabecera",
                     "rwnd solo existe en IPv6 y cwnd solo en IPv4",
                     "cwnd viaja en la cabecera y rwnd se negocia por ICMP"],
            explain="Los bytes en vuelo permitidos son min(cwnd, rwnd). En el "
                    "volcado solo puedes VER rwnd, en el campo window de la "
                    "cabecera TCP: cwnd es una variable interna del emisor y no "
                    "se transmite, así que jamás aparecerá en un hex dump.",
            difficulty="dificil", category="Ventana deslizante - teoría"),
    ]

    # ---- ejercicios numéricos, distintos en cada partida ----
    k = random.choice([3, 4, 5, 6])
    banco.append(Question(
        prompt=f"Un protocolo de ventana deslizante usa números de secuencia de "
               f"{k} bits ({2 ** k} valores, de 0 a {2 ** k - 1}). ¿Cuál es el "
               "tamaño MÁXIMO de ventana en Go-Back-N?",
        kind="text", answer=2 ** k - 1, answer_kind="int",
        explain=f"W <= 2^k - 1 = {2 ** k} - 1 = {2 ** k - 1}. Se resta uno "
                "porque, si la ventana ocupara todo el espacio, un ACK perdido "
                "haría imposible distinguir una ventana nueva de la "
                "retransmisión completa de la anterior.",
        difficulty="medio", category="Go-Back-N"))

    k2 = random.choice([3, 4, 5, 6])
    banco.append(Question(
        prompt=f"Con números de secuencia de {k2} bits ({2 ** k2} valores), pero "
               "ahora en Selective Repeat: ¿cuál es el tamaño MÁXIMO de ventana?",
        kind="text", answer=2 ** (k2 - 1), answer_kind="int",
        explain=f"W <= 2^k / 2 = 2^{k2 - 1} = {2 ** (k2 - 1)}. Es la mitad que "
                "en GBN porque el receptor de SR acepta paquetes fuera de orden "
                "dentro de su ventana, y las ventanas de emisor y receptor no "
                "deben poder solaparse.",
        difficulty="dificil", category="Selective Repeat"))

    n = random.choice([4, 5, 6, 7, 8])
    base = random.choice([0, 10, 20, 100])
    perdido = base + random.randint(0, n - 2)
    ultimo = base + n - 1
    banco.append(Question(
        prompt=f"En Go-Back-N con ventana N={n}, el emisor manda los paquetes "
               f"{base} a {ultimo} y se pierde el {perdido}. Los demás llegan "
               "pero el receptor los descarta por estar fuera de orden. Al "
               "vencer el temporizador, ¿cuántos paquetes retransmite?",
        kind="text", answer=ultimo - perdido + 1, answer_kind="int",
        explain=f"Retrocede al primer no confirmado y reenvía desde ahí: del "
                f"{perdido} al {ultimo} son {ultimo} - {perdido} + 1 = "
                f"{ultimo - perdido + 1} paquetes. Los "
                f"{ultimo - perdido} posteriores se reenvían aunque hubieran "
                "llegado bien. En Selective Repeat se retransmitiría uno solo.",
        difficulty="medio", category="Go-Back-N"))

    n2 = random.choice([4, 6, 8])
    banco.append(Question(
        prompt=f"Mismo escenario (ventana N={n2}, se pierde UN paquete del medio "
               "y el resto llega bien), pero con Selective Repeat. ¿Cuántos "
               "paquetes se retransmiten?",
        kind="text", answer=1, answer_kind="int",
        explain="Solo el que se perdió. El receptor guardó los adelantados y los "
                "confirmó uno por uno, así que el emisor sabe exactamente cuál "
                "falta. Comparar este número con el de GBN es la forma más "
                "clara de ver por qué SR aprovecha mejor el ancho de banda.",
        difficulty="medio", category="Selective Repeat"))

    mbps = random.choice([10, 100, 1000])
    rtt = random.choice([20, 50, 100, 200])
    bdp = int(mbps * 1_000_000 * (rtt / 1000) / 8)
    banco.append(Question(
        prompt=f"Un enlace de {mbps} Mbps con RTT de {rtt} ms. ¿Cuántos BYTES "
               "debe poder tener el emisor en vuelo (producto ancho de banda por "
               "retardo) para aprovechar el enlace al 100%?",
        kind="text", answer=bdp, answer_kind="int",
        explain=f"BDP = {mbps} Mbps x {rtt} ms = "
                f"{int(mbps * 1_000_000 * (rtt / 1000)):,} bits, que entre 8 son "
                f"{bdp:,} bytes. Si la ventana es menor que el BDP, el emisor se "
                "queda esperando ACK con el enlace ocioso. Compáralo con el "
                "máximo de 65535 del campo window y verás por qué hace falta "
                "window scaling.",
        difficulty="dificil", category="Ventana deslizante - teoría"))

    w = random.choice([85, 229, 501, 1024])
    s = random.choice([2, 4, 7])
    banco.append(Question(
        prompt=f"En el handshake se negoció Window Scaling con s={s}, y un "
               f"paquete posterior anuncia win={w}. ¿Cuántos bytes de ventana "
               "son realmente?",
        kind="text", answer=w * (2 ** s), answer_kind="int",
        explain=f"win x 2^s = {w} x {2 ** s} = {w * (2 ** s)} bytes. Por eso no "
                "se puede leer el campo window literalmente sin haber capturado "
                "el handshake donde se negoció la opción.",
        difficulty="dificil", category="Ventana deslizante - teoría"))

    return banco


# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Panel de referencia en una ventana aparte, anclada a la derecha
# ---------------------------------------------------------------------------

RUTA_REFERENCIA = Path(__file__).resolve().parent / "referencia.py"
RUTA_SIMULADOR = Path(__file__).resolve().parent / "ventana_deslizante.py"
RUTA_TCP = Path(__file__).resolve().parent / "tcp_escenarios.py"

APPLESCRIPT_PANEL = """
tell application "Finder"
    set escritorio to bounds of window of desktop
end tell
set anchoPantalla to item 3 of escritorio
set altoPantalla to item 4 of escritorio

tell application "Terminal"
    activate
    do script "clear; {comando}"
    delay 0.4
    try
        -- primero fijamos 84 columnas para que los diagramas no se partan,
        -- y luego anclamos la ventana al borde derecho con ese mismo ancho
        set number of columns of front window to 84
        set marco to bounds of front window
        set anchoVentana to (item 3 of marco) - (item 1 of marco)
        if anchoVentana > anchoPantalla then set anchoVentana to anchoPantalla
        set izquierda to (anchoPantalla - anchoVentana) as integer
        set bounds of front window to {{izquierda, 0, anchoPantalla, altoPantalla}}
    end try
end tell
"""


def abrir_panel_referencia() -> None:
    """Abre el panel de cabeceras en una terminal nueva, en la mitad derecha."""
    if not RUTA_REFERENCIA.exists():
        print(f"\nNo encuentro '{RUTA_REFERENCIA.name}' junto a este script.")
        return

    comando = f"{sys.executable} '{RUTA_REFERENCIA}'"

    if sys.platform != "darwin":
        print("\nLa apertura automática de la ventana solo está preparada para "
              "macOS. En otro sistema, abre otra terminal y ejecuta:")
        print(f"    {comando}")
        return

    import subprocess
    guion = APPLESCRIPT_PANEL.format(comando=comando.replace('"', '\\"'))
    try:
        resultado = subprocess.run(["osascript", "-e", guion],
                                   capture_output=True, text=True, timeout=20)
    except Exception as e:
        print(f"\nNo pude abrir la ventana ({e}). Ábrela a mano con:")
        print(f"    {comando}")
        return

    if resultado.returncode != 0:
        detalle = resultado.stderr.strip().splitlines()
        print("\nNo pude abrir la ventana automáticamente"
              + (f": {detalle[-1]}" if detalle else "."))
        print("Si macOS pidió permiso para controlar Terminal, acéptalo en "
              "Ajustes > Privacidad y seguridad > Automatización.")
        print(f"Mientras tanto, ábrela a mano con:\n    {comando}")
        return

    print("\nPanel de referencia abierto en una ventana nueva, a la derecha.")
    print("Deja esta ventana a la izquierda para tener el volcado y la chuleta "
          "a la vista al mismo tiempo.")
    print("En el panel puedes escribir «tcp», «ipv4», «tablas»... para saltar a "
          "una sección, o «q» para cerrarlo.")


def _lanzar(ruta: Path) -> None:
    """Ejecuta otro script del proyecto en esta misma terminal."""
    if not ruta.exists():
        print(f"\nNo encuentro '{ruta.name}' junto a este script.")
        return
    import runpy
    try:
        runpy.run_path(str(ruta), run_name="__main__")
    except (KeyboardInterrupt, EOFError):
        print()
    except SystemExit:
        pass


def abrir_simulador() -> None:
    _lanzar(RUTA_SIMULADOR)


def abrir_tcp() -> None:
    _lanzar(RUTA_TCP)


# ---------------------------------------------------------------------------
# Temas: en vez de elegir un archivo, se elige QUÉ se quiere practicar
# ---------------------------------------------------------------------------

@dataclass
class Coleccion:
    """Los paquetes de un tema, reunidos de todas las capturas que lo tengan."""
    tema: str
    descripcion: str
    paquetes: List[Packet] = field(default_factory=list)
    # captura completa de cada archivo que aporta algo: las preguntas de
    # secuencia y de análisis necesitan el contexto entero, no paquetes sueltos
    por_archivo: Dict[str, List[Packet]] = field(default_factory=dict)

    @property
    def archivos(self) -> List[str]:
        return sorted(self.por_archivo)


def _tiene(*capas):
    return lambda p: bool(set(capas) & set(p.layers))


def _es_texto(p: Packet) -> bool:
    if "TCP" not in p.layers or len(p.payload) < 4:
        return False
    legible = sum(1 for b in p.payload if 32 <= b <= 126 or b in (13, 10))
    return legible >= len(p.payload) * 0.9


def _es_ataque(p: Packet) -> bool:
    """Paquetes que por sí solos delatan algo raro."""
    if p.info.get("arp_oper") == 2:
        return True
    if p.info.get("icmp_type") == 8:
        d = p.info.get("dst_ip", "")
        if d.endswith(".255") or d == "255.255.255.255":
            return True
    if p.info.get("tcp_syn") == 1 and p.info.get("tcp_ack") == 0:
        return True
    return False


TEMAS = [
    ("Ethernet y capa 2", "MAC origen y destino, EtherType, broadcast",
     _tiene("Ethernet", "Loopback", "Linux SLL")),
    ("ARP", "resolución IP a MAC, gratuitous ARP, spoofing", _tiene("ARP")),
    ("IPv4", "versión, IHL, TTL, fragmentación, checksum", _tiene("IPv4")),
    ("IPv6", "cabecera fija de 40 bytes, next header, hop limit", _tiene("IPv6")),
    ("ICMP", "tipos y códigos, ping, destino inalcanzable, TTL agotado",
     _tiene("ICMP")),
    ("TCP", "puertos, seq y ack, flags, ventana, opciones", _tiene("TCP")),
    ("UDP", "cabecera de 8 bytes, longitud, checksum opcional", _tiene("UDP")),
    ("DNS", "transaction ID, flags, nombres codificados con longitudes",
     _tiene("DNS")),
    ("DHCP", "ciclo DORA, yiaddr, magic cookie, opción 53", _tiene("DHCP")),
    ("RIP", "vector distancia, métricas, redes anunciadas, métrica 16",
     _tiene("RIP")),
    ("OSPF", "estado de enlace, Hello, áreas, LSA, DR y BDR", _tiene("OSPF")),
    ("IGMP", "grupos multicast, Query y Report", _tiene("IGMP")),
    ("Enrutamiento (RIP + OSPF)", "comparar vector distancia con estado de enlace",
     _tiene("RIP", "OSPF")),
    ("Aplicación en texto plano", "FTP y HTTP legibles en la columna ASCII",
     _es_texto),
    ("Seguridad y ataques", "ARP spoofing, floods, escaneos, MITM", _es_ataque),
]


def cargar_todas(mostrar: bool = True) -> Dict[str, List[Packet]]:
    """Lee de una vez todas las capturas de la carpeta 'files'."""
    if not FILES_DIR.is_dir():
        print(f"\nNo existe la carpeta '{FILES_DIR}'.")
        sys.exit(1)
    archivos = sorted(FILES_DIR.glob("*.pcap")) + sorted(FILES_DIR.glob("*.pcapng"))
    if not archivos:
        print(f"\nNo encontré capturas en '{FILES_DIR}'.")
        sys.exit(1)

    capturas: Dict[str, List[Packet]] = {}
    problemas = []
    for ruta in archivos:
        try:
            capturas[ruta.name] = cargar_captura(ruta)
        except Exception as e:
            problemas.append(f"{ruta.name}: {e}")
    if not capturas:
        print("No pude leer ninguna captura.")
        sys.exit(1)
    if mostrar:
        total = sum(len(v) for v in capturas.values())
        print(f"\n{len(capturas)} capturas leídas, {total} paquetes en total.")
        for x in problemas:
            print(f"  (no pude leer {x})")
    return capturas


def indexar(capturas: Dict[str, List[Packet]]) -> List[Coleccion]:
    """Reparte los paquetes de todas las capturas entre los temas."""
    colecciones = []
    for nombre, desc, cumple in TEMAS:
        col = Coleccion(nombre, desc)
        for archivo, pkts in capturas.items():
            elegidos = [p for p in pkts if cumple(p)]
            if elegidos:
                col.paquetes.extend(elegidos)
                col.por_archivo[archivo] = pkts
        if col.paquetes:
            colecciones.append(col)
    return colecciones


def elegir_tema(colecciones: List[Coleccion]):
    """Devuelve una Coleccion, None para elegir archivo, o False para salir."""
    print("\n" + RULE)
    print("  ¿QUÉ QUIERES PRACTICAR?")
    print(RULE)
    for i, c in enumerate(colecciones, 1):
        print(f"  {i:>2}) {c.tema}")
    print(f"  {len(colecciones) + 1:>2}) Todo mezclado")
    print(f"  {len(colecciones) + 2:>2}) Elegir una captura concreta")
    print(f"  {len(colecciones) + 3:>2}) Salir")

    while True:
        bruto = input("> ").strip()
        if bruto.isdigit():
            n = int(bruto)
            if 1 <= n <= len(colecciones):
                return colecciones[n - 1]
            if n == len(colecciones) + 1:
                todo = Coleccion("Todo mezclado", "paquetes de todas las capturas")
                for c in colecciones:
                    todo.por_archivo.update(c.por_archivo)
                for pkts in todo.por_archivo.values():
                    todo.paquetes.extend(pkts)
                return todo
            if n == len(colecciones) + 2:
                return None
            if n == len(colecciones) + 3:
                return False
        print(f"Escribe un número entre 1 y {len(colecciones) + 3}.")



def armar_pool_tema(col: Coleccion, dificultad: str, ascii_on: bool,
                    por_paquete: int = 3) -> List[Question]:
    """Preguntas del tema, con paquetes de todas las capturas que lo contengan."""
    utiles = [p for p in col.paquetes if len(p.fields) >= 4] or col.paquetes
    muestra = random.sample(utiles, k=min(14, len(utiles)))

    pool: List[Question] = []
    for p in muestra:
        pool.extend(preguntas_de_campos(p, ascii_on, dificultad, por_paquete))
        pool.extend(preguntas_calculadas(p, ascii_on))

    # secuencias y análisis se hacen POR CAPTURA: mezclar paquetes de archivos
    # distintos inventaría conversaciones que nunca existieron
    for pkts in col.por_archivo.values():
        pool.extend(preguntas_de_secuencia(pkts))
        pool.extend(preguntas_de_captura(pkts, ascii_on))

    pool.extend(preguntas_ventana(col.paquetes, ascii_on))
    pool.extend(preguntas_gbn_sr())

    if dificultad != "mixto":
        filtrado = [q for q in pool if q.difficulty == dificultad]
        if filtrado:
            pool = filtrado
    random.shuffle(pool)
    return pool


# ---------------------------------------------------------------------------
# Menús y flujo principal
# ---------------------------------------------------------------------------

def menu(titulo: str, opciones: List[str]) -> int:
    print(f"\n{titulo}")
    for i, o in enumerate(opciones, 1):
        print(f"  {i}) {o}")
    while True:
        bruto = input("> ").strip()
        if bruto.isdigit() and 1 <= int(bruto) <= len(opciones):
            return int(bruto) - 1
        print(f"Escribe un número entre 1 y {len(opciones)}.")


def elegir_captura() -> Path:
    if not FILES_DIR.is_dir():
        print(f"\nNo existe la carpeta '{FILES_DIR}'.")
        sys.exit(1)
    candidatos = sorted(FILES_DIR.glob("*.pcap"))
    if not candidatos:
        print(f"\nNo encontré archivos .pcap en '{FILES_DIR}'.")
        print("Coloca ahí tus capturas y vuelve a ejecutar el juego.")
        sys.exit(1)
    idx = menu("Capturas disponibles en la carpeta 'files':",
               [c.name for c in candidatos])
    return candidatos[idx]


def jugar(col: "Coleccion") -> None:
    print(f"\n{RULE}\n  {col.tema.upper()}  ·  {len(col.paquetes)} paquetes")
    if len(col.por_archivo) > 1:
        print(f"  reunidos de {len(col.archivos)} capturas: "
              f"{', '.join(col.archivos)}")
    else:
        print(f"  de: {col.archivos[0]}")
    print(RULE)

    dificultad = ["facil", "medio", "dificil", "mixto"][
        menu("Dificultad:", ["Fácil (campos directos: MACs, IPs, puertos, TTL)",
                             "Medio (longitudes, checksums, flags, DNS)",
                             "Difícil (bits, offsets, cálculos, GBN/SR)",
                             "Mixta (todas)"])]
    ascii_on = menu("Volcado hexadecimal:",
                    ["Hex + ASCII (recomendado)", "Solo hex"]) == 0

    pool = armar_pool_tema(col, dificultad, ascii_on)
    if not pool:
        print("No hay preguntas para esa combinación. Prueba con «Mixta».")
        return

    bruto = input(f"\n¿Cuántas preguntas? (1-{len(pool)}, Enter = 10): ").strip()
    n = a_entero(bruto) if bruto else 10
    if n is None:
        n = 10
    n = max(1, min(n, len(pool)))

    print(f"\n{RULE}\nEmpezamos: {n} preguntas ({DIFFICULTY_LABELS[dificultad]})")
    print("En cualquier momento puedes escribir «form» para abrir la guía en "
          "otra ventana,")
    print("o «form tcp», «form gbn», «form teoriarip»... para ver una sección "
          "aquí mismo.")
    print(RULE)

    aciertos = 0
    fallos: List[Question] = []
    try:
        for i, q in enumerate(pool[:n], 1):
            print(f"\nPregunta {i}/{n}")
            if q.preguntar():
                aciertos += 1
            else:
                fallos.append(q)
    except (KeyboardInterrupt, EOFError):
        print("\n\nPartida interrumpida.")
        n = i

    pct = 100 * aciertos / n if n else 0
    print(f"\n{RULE}\nResultado: {aciertos}/{n}  ({pct:.0f}%)\n{RULE}")

    if fallos:
        temas = Counter(q.category for q in fallos)
        print("Temas donde fallaste:")
        for tema, veces in temas.most_common():
            print(f"  {veces}x  {tema}")

    if pct >= 90:
        print("\nLees el volcado con soltura.")
    elif pct >= 70:
        print("\nBuen nivel. Repasa las notas de lo que fallaste.")
    elif pct >= 40:
        print("\nVas bien, pero conviene practicar los offsets de cabecera.")
    else:
        print("\nUsa el modo estudio: mira paquetes anotados antes de jugar.")



def coleccion_de_archivo(capturas: Dict[str, List[Packet]]
                        ) -> Optional["Coleccion"]:
    """La opción de siempre: practicar con una sola captura."""
    nombres = sorted(capturas)
    idx = menu("Capturas disponibles:", nombres + ["Volver"])
    if idx == len(nombres):
        return None
    nombre = nombres[idx]
    col = Coleccion(nombre, "todos los paquetes de esta captura")
    col.paquetes = capturas[nombre]
    col.por_archivo = {nombre: capturas[nombre]}
    return col


def main() -> None:
    print(RULE)
    print("HEX DUMP QUIZ - lectura de paquetes byte a byte")
    print(RULE)
    print("Todo se responde mirando el volcado hexadecimal: valores de campos,")
    print("en qué offset vive cada uno, cómo se decodifican esos bytes, qué")
    print("significan, y qué está ocurriendo en secuencias de 3 a 6 paquetes.")

    capturas = cargar_todas()
    colecciones = indexar(capturas)
    if not colecciones:
        print("No pude interpretar ningún paquete de las capturas.")
        sys.exit(1)

    col = None
    while True:
        if col is None:
            elegido = elegir_tema(colecciones)
            if elegido is False:
                print("\nHasta la próxima.")
                return
            if elegido is None:
                elegido = coleccion_de_archivo(capturas)
                if elegido is None:
                    continue
            col = elegido

        opcion = menu(f"[{col.tema}]  ¿Qué quieres hacer?",
                      ["Jugar",
                       "Escenarios TCP aleatorios (SYN, ACK y ventana)",
                       "Simulador Go-Back-N y Selective Repeat",
                       "Abrir la guía de referencia en una ventana",
                       "Cambiar de tema o de captura",
                       "Salir"])
        if opcion == 0:
            jugar(col)
        elif opcion == 1:
            abrir_tcp()
        elif opcion == 2:
            abrir_simulador()
        elif opcion == 3:
            abrir_panel_referencia()
        elif opcion == 4:
            col = None
        else:
            print("\nHasta la próxima.")
            return



# ---------------------------------------------------------------------------
# Protocolos de enrutamiento: RIP, OSPF e IGMP
# ---------------------------------------------------------------------------

def parse_rip(pkt: Packet, base: int) -> None:
    """RIPv2 sobre UDP 520. Cabecera de 4 bytes + entradas de 20 bytes."""
    d = pkt.raw
    if len(d) < base + 4:
        return
    pkt.layers.append("RIP")

    cmd, ver = d[base], d[base + 1]
    pkt.add("rip_command", "Comando RIP", "RIP", base, 1, cmd,
            note=f"{cmd} = {RIP_COMANDOS.get(cmd, 'desconocido')}. Un Request "
                 "pide la tabla de rutas entera; un Response la anuncia. Los "
                 "routers RIP mandan un Response cada 30 segundos aunque nadie "
                 "les pregunte.")
    pkt.add("rip_version", "Versión RIP", "RIP", base + 1, 1, ver,
            note="La versión 2 añade máscara de red, next hop y route tag a "
                 "cada entrada, y usa multicast 224.0.0.9 en lugar de "
                 "broadcast. La versión 1 no llevaba máscara: era classful.")
    pkt.info["rip_command_name"] = RIP_COMANDOS.get(cmd, str(cmd))

    # cada ruta ocupa 20 bytes exactos
    cuerpo = len(d) - (base + 4)
    n_rutas = cuerpo // 20
    pkt.info["rip_n_rutas"] = n_rutas
    rutas = []
    for i in range(n_rutas):
        o = base + 4 + i * 20
        if o + 20 > len(d):
            break
        afi = struct.unpack("!H", d[o:o + 2])[0]
        tag = struct.unpack("!H", d[o + 2:o + 4])[0]
        red = ip_to_str(d[o + 4:o + 8])
        masc = ip_to_str(d[o + 8:o + 12])
        nh = ip_to_str(d[o + 12:o + 16])
        met = struct.unpack("!I", d[o + 16:o + 20])[0]
        rutas.append({"red": red, "mascara": masc, "next_hop": nh,
                      "metrica": met, "afi": afi, "tag": tag})

        etq = f" (ruta {i + 1})" if n_rutas > 1 else ""
        pkt.add(f"rip{i}_afi", f"AFI{etq}", "RIP", o, 2, afi,
                note="Address Family Identifier: 2 = IPv4. Un AFI de 0 con "
                     "métrica 16 es la petición especial de «mándame la tabla "
                     "entera».")
        pkt.add(f"rip{i}_tag", f"Route tag{etq}", "RIP", o + 2, 2, tag,
                note="Marca rutas aprendidas de otro protocolo (redistribución). "
                     "En una red RIP pura vale 0.")
        pkt.add(f"rip{i}_red", f"Red anunciada{etq}", "RIP", o + 4, 4, red,
                kind="ip",
                note="La red que este router dice saber alcanzar.")
        pkt.add(f"rip{i}_mascara", f"Máscara{etq}", "RIP", o + 8, 4, masc,
                kind="ip",
                note="Solo existe en RIPv2. Es lo que permite VLSM y CIDR: sin "
                     "ella habría que asumir la máscara por clase.")
        pkt.add(f"rip{i}_nexthop", f"Next hop{etq}", "RIP", o + 12, 4, nh,
                kind="ip",
                note="0.0.0.0 significa «mándamelo a mí, al que envía este "
                     "paquete». Solo se rellena para evitar un salto extra "
                     "cuando hay varios routers en la misma LAN.")
        pkt.add(f"rip{i}_metrica", f"Métrica{etq}", "RIP", o + 16, 4, met,
                note=f"{met} saltos. En RIP la métrica es el número de routers "
                     "que hay que atravesar, y el máximo es 15: el valor 16 "
                     "significa INFINITO, o sea red inalcanzable. Ese techo tan "
                     "bajo es la principal limitación de RIP y lo que lo hace "
                     "inservible en redes grandes.")
    pkt.info["rip_rutas"] = rutas


def parse_ospf(pkt: Packet, base: int) -> None:
    """OSPFv2 va directo sobre IP con protocolo 89, sin TCP ni UDP."""
    d = pkt.raw
    if len(d) < base + 24:
        return
    pkt.layers.append("OSPF")

    ver, tipo = d[base], d[base + 1]
    largo = struct.unpack("!H", d[base + 2:base + 4])[0]
    rid = ip_to_str(d[base + 4:base + 8])
    area = ip_to_str(d[base + 8:base + 12])
    cks = struct.unpack("!H", d[base + 12:base + 14])[0]
    autype = struct.unpack("!H", d[base + 14:base + 16])[0]

    pkt.add("ospf_version", "Versión OSPF", "OSPF", base, 1, ver,
            note="2 para IPv4 (OSPFv2); la versión 3 es la de IPv6.")
    pkt.add("ospf_type", "Tipo de paquete OSPF", "OSPF", base + 1, 1, tipo,
            note=f"{tipo} = {OSPF_TIPOS.get(tipo, 'desconocido')}. Los cinco "
                 "tipos son: 1 Hello (descubre vecinos y mantiene la "
                 "adyacencia), 2 Database Description (resumen de la base de "
                 "datos), 3 Link State Request (pide lo que le falta), 4 Link "
                 "State Update (manda las LSA), 5 LSAck (las confirma).")
    pkt.add("ospf_length", "Longitud OSPF", "OSPF", base + 2, 2, largo,
            note="Bytes del paquete OSPF, cabecera incluida. No cuenta ni IP ni "
                 "Ethernet.")
    pkt.add("ospf_router_id", "Router ID", "OSPF", base + 4, 4, rid, kind="ip",
            note="Identifica al router dentro del dominio OSPF. Tiene forma de "
                 "IP pero NO es una dirección: es un identificador de 32 bits, "
                 "normalmente la IP más alta de sus interfaces o una loopback.")
    pkt.add("ospf_area", "Area ID", "OSPF", base + 8, 4, area, kind="ip",
            note="0.0.0.0 es el área backbone (área 0), a la que deben "
                 "conectarse todas las demás. Dividir en áreas es lo que "
                 "permite a OSPF escalar donde RIP no puede.")
    pkt.add("ospf_checksum", "Checksum OSPF", "OSPF", base + 12, 2, cks,
            display=f"0x{cks:04x}", kind="hex")
    pkt.add("ospf_autype", "Tipo de autenticación", "OSPF", base + 14, 2, autype,
            note=f"{autype} = {OSPF_AUTH.get(autype, 'desconocido')}. A "
                 "diferencia de ARP o RIPv1, OSPF sí puede autenticar sus "
                 "mensajes, lo que dificulta que un atacante inyecte rutas "
                 "falsas.")
    pkt.info["ospf_type_name"] = OSPF_TIPOS.get(tipo, str(tipo))

    if tipo == 1 and len(d) >= base + 44:      # Hello
        o = base + 24
        masc = ip_to_str(d[o:o + 4])
        hello = struct.unpack("!H", d[o + 4:o + 6])[0]
        opciones = d[o + 6]
        prio = d[o + 7]
        muerto = struct.unpack("!I", d[o + 8:o + 12])[0]
        dr = ip_to_str(d[o + 12:o + 16])
        bdr = ip_to_str(d[o + 16:o + 20])

        pkt.add("ospf_netmask", "Máscara de red", "OSPF", o, 4, masc, kind="ip",
                note="Los dos vecinos tienen que coincidir en la máscara, o no "
                     "llegan a formar adyacencia.")
        pkt.add("ospf_hello_interval", "Hello interval", "OSPF", o + 4, 2, hello,
                note=f"Cada {hello} segundos se manda un Hello. Es uno de los "
                     "parámetros que DEBEN coincidir entre vecinos.")
        pkt.add("ospf_options", "Opciones", "OSPF", o + 6, 1, opciones,
                display=f"0x{opciones:02x}", kind="hex",
                note="Bits de capacidades: el bit E indica si el área acepta "
                     "rutas externas.")
        pkt.add("ospf_priority", "Prioridad del router", "OSPF", o + 7, 1, prio,
                note=f"{prio}. Sirve para elegir el DR de la red: gana la "
                     "prioridad más alta y, en caso de empate, el Router ID "
                     "mayor. Con prioridad 0 el router renuncia a ser DR.")
        pkt.add("ospf_dead_interval", "Dead interval", "OSPF", o + 8, 4, muerto,
                note=f"{muerto} segundos sin recibir un Hello y el vecino se da "
                     f"por caído. Suele ser 4 veces el hello interval "
                     f"({hello} x 4 = {hello * 4}"
                     + (", que es justo lo que vale aquí)."
                        if muerto == hello * 4 else f", aquí vale {muerto}).")
                     + " También tiene que coincidir entre vecinos.")
        pkt.add("ospf_dr", "Designated Router", "OSPF", o + 12, 4, dr, kind="ip",
                note="0.0.0.0 significa que todavía no se ha elegido DR. El DR "
                     "centraliza el intercambio de LSA en redes con muchos "
                     "routers, para no tener que emparejarlos todos con todos.")
        pkt.add("ospf_bdr", "Backup Designated Router", "OSPF", o + 16, 4, bdr,
                kind="ip", note="El suplente del DR, listo para reemplazarlo.")

        vecinos = []
        v = o + 20
        while v + 4 <= min(len(d), base + largo):
            vecinos.append(ip_to_str(d[v:v + 4]))
            v += 4
        pkt.info["ospf_vecinos"] = vecinos
        if vecinos:
            pkt.add("ospf_neighbor", "Vecino declarado", "OSPF", o + 20, 4,
                    vecinos[0], kind="ip",
                    note=f"Lista de Router ID que este router ya está oyendo "
                         f"({len(vecinos)} en este Hello). Verse a uno mismo en "
                         "la lista del vecino es lo que confirma que la "
                         "comunicación es bidireccional.")

    elif tipo == 4 and len(d) >= base + 28:    # Link State Update
        n = struct.unpack("!I", d[base + 24:base + 28])[0]
        pkt.add("ospf_n_lsa", "Número de LSA", "OSPF", base + 24, 4, n,
                note="Cuántos anuncios de estado de enlace vienen en este "
                     "paquete. Cada LSA describe un trozo de la topología; con "
                     "todas ellas cada router construye el mismo mapa y corre "
                     "Dijkstra sobre él.")
        if len(d) >= base + 32 + 4:
            tipo_lsa = d[base + 28 + 3]
            pkt.add("ospf_lsa_tipo", "Tipo de la primera LSA", "OSPF",
                    base + 28 + 3, 1, tipo_lsa,
                    note=f"{tipo_lsa} = {LSA_TIPOS.get(tipo_lsa, 'desconocido')}. "
                         "La Router-LSA describe los enlaces del propio router; "
                         "la Network-LSA, una red de acceso múltiple.")


def parse_igmp(pkt: Packet, base: int) -> None:
    """IGMP: cómo un host se apunta o se borra de un grupo multicast."""
    d = pkt.raw
    if len(d) < base + 8:
        return
    pkt.layers.append("IGMP")
    tipo = d[base]
    pkt.add("igmp_type", "Tipo IGMP", "IGMP", base, 1, tipo,
            display=f"0x{tipo:02x}", kind="hex",
            note=f"0x{tipo:02x} = {IGMP_TIPOS.get(tipo, 'desconocido')}. IGMP "
                 "es cómo un host le dice al router «quiero recibir este grupo "
                 "multicast». El router usa esa información para saber por qué "
                 "puertos reenviar el tráfico del grupo.")
    if tipo != 0x22:
        pkt.add("igmp_grupo", "Grupo multicast", "IGMP", base + 4, 4,
                ip_to_str(d[base + 4:base + 8]), kind="ip",
                note="La dirección de grupo a la que se refiere el mensaje.")


# ---------------------------------------------------------------------------
# Análisis de la captura completa: preguntas derivadas de lo que hay dentro
# ---------------------------------------------------------------------------

def _txt(n, sing, plur=None):
    return sing if n == 1 else (plur or sing + "s")


def bloque_evidencia(titulo: str, lineas: List[str]) -> str:
    """Evidence block: what the question is asked about must be visible here."""
    return "\n".join(["", RULE, "  " + titulo, RULE] + lineas + [RULE])


def _prefijo(mascara: str) -> int:
    """255.255.255.252 -> 30. Counts the bits actually set to one."""
    try:
        return sum(bin(int(x)).count("1") for x in mascara.split("."))
    except ValueError:
        return 0


def _resumen_rip(p: Packet) -> str:
    rutas = [r for r in p.info.get("rip_rutas", []) if r["red"] != "0.0.0.0"]
    if rutas:
        detalle = "  ".join(f"{r['red']}/{_prefijo(r['mascara'])} m={r['metrica']}"
                            for r in rutas[:3])
        if len(rutas) > 3:
            detalle += f"  (+{len(rutas) - 3})"
    else:
        detalle = "full-table request (AFI=0, metric=16)"
    cmd = "Response" if p.info.get("rip_command") == 2 else "Request "
    return f"  #{p.num:<5} {p.info['src_ip']:>15}  {cmd}  {detalle}"


def preguntas_rip(pkts: List[Packet], ascii_on: bool) -> List[Question]:
    """RIP questions. Everything asked is visible in the evidence block."""
    rip = [p for p in pkts if "RIP" in p.layers]
    if not rip:
        return []
    qs = []

    # a bounded sample: the questions below are about THIS sample, so the
    # answer is always derivable from what is on screen
    muestra = rip[:14]
    tabla = bloque_evidencia(
        f"RIP packets in this capture (showing {len(muestra)} of {len(rip)})",
        [f"  {'#':<6}{'source':>15}  command   advertised routes",
         "  " + "-" * 68] + [_resumen_rip(p) for p in muestra])

    routers = sorted({p.info["src_ip"] for p in muestra})
    qs.append(Question(
        prompt="Looking at the table, how many DIFFERENT routers are "
               "advertising routes by RIP?",
        kind="text", answer=len(routers), answer_kind="int",
        explain=f"{len(routers)}: {', '.join(routers)}. Just count the distinct "
                "source addresses. In a RIP network every router talks only to "
                "its direct neighbours and sends them its whole table every 30 "
                "seconds.",
        difficulty="medio", category="RIP", dump=tabla))

    redes = sorted({r["red"] for p in muestra for r in p.info.get("rip_rutas", [])
                    if r["red"] != "0.0.0.0"})
    if redes:
        qs.append(Question(
            prompt="How many DIFFERENT networks are advertised in the table?",
            kind="text", answer=len(redes), answer_kind="int",
            explain=f"{len(redes)}: {', '.join(redes)}. Putting all the "
                    "advertisements together you can rebuild the topology "
                    "without logging into a single router.",
            difficulty="dificil", category="RIP", dump=tabla))

        con_rutas = [p for p in muestra
                     if any(r["red"] != "0.0.0.0" for r in p.info.get("rip_rutas", []))]
        if con_rutas:
            p = random.choice(con_rutas)
            r = random.choice([x for x in p.info["rip_rutas"] if x["red"] != "0.0.0.0"])
            qs.append(Question(
                prompt=f"Packet #{p.num} advertises the network {r['red']}. "
                       "With what metric (hop count)?",
                kind="text", answer=r["metrica"], answer_kind="int",
                explain=f"Metric {r['metrica']}. In RIP the metric is simply how "
                        "many routers you have to cross. A metric of 1 means the "
                        "network is directly connected to the router announcing "
                        "it. The maximum valid value is 15, and 16 means "
                        "unreachable, which is why RIP is useless in networks "
                        "more than 15 hops wide.",
                difficulty="medio", category="RIP",
                dump=bloque_dump(p, ascii_on)))

    peticiones = [p for p in muestra if p.info.get("rip_command") == 1]
    if peticiones and len(peticiones) < len(muestra):
        qs.append(Question(
            prompt="How many of the packets in the table are Requests "
                   "(command 1), that is, asking for the table?",
            kind="text", answer=len(peticiones), answer_kind="int",
            explain=f"{len(peticiones)} Request and "
                    f"{len(muestra) - len(peticiones)} Response. A Request shows "
                    "up mostly when a router boots: it asks for the full table "
                    "instead of waiting 30 seconds for the next periodic "
                    "advertisement.",
            difficulty="medio", category="RIP", dump=tabla))

    p = rip[0]
    dst = p.info["dst_ip"]
    otras = [k for k in MULTICAST_CONOCIDAS if k != dst][:3]
    opts, idx = mcq_opciones(
        f"{dst} — all RIPv2 routers",
        [f"{k} — {MULTICAST_CONOCIDAS[k]}" for k in otras])
    qs.append(Question(
        prompt=f"Read the destination address of this packet ({dst}). "
               "What does that address stand for?",
        kind="mcq", answer=idx, options=opts,
        explain=f"RIPv2 uses {dst} so that only routers speaking RIP process "
                "the packet, instead of bothering every host with a broadcast "
                "the way RIPv1 did. You can also see it in the destination MAC, "
                "which starts with 01:00:5e, the IPv4 multicast prefix.",
        difficulty="medio", category="RIP",
        dump=bloque_dump(p, ascii_on, highlight=p.get("dst_ip"))))

    if {x.info["ip_ttl"] for x in rip} == {1}:
        qs.append(Question(
            prompt="Every RIP packet in this capture leaves with TTL=1. Why?",
            kind="mcq", answer=0,
            options=["So that no router forwards them: RIP must only talk to "
                     "directly connected neighbours",
                     "Because the network is one hop wide",
                     "Because multicast TTL is always 1 by standard",
                     "It is a router misconfiguration"],
            explain="With TTL=1 the first router that receives the packet drops "
                    "it instead of forwarding it. That is deliberate: RIP "
                    "advertisements are link-local, each router should only hear "
                    "what its immediate neighbours tell it, and then it "
                    "propagates its own version. OSPF does the same with its "
                    "Hellos.",
            difficulty="dificil", category="RIP",
            dump=bloque_dump(p, ascii_on, highlight=p.get("ip_ttl"))))

    infinitas = [x for x in rip
                 if any(r["metrica"] == 16 for r in x.info.get("rip_rutas", []))]
    if infinitas:
        z = infinitas[0]
        qs.append(Question(
            prompt="This packet carries an entry with metric 16. What does "
                   "that value mean?",
            kind="mcq", answer=0,
            options=["Infinity: the network is unreachable",
                     "That the route is the best one available",
                     "That the destination is exactly 16 hops away",
                     "That the entry uses authentication"],
            explain="16 is RIP's infinity. It is used for two things: "
                    "announcing that a network can no longer be reached (route "
                    "poisoning, so neighbours delete it instead of waiting for "
                    "it to expire) and, together with AFI=0, asking for the "
                    "complete routing table. Since the maximum useful value is "
                    "15, that short counter is also what stops a routing loop "
                    "from lasting forever.",
            difficulty="dificil", category="RIP",
            dump=bloque_dump(z, ascii_on)))
    return qs

def preguntas_ospf(pkts: List[Packet], ascii_on: bool) -> List[Question]:
    """OSPF questions, always with the evidence on screen."""
    ospf = [p for p in pkts if "OSPF" in p.layers]
    if not ospf:
        return []
    qs = []

    muestra = ospf[:14]
    tabla = bloque_evidencia(
        f"OSPF packets in this capture (showing {len(muestra)} of {len(ospf)})",
        [f"  {'#':<7}{'source':>15}  {'type':<22}{'Router ID':<16}area",
         "  " + "-" * 68] +
        [f"  #{p.num:<6}{p.info['src_ip']:>15}  "
         f"{OSPF_TIPOS.get(p.info['ospf_type'], '?'):<22}"
         f"{p.info['ospf_router_id']:<16}{p.info['ospf_area']}"
         for p in muestra])

    rids = sorted({p.info["ospf_router_id"] for p in muestra})
    qs.append(Question(
        prompt="How many different Router IDs appear in the table?",
        kind="text", answer=len(rids), answer_kind="int",
        explain=f"{len(rids)}: {', '.join(rids)}. The Router ID looks like an "
                "IP address but it is not one: it is a 32-bit identifier that "
                "tells each router apart inside the OSPF domain.",
        difficulty="medio", category="OSPF", dump=tabla))

    tipos = Counter(p.info["ospf_type"] for p in muestra)
    mas, veces = tipos.most_common(1)[0]
    nombre = OSPF_TIPOS.get(mas, str(mas))
    opts, idx = mcq_opciones(nombre, [v for v in OSPF_TIPOS.values() if v != nombre])
    qs.append(Question(
        prompt="Which packet type shows up most often in the table?",
        kind="mcq", answer=idx, options=opts,
        explain=f"{nombre}, {veces} times out of {len(muestra)}. Hellos are the "
                "most numerous because they repeat every few seconds to keep "
                "the adjacency alive, while Updates only appear when something "
                "actually changes.",
        difficulty="medio", category="OSPF", dump=tabla))

    p = ospf[0]
    qs.append(Question(
        prompt="OSPF uses neither TCP nor UDP: it rides straight on top of IP. "
               "Read the «protocol» field of the IP header. What number is it?",
        kind="text", answer=89, answer_kind="int",
        explain="89. That is why there are no ports to read in the dump: right "
                "after the IP header the OSPF header begins. RIP does go over "
                "UDP (port 520), and there you do get ports.",
        difficulty="medio", category="OSPF",
        dump=bloque_dump(p, ascii_on, highlight=p.get("ip_proto"))))

    hellos = [x for x in ospf if x.info.get("ospf_type") == 1
              and "ospf_hello_interval" in x.info]
    if hellos:
        h = hellos[0]
        hi, di = h.info["ospf_hello_interval"], h.info["ospf_dead_interval"]
        dump_h = bloque_dump(h, ascii_on, highlight=h.get("ospf_dead_interval"))
        qs.append(Question(
            prompt="How many seconds without hearing a Hello before this "
                   "router declares a neighbour dead?",
            kind="text", answer=di, answer_kind="int",
            explain=f"The dead interval: {di} seconds (the highlighted field). "
                    f"The hello interval is {hi}, so the usual 4:1 ratio holds: "
                    f"{hi} x 4 = {di}. Lowering it makes the network react "
                    "faster to a failure, but risks declaring a neighbour dead "
                    "over a passing congestion. Both values must MATCH on both "
                    "ends or the adjacency never forms.",
            difficulty="medio", category="OSPF", dump=dump_h))

        area = h.info["ospf_area"]
        qs.append(Question(
            prompt=f"This packet carries Area ID = {area}. What does that "
                   "particular area mean?",
            kind="mcq", answer=0,
            options=["It is area 0, the backbone: every other area must connect "
                     "to it" if area == "0.0.0.0" else
                     f"It is area {area}, a normal area, not the backbone",
                     "It is an area reserved for external routes",
                     "It means the router has no area assigned",
                     "It is the autonomous system identifier"],
            explain=("Area 0.0.0.0 is the backbone. OSPF splits the domain into "
                     "areas so each router only needs the detailed topology of "
                     "its own: that is what lets it scale where RIP, which "
                     "floods its whole table to everyone, cannot."
                     if area == "0.0.0.0" else
                     f"Area {area} is not the backbone; it would have to "
                     "connect to area 0 to exchange routes with the rest of "
                     "the domain."),
            difficulty="dificil", category="OSPF",
            dump=bloque_dump(h, ascii_on, highlight=h.get("ospf_area"))))

        if h.info.get("ospf_dr") == "0.0.0.0":
            qs.append(Question(
                prompt="In this Hello the Designated Router field is 0.0.0.0. "
                       "What does that tell you?",
                kind="mcq", answer=0,
                options=["That no DR has been elected on that link yet",
                         "That the router refuses to take part in the election",
                         "That the network does not support multicast",
                         "That the DR has crashed"],
                explain="A DR of 0.0.0.0 means the election has not happened. "
                        "On a point-to-point link (a /30 mask, for instance) no "
                        "DR is needed at all: with only two routers there is "
                        "nothing to centralise. The DR matters on multi-access "
                        "networks with many routers, to avoid pairing every "
                        "router with every other one.",
                difficulty="dificil", category="OSPF",
                dump=bloque_dump(h, ascii_on, highlight=h.get("ospf_dr"))))

    lsu = [x for x in ospf if x.info.get("ospf_type") == 4 and "ospf_n_lsa" in x.info]
    if lsu:
        z = lsu[0]
        qs.append(Question(
            prompt="How many LSAs does this Link State Update carry?",
            kind="text", answer=z.info["ospf_n_lsa"], answer_kind="int",
            explain=f"{z.info['ospf_n_lsa']}. Every LSU carries a counter of how "
                    "many LSAs it transports. With all the LSAs each router "
                    "builds an identical copy of the network map and runs "
                    "Dijkstra on it: that is why OSPF is link state and RIP is "
                    "distance vector.",
            difficulty="dificil", category="OSPF",
            dump=bloque_dump(z, ascii_on, highlight=z.get("ospf_n_lsa"))))
    return qs

def preguntas_ataque(pkts: List[Packet], ascii_on: bool) -> List[Question]:
    """Attack patterns found in the capture, always with the evidence shown."""
    qs = []

    # ---- ICMP flood: the rate is computed from the real timestamps ----
    reqs = [p for p in pkts if p.info.get("icmp_type") == 8]
    if len(reqs) >= 100:
        pares = Counter((p.info["src_ip"], p.info["dst_ip"]) for p in reqs)
        (src, dst), n = pares.most_common(1)[0]
        rafaga = [p for p in reqs
                  if p.info["src_ip"] == src and p.info["dst_ip"] == dst]
        dur = rafaga[-1].ts - rafaga[0].ts
        tasa = int(n / dur) if dur > 0 else n
        t0 = rafaga[0].ts
        muestra = bloque_evidencia(
            f"First packets of the burst ({n} of them in {dur:.1f} s in total)",
            [f"  {x.ts - t0:9.6f}s  {x.info['src_ip']} -> {x.info['dst_ip']}  "
             f"Echo Request  IP total length={x.info.get('ip_total_length')}"
             for x in rafaga[:8]])

        qs.append(Question(
            prompt=f"This capture holds {n} Echo Requests from {src} to {dst} "
                   f"in {dur:.1f} seconds. How many packets per second is that, "
                   "rounded?",
            kind="text", answer=tasa, answer_kind="int",
            explain=f"{n} / {dur:.2f} s = {tasa} packets per second. Look at the "
                    "gaps between timestamps above: a normal ping sends ONE per "
                    "second. Three orders of magnitude above that only comes "
                    "from a flooding tool (hping3 --flood, ping -f), and the "
                    "goal is not to diagnose anything but to burn bandwidth or "
                    "CPU.",
            difficulty="dificil", category="Attack - flood", dump=muestra))

        if dst.endswith(".255") or dst == "255.255.255.255":
            respuestas = [p for p in pkts if p.info.get("icmp_type") == 0]
            z = rafaga[0]
            qs.append(Question(
                prompt=f"These Echo Requests do not go to one host but to "
                       f"{dst}. Look at the destination MAC as well. What does "
                       "the attacker gain by aiming there?",
                kind="mcq", answer=0,
                options=["Amplification: it is a broadcast address, so each "
                         "packet can trigger a reply from EVERY host on the "
                         "network",
                         "Nothing: broadcast packets are always dropped",
                         "It encrypts the attack so it is not detected",
                         "It discovers which ports the victim has open"],
                explain=f"{dst} is the network broadcast address, and the dump "
                        "shows the destination MAC is ff:ff:ff:ff:ff:ff. One "
                        "single packet can produce as many replies as there are "
                        "hosts: that is the amplification factor. If the "
                        "attacker also SPOOFED the source address to the "
                        "victim's, all those replies would land on the victim "
                        "without it having sent anything: that is exactly the "
                        f"Smurf attack. This capture holds {len(respuestas)} "
                        "Echo Replies.",
                difficulty="dificil", category="Attack - flood",
                dump=bloque_dump(z, ascii_on, highlight=z.get("dst_mac"))))

            t = z.info.get("ip_total_length")
            if t is not None:
                qs.append(Question(
                    prompt=f"Every packet of the burst has IP total length = "
                           f"{t} bytes. How many bytes of ICMP DATA is that?",
                    kind="text", answer=max(0, t - 20 - 8), answer_kind="int",
                    explain=f"{t} - 20 (IP header) - 8 (ICMP header) = "
                            f"{max(0, t - 20 - 8)} bytes."
                            + (" Zero: these are minimum-size packets with no "
                               "payload. The attacker does not care about the "
                               "content, only the COUNT: many small packets "
                               "exhaust packets-per-second capacity, not "
                               "bandwidth." if t - 20 - 8 == 0 else
                               " A normal Linux ping carries 56 bytes of data, "
                               "which with the headers adds up to 84."),
                    difficulty="dificil", category="Attack - flood",
                    dump=bloque_dump(z, ascii_on,
                                     highlight=z.get("ip_total_length"))))

    # ---- ARP spoofing ----
    replies = [p for p in pkts if p.info.get("arp_oper") == 2]
    if replies:
        por_mac = defaultdict(set)
        for p in replies:
            por_mac[p.info["arp_sha"]].add(p.info["arp_spa"])
        culpables = {mm: ips for mm, ips in por_mac.items() if len(ips) > 1}

        muestra_arp = replies[:14]
        tabla_arp = bloque_evidencia(
            f"ARP replies in this capture (showing {len(muestra_arp)} of "
            f"{len(replies)})",
            [f"  {'#':<7}{'claims to own':>16}   is at MAC", "  " + "-" * 60] +
            [f"  #{p.num:<6}{p.info['arp_spa']:>16}   {p.info['arp_sha']}"
             for p in muestra_arp])

        if culpables:
            mac = sorted(culpables)[0]
            ips = sorted(culpables[mac])
            limpias = [mm for mm in por_mac if mm not in culpables]
            opts, idx = mcq_opciones(mac, limpias)
            qs.append(Question(
                prompt="In the table above, one MAC claims to own more than one "
                       "IP address. Which one?",
                kind="mcq", answer=idx, options=opts,
                explain=f"{mac} claims {len(ips)} different addresses: "
                        f"{', '.join(ips)}. That is the attacker: it "
                        "impersonates both victims at once so the traffic "
                        "between them flows through it. Every other MAC in the "
                        "capture claims a single address, which is what normal "
                        "looks like.",
                difficulty="dificil", category="Attack - MITM", dump=tabla_arp))

            qs.append(Question(
                prompt=f"How many different IP addresses does {mac} claim?",
                kind="text", answer=len(ips), answer_kind="int",
                explain=f"{len(ips)}: {', '.join(ips)}. On a healthy network the "
                        "IP-to-MAC relation is one to one. Wireshark flags this "
                        "as «duplicate use of <IP> detected!».",
                difficulty="medio", category="Attack - MITM", dump=tabla_arp))

        peticiones = [p for p in pkts if p.info.get("arp_oper") == 1]
        if len(replies) > 3 * max(1, len(peticiones)):
            qs.append(Question(
                prompt=f"This capture has {len(replies)} ARP replies but only "
                       f"{len(peticiones)} request(s). Why is that suspicious?",
                kind="mcq", answer=0,
                options=["Because they are replies nobody asked for (gratuitous "
                         "ARP): that is how you poison the victims' cache",
                         "Because ARP must always have more requests than "
                         "replies by design",
                         "Because it means the network is congested",
                         "Because ARP replies do not exist in IPv4"],
                explain="On a normal network each reply answers a previous "
                        f"request, so the ratio is 1:1. Here there are "
                        f"{len(replies)} replies for {len(peticiones)} "
                        "request(s): the attacker keeps repeating unsolicited "
                        "announcements so its fake entry stays in the victims' "
                        "cache and the legitimate one never overwrites it.",
                difficulty="dificil", category="Attack - MITM", dump=tabla_arp))

    # ---- inconsistent TTL: proof that somebody is relaying the traffic ----
    # NOTE: RIP, OSPF and IGMP use TTL=1 on purpose so they never leave the LAN,
    # and multicast usually carries a low TTL. Mixing them with normal traffic
    # would produce a false MITM positive, so they are excluded here.
    def es_control(p: Packet) -> bool:
        if {"RIP", "OSPF", "IGMP"} & set(p.layers):
            return True
        d = p.info.get("dst_ip", "")
        if d.endswith(".255") or d == "255.255.255.255":
            return True
        try:
            return 224 <= int(d.split(".")[0]) <= 239
        except (ValueError, IndexError):
            return False

    ttls = defaultdict(list)
    for p in pkts:
        if ("ip_ttl" in p.info and "src_ip" in p.info and "IPv4" in p.layers
                and not es_control(p)):
            ttls[p.info["src_ip"]].append(p)
    raros = {ip: v for ip, v in ttls.items()
             if len({x.info["ip_ttl"] for x in v}) > 1
             and max(x.info["ip_ttl"] for x in v)
             - min(x.info["ip_ttl"] for x in v) <= 2}
    if raros:
        ip = sorted(raros)[0]
        elegidos = raros[ip]
        vistos, ejemplos = set(), []
        for x in elegidos:
            if x.info["ip_ttl"] not in vistos:
                vistos.add(x.info["ip_ttl"])
                ejemplos.append(x)
        vals = sorted(vistos)
        tabla_ttl = bloque_evidencia(
            f"Packets sent by {ip}, with their TTL",
            [f"  #{x.num:<6} {x.info['src_ip']} -> {x.info['dst_ip']:<16} "
             f"TTL={x.info['ip_ttl']}" for x in (ejemplos + elegidos[:6])[:10]])
        qs.append(Question(
            prompt=f"{ip} shows up as the source with TTL {vals} in different "
                   "packets, even though it is a single host on the local "
                   "network. What explains that?",
            kind="mcq", answer=0,
            options=["A third machine is relaying part of its traffic, and that "
                     "extra hop subtracts 1 from the TTL",
                     "The host changes its initial TTL depending on the "
                     "application",
                     "The packets were fragmented along the way",
                     "It is a network card fault"],
            explain=f"A host always uses the same initial TTL ({max(vals)} "
                    f"here). Seeing the same source with {max(vals)} and "
                    f"{min(vals)} means some packets went straight through and "
                    "others took one extra hop. On a LAN with no routers that "
                    "hop is somebody doing IP forwarding: the attacker relaying "
                    "the intercepted traffic so the victim never notices the "
                    "cut. It confirms the Man-in-the-Middle, and it lines up "
                    "with the forged ARP replies.",
            difficulty="dificil", category="Attack - MITM", dump=tabla_ttl))
    return qs

def preguntas_sesion(pkts: List[Packet], ascii_on: bool) -> List[Question]:
    """Rebuilds plaintext conversations (FTP, HTTP) and asks about them."""
    qs = []
    lineas = []
    for p in pkts:
        if "TCP" not in p.layers or len(p.payload) < 4:
            continue
        # decode for real: safe_ascii would turn the CRLF into dots and those
        # dots would end up glued to the end of every reply
        legible = sum(1 for b in p.payload if 32 <= b <= 126 or b in (13, 10))
        if legible < len(p.payload) * 0.9:
            continue
        texto = p.payload.decode("latin-1")
        for l in texto.replace("\r\n", "\n").replace("\r", "\n").split("\n"):
            l = l.strip()
            if l:
                lineas.append((p, l))
    if not lineas:
        return qs

    def transcripcion(hasta: Optional[int] = None, titulo: str = "") -> str:
        """The conversation as it travels on the wire, in plain text."""
        sub = lineas if hasta is None else lineas[:hasta]
        filas = []
        for p, l in sub[:22]:
            quien = "client" if p.info.get("dst_port", 0) < 1024 else "server"
            filas.append(f"  #{p.num:<5} {quien:<7} {l[:56]}")
        return bloque_evidencia(
            titulo or "Plaintext conversation carried in the TCP payload", filas)

    # credentials in the clear
    usuarios = [(p, l) for p, l in lineas if l.upper().startswith("USER ")]
    if usuarios:
        p, l = usuarios[0]
        usuario = l.split(None, 1)[1] if " " in l else ""
        idx = next(i for i, (q, x) in enumerate(lineas) if x == l)
        qs.append(Question(
            prompt="A login travels in PLAIN TEXT in this capture. What "
                   "username does the client log in with?",
            kind="text", answer=usuario, answer_kind="text",
            explain=f"Packet #{p.num} carries «{l}», readable straight from the "
                    "ASCII column of the dump with nothing to decrypt. FTP, "
                    "Telnet, SMTP and HTTP send credentials as-is: anyone "
                    "capturing the traffic gets them. That is exactly why SFTP, "
                    "SSH and HTTPS exist.",
            difficulty="medio", category="Plaintext session",
            dump=transcripcion(idx + 3)))
        qs.append(Question(
            prompt=f"Packet #{p.num} carries the login. Read its hex dump: in "
                   "which OFFSET does the payload with that text start?",
            kind="text", answer=p.payload_offset, answer_kind="int",
            explain=f"At {off(p.payload_offset)}. Everything before that is "
                    "headers: 14 bytes of Ethernet, the IP header and the TCP "
                    "header. From there on it is application data, and since "
                    "FTP is plain text you can read it in the ASCII column on "
                    "the right.",
            difficulty="dificil", category="Plaintext session",
            dump=bloque_dump(p, True)))

    # data port negotiated in passive mode
    for i, (p, l) in enumerate(lineas):
        mm = re.search(r"\(\|\|\|(\d+)\|\)", l)
        if mm:
            puerto = int(mm.group(1))
            usado = any(x.info.get("src_port") == puerto
                        or x.info.get("dst_port") == puerto for x in pkts)
            qs.append(Question(
                prompt="The server answers with a 229 reply. On which port "
                       "will the DATA connection listen?",
                kind="text", answer=puerto, answer_kind="int",
                explain=f"Port {puerto}, between the vertical bars of the 229 "
                        "reply. FTP uses TWO connections: the control one (port "
                        "21), visible throughout the session, and a separate "
                        "data connection for each transfer. In passive mode it "
                        "is the server that opens a port and tells the client "
                        "over the control connection."
                        + (f" You can see real traffic on port {puerto} in this "
                           "same capture." if usado else ""),
                difficulty="dificil", category="Plaintext session",
                dump=transcripcion(i + 2)))
            break

    # announced file size
    for i, (p, l) in enumerate(lineas):
        if l.startswith("213 ") and l[4:].strip().isdigit():
            tam = int(l[4:].strip())
            previo = next((x for _, x in reversed(lineas[:i])
                           if x.upper().startswith("SIZE ")), None)
            if previo:
                qs.append(Question(
                    prompt=f"The client asks «{previo}» and the server answers "
                           "with a 213 reply. How many bytes does the file take?",
                    kind="text", answer=tam, answer_kind="int",
                    explain=f"{tam} bytes. FTP reply code 213 returns the size "
                            "asked for with SIZE. The whole protocol dialogue is "
                            "readable text: commands in upper case, replies "
                            "starting with a three-digit code (2xx fine, 3xx "
                            "something still missing, 4xx and 5xx errors).",
                    difficulty="medio", category="Plaintext session",
                    dump=transcripcion(i + 2)))
            break

    # transferred file
    for i, (p, l) in enumerate(lineas):
        if l.upper().startswith(("RETR ", "STOR ")):
            nombre = l.split(None, 1)[1]
            qs.append(Question(
                prompt="Which file is transferred in this session? (type the "
                       "name exactly as it appears)",
                kind="text", answer=nombre, answer_kind="text",
                explain=f"Packet #{p.num} carries «{l}». RETR is a download and "
                        "STOR an upload. With no encryption, whoever captures "
                        "the traffic does not just see the name: they can "
                        "rebuild the whole file from the segments of the data "
                        "connection.",
                difficulty="medio", category="Plaintext session",
                dump=transcripcion(i + 2)))
            break

    # reply codes
    codigos = [int(l[:3]) for _, l in lineas[:22]
               if len(l) > 3 and l[:3].isdigit() and l[3] in " -"]
    if len(codigos) >= 4:
        exitos = sum(1 for c in codigos if 200 <= c < 300)
        qs.append(Question(
            prompt="Counting only the lines shown above: how many server "
                   "replies belong to the 2xx family (operation completed)?",
            kind="text", answer=exitos, answer_kind="int",
            explain=f"{exitos} out of {len(codigos)} numeric replies shown. The "
                    "codes that appear are "
                    + ", ".join(str(c) for c in sorted(set(codigos)))
                    + ". The first digit is what matters: 1xx in progress, 2xx "
                      "done, 3xx one more step needed, 4xx temporary error, 5xx "
                      "permanent error. HTTP inherited this scheme from FTP.",
            difficulty="dificil", category="Plaintext session",
            dump=transcripcion()))
    return qs

def preguntas_de_captura(pkts: List[Packet], ascii_on: bool) -> List[Question]:
    """Junta el análisis del conjunto de la captura, sea cual sea su contenido."""
    qs = []
    qs.extend(preguntas_rip(pkts, ascii_on))
    qs.extend(preguntas_ospf(pkts, ascii_on))
    qs.extend(preguntas_ataque(pkts, ascii_on))
    qs.extend(preguntas_sesion(pkts, ascii_on))
    return qs


if __name__ == "__main__":
    try:
        main()
    except (KeyboardInterrupt, EOFError):
        print("\n\nHasta la próxima.")
