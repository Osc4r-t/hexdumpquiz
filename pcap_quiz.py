#!/usr/bin/env python3
"""
PCAP QUIZ - Trivia interactiva de análisis de tráfico de red
==============================================================
Carga un archivo .pcap, genera preguntas automáticamente a partir de su
contenido real (ARP, ICMP, TCP, UDP, DNS) y las combina con preguntas
teóricas de ciberseguridad (ARP spoofing, MITM, SYN flood, DNS spoofing,
etc). Pensado para practicar lectura de capturas y conceptos de seguridad
de forma activa, en la terminal.

Requisitos:
    pip install scapy --break-system-packages

Uso:
    python3 pcap_quiz.py
"""

import random
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

try:
    from scapy.all import (rdpcap, Ether, ARP, IP, TCP, UDP, ICMP, DNS,
                           BOOTP, DHCP)
except ImportError:
    print("Falta la librería scapy. Instálala con:")
    print("    pip install scapy --break-system-packages")
    sys.exit(1)


# ---------------------------------------------------------------------------
# Utilidades de presentación
# ---------------------------------------------------------------------------

RULE = "-" * 64

WELL_KNOWN_PORTS = {
    20: "FTP (datos)", 21: "FTP (control)", 22: "SSH", 23: "Telnet",
    25: "SMTP", 53: "DNS", 67: "DHCP (server)", 68: "DHCP (client)",
    80: "HTTP", 110: "POP3", 123: "NTP", 143: "IMAP", 443: "HTTPS",
    3306: "MySQL", 3389: "RDP", 8080: "HTTP alterno",
}

DIFFICULTY_LABELS = {
    "facil": "FÁCIL", "medio": "MEDIO", "dificil": "DIFÍCIL", "mixto": "MIXTO",
}

DHCP_MSG_TYPES = {
    1: "Discover", 2: "Offer", 3: "Request", 4: "Decline",
    5: "ACK", 6: "NAK", 7: "Release", 8: "Inform",
}

ICMP_TYPES = {
    0: "Echo Reply", 3: "Destination Unreachable", 5: "Redirect",
    8: "Echo Request", 11: "Time Exceeded",
}


def _norm_text(value):
    """Normaliza una respuesta de texto: sin espacios, comas ni guiones."""
    return re.sub(r"[\s,\-]", "", str(value)).lower()


def flags_human(flags):
    """Traduce las flags TCP de Scapy ('SA') a nombres legibles ('SYN, ACK')."""
    names = {"F": "FIN", "S": "SYN", "R": "RST", "P": "PSH",
             "A": "ACK", "U": "URG", "E": "ECE", "C": "CWR"}
    out = [names[c] for c in str(flags) if c in names]
    return ", ".join(out) if out else str(flags)


def banner(text):
    print("\n" + RULE)
    print(text)
    print(RULE)


def ask_choice(prompt, options):
    """Menú numerado simple. Devuelve el índice elegido (0-based)."""
    print(prompt)
    for i, opt in enumerate(options, 1):
        print(f"  {i}) {opt}")
    while True:
        raw = input("> ").strip()
        if raw.isdigit() and 1 <= int(raw) <= len(options):
            return int(raw) - 1
        print(f"Escribe un número entre 1 y {len(options)}.")


# ---------------------------------------------------------------------------
# Parseo del pcap
# ---------------------------------------------------------------------------

class PcapDataset:
    """Extrae y organiza la información de un pcap para generar preguntas."""

    def __init__(self, path):
        self.path = path
        self.packets = rdpcap(path)
        self.arp = []
        self.icmp = []
        self.tcp = []
        self.udp = []
        self.dns = []
        self.mac_to_ips = defaultdict(set)   # detección de ARP spoofing
        self.ip_ttls = defaultdict(set)      # detección de TTL inconsistente
        self.timeline = []                   # todos los paquetes, en orden
        self._parse()
        self._build_timeline()

    def _parse(self):
        for i, pkt in enumerate(self.packets, 1):
            t = float(pkt.time) if hasattr(pkt, "time") else None

            if pkt.haslayer(ARP):
                a = pkt[ARP]
                op = {1: "request", 2: "reply"}.get(a.op, str(a.op))
                self.arp.append({"i": i, "t": t, "op": op, "psrc": a.psrc,
                                  "pdst": a.pdst, "hwsrc": a.hwsrc})
                self.mac_to_ips[a.hwsrc].add(a.psrc)

            if pkt.haslayer(IP):
                ip = pkt[IP]
                self.ip_ttls[ip.src].add(ip.ttl)

                if pkt.haslayer(ICMP):
                    ic = pkt[ICMP]
                    self.icmp.append({"i": i, "t": t, "src": ip.src, "dst": ip.dst,
                                       "ttl": ip.ttl, "type": int(ic.type),
                                       "code": int(ic.code)})

                elif pkt.haslayer(TCP):
                    tc = pkt[TCP]
                    self.tcp.append({"i": i, "t": t, "src": ip.src, "dst": ip.dst,
                                      "ttl": ip.ttl, "sport": int(tc.sport),
                                      "dport": int(tc.dport), "flags": str(tc.flags),
                                      "win": int(tc.window), "seq": int(tc.seq),
                                      "ack": int(tc.ack)})

                elif pkt.haslayer(UDP):
                    u = pkt[UDP]
                    entry = {"i": i, "t": t, "src": ip.src, "dst": ip.dst,
                              "ttl": ip.ttl, "sport": int(u.sport), "dport": int(u.dport)}
                    if pkt.haslayer(DNS):
                        d = pkt[DNS]
                        qname = None
                        if d.qd:
                            try:
                                qname = d.qd.qname.decode(errors="ignore").rstrip(".")
                            except Exception:
                                qname = str(d.qd.qname)
                        answers = []
                        if d.an:
                            for j in range(d.ancount):
                                try:
                                    answers.append(str(d.an[j].rdata))
                                except Exception:
                                    pass
                        entry.update({"is_dns": True, "qname": qname,
                                      "answers": answers, "qr": int(d.qr)})
                        self.dns.append(entry)
                    self.udp.append(entry)


    # -- linea de tiempo: un registro legible por paquete, en orden de captura --

    def _dhcp_type(self, pkt):
        if not pkt.haslayer(DHCP):
            return None
        for opt in pkt[DHCP].options:
            if isinstance(opt, tuple) and opt[0] == "message-type":
                return DHCP_MSG_TYPES.get(int(opt[1]))
        return None

    def _build_timeline(self):
        t0 = None
        for i, pkt in enumerate(self.packets, 1):
            t = float(pkt.time) if hasattr(pkt, "time") else 0.0
            if t0 is None:
                t0 = t
            rec = {"num": i, "rel_t": t - t0, "proto": "OTRO", "src": "?",
                   "dst": "?", "detail": "", "sport": None, "dport": None,
                   "flags": None, "ttl": None, "icmp_type": None,
                   "win": None, "seq": None, "ack": None,
                   "qname": None, "answers": [], "qr": None, "dhcp": None,
                   "arp_op": None, "hwsrc": None}

            if pkt.haslayer(ARP):
                a = pkt[ARP]
                rec.update({"proto": "ARP", "src": a.psrc, "dst": a.pdst,
                            "arp_op": {1: "request", 2: "reply"}.get(a.op, str(a.op)),
                            "hwsrc": a.hwsrc})
                if rec["arp_op"] == "request":
                    rec["detail"] = f"¿Quién tiene {a.pdst}? Díselo a {a.psrc}"
                else:
                    rec["detail"] = f"{a.psrc} está en {a.hwsrc}"

            elif pkt.haslayer(IP):
                ip = pkt[IP]
                rec.update({"src": ip.src, "dst": ip.dst, "ttl": int(ip.ttl)})

                if pkt.haslayer(ICMP):
                    ic = pkt[ICMP]
                    rec["proto"] = "ICMP"
                    rec["icmp_type"] = int(ic.type)
                    label = ICMP_TYPES.get(int(ic.type), f"type={int(ic.type)}")
                    rec["detail"] = f"{label} (type={int(ic.type)}, code={int(ic.code)})  ttl={ip.ttl}"

                elif pkt.haslayer(TCP):
                    tc = pkt[TCP]
                    rec.update({"proto": "TCP", "sport": int(tc.sport),
                                "dport": int(tc.dport), "flags": str(tc.flags),
                                "win": int(tc.window), "seq": int(tc.seq),
                                "ack": int(tc.ack)})
                    svc = WELL_KNOWN_PORTS.get(int(tc.dport)) or WELL_KNOWN_PORTS.get(int(tc.sport))
                    svc = f"  [{svc}]" if svc else ""
                    rec["detail"] = (f"{tc.sport} -> {tc.dport}  [{flags_human(tc.flags)}]"
                                     f"  seq={tc.seq} ack={tc.ack} win={tc.window}"
                                     f"  ttl={ip.ttl}{svc}")

                elif pkt.haslayer(UDP):
                    u = pkt[UDP]
                    rec.update({"proto": "UDP", "sport": int(u.sport),
                                "dport": int(u.dport)})
                    dhcp_t = self._dhcp_type(pkt)
                    if dhcp_t:
                        rec["proto"] = "DHCP"
                        rec["dhcp"] = dhcp_t
                        rec["detail"] = f"DHCP {dhcp_t}  ({u.sport} -> {u.dport})"
                    elif pkt.haslayer(DNS):
                        d = pkt[DNS]
                        rec["proto"] = "DNS"
                        rec["qr"] = int(d.qr)
                        if d.qd:
                            try:
                                rec["qname"] = d.qd.qname.decode(errors="ignore").rstrip(".")
                            except Exception:
                                rec["qname"] = str(d.qd.qname)
                        if d.an:
                            for j in range(d.ancount):
                                try:
                                    rec["answers"].append(str(d.an[j].rdata))
                                except Exception:
                                    pass
                        if rec["qr"] == 0:
                            rec["detail"] = f"Consulta: {rec['qname']}"
                        else:
                            ans = ", ".join(rec["answers"]) or "sin respuesta"
                            rec["detail"] = f"Respuesta: {rec['qname']} -> {ans}"
                    else:
                        rec["detail"] = f"{u.sport} -> {u.dport}  ttl={ip.ttl}"

            self.timeline.append(rec)

    def summary(self):
        return {
            "Total de paquetes": len(self.packets),
            "ARP": len(self.arp),
            "ICMP": len(self.icmp),
            "TCP": len(self.tcp),
            "UDP": len(self.udp),
            "DNS": len(self.dns),
        }

    # -- detección de anomalías de seguridad, reutilizadas por las preguntas --

    def spoofed_macs(self):
        """MACs que reclaman más de una IP -> posible ARP spoofing."""
        return {mac: ips for mac, ips in self.mac_to_ips.items() if len(ips) > 1}

    def inconsistent_ttl_ips(self):
        """IPs cuyo tráfico llega con más de un TTL -> posible relay/MITM."""
        return {ip: ttls for ip, ttls in self.ip_ttls.items() if len(ttls) > 1}

    def icmp_flood_candidates(self, threshold=200):
        """Pares (src,dst) de ICMP con volumen muy alto de paquetes."""
        pairs = Counter((e["src"], e["dst"]) for e in self.icmp)
        return {p: c for p, c in pairs.items() if c >= threshold}


# ---------------------------------------------------------------------------
# Modelo de pregunta
# ---------------------------------------------------------------------------

class Question:
    def __init__(self, prompt, kind, answer, options=None, explain="",
                 difficulty="facil", category="general"):
        self.prompt = prompt
        self.kind = kind          # "mcq" o "text"
        self.answer = answer      # índice (mcq) o string/num (text)
        self.options = options or []
        self.explain = explain
        self.difficulty = difficulty
        self.category = category

    def ask(self):
        print("\n" + RULE)
        label = DIFFICULTY_LABELS.get(self.difficulty, self.difficulty.upper())
        tag = f"[{label} | {self.category}]"
        print(tag)
        print(self.prompt)
        if self.kind == "mcq":
            letters = "ABCDEFGH"
            for idx, opt in enumerate(self.options):
                print(f"  {letters[idx]}) {opt}")
            raw = input("Tu respuesta (letra): ").strip().upper()
            correct = raw and (letters.index(raw) == self.answer if raw in letters[:len(self.options)] else False)
        else:
            raw = input("Tu respuesta: ").strip()
            correct = _norm_text(raw) == _norm_text(self.answer)

        if correct:
            print(">> Correcto.")
        else:
            if self.kind == "mcq":
                letters = "ABCDEFGH"
                print(f">> Incorrecto. Respuesta correcta: {letters[self.answer]}) {self.options[self.answer]}")
            else:
                print(f">> Incorrecto. Respuesta correcta: {self.answer}")
        if self.explain:
            print(f"Nota: {self.explain}")
        return correct


# ---------------------------------------------------------------------------
# Generación de preguntas a partir de la captura
# ---------------------------------------------------------------------------

def make_distractors_ip(real_values, count=3):
    """Genera IPs falsas plausibles distintas de las reales, para armar MCQs."""
    fakes = set()
    attempts = 0
    while len(fakes) < count and attempts < 200:
        attempts += 1
        base = random.choice(list(real_values)) if real_values else "10.0.0.1"
        parts = base.split(".")
        try:
            parts[-1] = str((int(parts[-1]) + random.randint(1, 40)) % 255)
        except ValueError:
            continue
        candidate = ".".join(parts)
        if candidate not in real_values:
            fakes.add(candidate)
    return list(fakes)[:count]


def build_dataset_questions(ds: PcapDataset):
    qs = []
    summ = ds.summary()

    # ---------- FACIL: estadísticas básicas de lectura del pcap ----------
    qs.append(Question(
        "¿Cuántos paquetes contiene esta captura en total?",
        "text", summ["Total de paquetes"],
        explain="El conteo total es el primer dato que conviene mirar al abrir "
                "cualquier pcap: te da una idea del tamaño de la captura y de "
                "cuánto tiempo/tráfico representa.",
        difficulty="facil", category="lectura",
    ))

    present_protos = [p for p in ["ARP", "ICMP", "TCP", "UDP", "DNS"] if summ[p] > 0]
    if present_protos:
        most_common = max(present_protos, key=lambda p: summ[p])
        distractors = [p for p in present_protos if p != most_common]
        distractors += [p for p in ["ARP", "ICMP", "TCP", "UDP", "DNS"] if p not in present_protos]
        options = [most_common] + distractors[:3]
        random.shuffle(options)
        qs.append(Question(
            "¿Cuál es el protocolo con más paquetes en esta captura?",
            "mcq", options.index(most_common), options,
            explain="Ver qué protocolo domina el tráfico ayuda a formarte una "
                     "hipótesis rápida: mucho ARP sugiere descubrimiento/spoofing "
                     "de red local; mucho ICMP puede ser diagnóstico o un flood; "
                     "mucho DNS puede indicar resolución masiva o tunneling.",
            difficulty="facil", category="lectura",
        ))

    for proto in present_protos:
        qs.append(Question(
            f"¿Cuántos paquetes {proto} hay en la captura?",
            "text", summ[proto],
            explain=f"Contar paquetes por protocolo ({proto}) es básico en Wireshark "
                     "con un filtro de display; en Python/Scapy se logra igual con "
                     "pkt.haslayer(...).",
            difficulty="facil", category="lectura",
        ))

    # ---------- ARP ----------
    if ds.arp:
        src_ips = sorted({e["psrc"] for e in ds.arp})
        if len(src_ips) >= 1:
            target_ip = random.choice(src_ips)
            distractors = make_distractors_ip(set(src_ips), 3)
            options = [target_ip] + distractors
            random.shuffle(options)
            qs.append(Question(
                "¿Cuál de estas IPs aparece anunciándose por ARP en la captura?",
                "mcq", options.index(target_ip), options,
                explain="En ARP, 'is at' significa que un host está declarando "
                         "qué MAC corresponde a su IP. Si dos MACs distintas "
                         "declaran la misma IP (o una MAC declara varias IPs), "
                         "es indicio de ARP spoofing.",
                difficulty="facil", category="ARP",
            ))

        replies = sum(1 for e in ds.arp if e["op"] == "reply")
        requests = sum(1 for e in ds.arp if e["op"] == "request")
        qs.append(Question(
            "¿Cuántos paquetes ARP son de tipo 'reply' (respuesta), y no 'request'?",
            "text", replies,
            explain="Un volumen de 'replies' no solicitados (gratuitous ARP) es "
                     "típico de herramientas de ARP spoofing como arpspoof/ettercap: "
                     "el atacante envía respuestas sin que nadie haya preguntado.",
            difficulty="medio", category="ARP",
        ))

        # Detección de spoofing real
        spoofed = ds.spoofed_macs()
        if spoofed:
            mac = random.choice(list(spoofed.keys()))
            n_ips = len(spoofed[mac])
            qs.append(Question(
                f"La dirección MAC {mac} aparece reclamando {n_ips} IPs distintas "
                "en los paquetes ARP. ¿Qué técnica de ataque describe mejor esto?",
                "mcq", 0,
                ["ARP Spoofing / envenenamiento de la caché ARP",
                 "Escaneo de puertos (port scanning)",
                 "Amplificación DNS",
                 "Ataque de fuerza bruta"],
                explain="Es la firma clásica de ARP spoofing: un atacante envía "
                         "respuestas ARP falsas para que dos (o más) hosts asocien "
                         "erróneamente una IP ajena con la MAC del atacante, "
                         "quedando el tráfico entre ellos redirigido hacia el "
                         "(Man-in-the-Middle). Wireshark suele marcarlo como "
                         "'duplicate use of <IP> detected!'.",
                difficulty="dificil", category="Seguridad - MITM",
            ))
        else:
            qs.append(Question(
                "En esta captura, ¿alguna dirección MAC reclama más de una IP "
                "distinta en los paquetes ARP? (indicio de ARP spoofing)",
                "mcq", 1,
                ["Sí, hay al menos una MAC con varias IPs", "No, cada MAC "
                 "está asociada a una sola IP"],
                explain="Revisar cuantas IPs distintas anuncia cada MAC en ARP es "
                         "una forma sencilla de detectar spoofing: en una red sana, "
                         "cada MAC debería corresponder a una sola IP.",
                difficulty="medio", category="Seguridad - MITM",
            ))

    # ---------- ICMP ----------
    if ds.icmp:
        pkt = random.choice(ds.icmp)
        options_types = list(ICMP_TYPES.items())
        random.shuffle(options_types)
        correct_label = ICMP_TYPES.get(pkt["type"], f"Tipo {pkt['type']}")
        opts = [correct_label]
        for code, label in options_types:
            if label != correct_label and len(opts) < 4:
                opts.append(label)
        random.shuffle(opts)
        qs.append(Question(
            f"El paquete ICMP #{pkt['i']} (de {pkt['src']} a {pkt['dst']}) "
            f"tiene type={pkt['type']}. ¿Qué representa ese tipo de mensaje ICMP?",
            "mcq", opts.index(correct_label), opts,
            explain="El campo 'type' de ICMP define el propósito del mensaje: "
                     "8 = Echo Request (ping), 0 = Echo Reply, 3 = Destino "
                     "inalcanzable, 5 = Redirect, 11 = Tiempo excedido (TTL "
                     "agotado). Los ICMP Redirect (5) también pueden falsificarse "
                     "para reforzar un ataque de tipo MITM.",
            difficulty="medio", category="ICMP",
        ))

        ttl_pkt = random.choice(ds.icmp)
        qs.append(Question(
            f"¿Cuál es el TTL del paquete ICMP #{ttl_pkt['i']} ({ttl_pkt['src']} "
            f"-> {ttl_pkt['dst']})?",
            "text", ttl_pkt["ttl"],
            explain="El TTL (Time To Live) se decrementa en 1 cada vez que un "
                     "paquete atraviesa un router/host haciendo forwarding. Ver "
                     "el mismo flujo lógico con dos TTLs distintos (ej. 64 y 63) "
                     "es una señal de que el paquete fue reenviado por un tercero "
                     "en el camino -- útil para detectar un MITM.",
            difficulty="facil", category="ICMP",
        ))

        # detección de flood
        flood_pairs = ds.icmp_flood_candidates(threshold=100)
        if flood_pairs:
            (src, dst), count = random.choice(list(flood_pairs.items()))
            qs.append(Question(
                f"Entre {src} y {dst} hay {count} paquetes ICMP en esta captura. "
                "¿Qué tipo de actividad sugiere ese volumen tan alto en una "
                "misma dirección?",
                "mcq", 0,
                ["Un posible ataque de flooding / denegación de servicio (DoS)",
                 "Una simple resolución de nombres DNS",
                 "El establecimiento normal de una conexión TCP",
                 "Tráfico cifrado HTTPS"],
                explain="Un número muy alto de paquetes ICMP en poco tiempo "
                         "(especialmente 'echo request' en modo flood, como con "
                         "hping3 --flood) es típico de un DoS por saturación de "
                         "ancho de banda o de CPU, no de tráfico normal de "
                         "diagnóstico de red.",
                difficulty="dificil", category="Seguridad - DoS",
            ))

        # TTL inconsistente / relay
        incons = ds.inconsistent_ttl_ips()
        if incons:
            ip = random.choice(list(incons.keys()))
            ttls = sorted(incons[ip])
            qs.append(Question(
                f"La IP {ip} aparece como origen de paquetes con TTLs distintos: "
                f"{ttls}. En el contexto de una red local pequeña donde todos los "
                "hosts deberían usar el mismo TTL inicial, ¿qué explica esto mejor?",
                "mcq", 0,
                ["Un tercer host está reenviando (forwarding) el tráfico, "
                 "decrementando el TTL -- posible Man-in-the-Middle",
                 "Es un comportamiento normal sin ninguna implicación",
                 "El paquete fue fragmentado por el firewall",
                 "Es un error de checksum en la NIC"],
                explain="Si el mismo host origina paquetes que a veces llegan con "
                         "TTL=64 y otras con TTL=63, lo más probable es que unos "
                         "vayan directo y otros pasen por un salto extra (un host "
                         "haciendo IP forwarding), como ocurre cuando un atacante "
                         "hace ARP spoofing y reenvía el tráfico interceptado para "
                         "no cortar la conexión.",
                difficulty="dificil", category="Seguridad - MITM",
            ))

    # ---------- TCP ----------
    if ds.tcp:
        pkt = random.choice(ds.tcp)
        service = WELL_KNOWN_PORTS.get(pkt["dport"])
        if service:
            wrong_services = [s for p, s in WELL_KNOWN_PORTS.items() if s != service]
            random.shuffle(wrong_services)
            opts = [service] + wrong_services[:3]
            random.shuffle(opts)
            qs.append(Question(
                f"El paquete TCP #{pkt['i']} va dirigido al puerto {pkt['dport']} "
                f"({pkt['src']} -> {pkt['dst']}). ¿Qué servicio suele usar ese puerto?",
                "mcq", opts.index(service), opts,
                explain="Reconocer puertos bien conocidos (80=HTTP, 443=HTTPS, "
                         "22=SSH, 53=DNS, etc.) ayuda a entender rápido para qué "
                         "sirve un flujo TCP sin tener que inspeccionar el payload.",
                difficulty="facil", category="TCP",
            ))
        else:
            qs.append(Question(
                f"¿A qué puerto de destino va dirigido el paquete TCP #{pkt['i']}?",
                "text", pkt["dport"],
                explain="El puerto de destino identifica el servicio al que se "
                         "intenta conectar; puertos altos y no estándar suelen "
                         "corresponder a aplicaciones específicas o conexiones "
                         "efímeras (cliente).",
                difficulty="facil", category="TCP",
            ))

        flag_pkt = random.choice(ds.tcp)
        flag_meanings = {
            "S": "SYN: intento de abrir una conexión (primer paso del handshake)",
            "SA": "SYN-ACK: el servidor acepta y responde al intento de conexión",
            "A": "ACK: confirmación de recepción de datos/segmento",
            "F": "FIN: solicitud de cierre ordenado de la conexión",
            "R": "RST: la conexión se corta abruptamente",
            "PA": "PSH-ACK: envío de datos con confirmación",
        }
        label = flag_meanings.get(flag_pkt["flags"])
        if label:
            other_labels = [v for k, v in flag_meanings.items() if v != label]
            random.shuffle(other_labels)
            opts = [label] + other_labels[:3]
            random.shuffle(opts)
            qs.append(Question(
                f"El paquete TCP #{flag_pkt['i']} tiene las flags '{flag_pkt['flags']}'. "
                "¿Qué significan en el protocolo TCP?",
                "mcq", opts.index(label), opts,
                explain="Las flags de TCP controlan el ciclo de vida de la "
                         "conexión (three-way handshake: SYN, SYN-ACK, ACK). Un "
                         "volumen masivo de paquetes SYN sin sus ACK correspondientes "
                         "es la firma clásica de un SYN flood (DoS contra el "
                         "servidor, que agota recursos esperando conexiones a "
                         "medio abrir).",
                difficulty="medio", category="TCP",
            ))

        syn_count = sum(1 for e in ds.tcp if e["flags"] == "S")
        synack_count = sum(1 for e in ds.tcp if e["flags"] == "SA")
        if syn_count > 20 and synack_count < syn_count * 0.5:
            qs.append(Question(
                f"Hay {syn_count} paquetes SYN pero solo {synack_count} SYN-ACK "
                "en esta captura. ¿Qué patrón de ataque describe mejor esta "
                "desproporción?",
                "mcq", 0,
                ["SYN flood: muchas conexiones a medio abrir para agotar "
                 "recursos del servidor",
                 "Un escaneo de vulnerabilidades autorizado sin impacto",
                 "Una transferencia de archivos por FTP",
                 "Una resolución DNS recursiva"],
                explain="En un handshake TCP normal cada SYN debería tener su "
                         "SYN-ACK y su ACK final. Cuando hay muchos SYN sin "
                         "completar el handshake, el servidor mantiene conexiones "
                         "'semiabiertas' que consumen memoria/tabla de conexiones: "
                         "es la base del ataque SYN flood.",
                difficulty="dificil", category="Seguridad - DoS",
            ))

    # ---------- DNS ----------
    if ds.dns:
        queries = [e for e in ds.dns if e.get("qr") == 0 and e.get("qname")]
        if queries:
            q = random.choice(queries)
            fake_domains = ["ejemplo-falso.net", "prueba123.org", "otrositio.io"]
            opts = [q["qname"]] + [d for d in fake_domains if d != q["qname"]][:3]
            random.shuffle(opts)
            qs.append(Question(
                f"El paquete DNS #{q['i']} es una consulta ({q['src']} -> {q['dst']}). "
                "¿Qué dominio se está consultando?",
                "mcq", opts.index(q["qname"]), opts,
                explain="Las consultas DNS revelan qué dominios intenta resolver "
                         "un host; en una investigación de seguridad, dominios "
                         "raros, generados algoritmicamente (DGA) o con muchas "
                         "subconsultas pueden indicar malware o exfiltración vía "
                         "DNS tunneling.",
                difficulty="medio", category="DNS",
            ))

        answered = [e for e in ds.dns if e.get("qr") == 1 and e.get("answers")]
        if answered:
            r = random.choice(answered)
            real_ip = r["answers"][0]
            distractors = make_distractors_ip({real_ip}, 3)
            opts = [real_ip] + distractors
            random.shuffle(opts)
            qs.append(Question(
                f"La respuesta DNS #{r['i']} para '{r.get('qname')}' resuelve a "
                "¿cuál dirección IP?",
                "mcq", opts.index(real_ip), opts,
                explain="Comparar la IP que 'debería' devolver un dominio contra "
                         "la que realmente aparece en la respuesta DNS es la base "
                         "para detectar DNS spoofing/caché poisoning, donde un "
                         "atacante hace que un dominio legítimo resuelva a una IP "
                         "maliciosa.",
                difficulty="dificil", category="Seguridad - DNS",
            ))

    return qs



# ---------------------------------------------------------------------------
# Preguntas de SECUENCIA: leer 3-6 paquetes en conjunto e interpretar que pasa
# ---------------------------------------------------------------------------

def render_sequence(records, title="Secuencia de paquetes (# = número real en la captura)"):
    """Dibuja un bloque tipo Wireshark con los paquetes de la secuencia."""
    lines = ["", RULE, title, RULE]
    for r in records:
        lines.append(
            f"  #{r['num']:<5} {r['rel_t']:9.4f}s  {r['src']:>15} -> "
            f"{r['dst']:<15} {r['proto']:<5} {r['detail']}"
        )
    lines.append(RULE)
    return "\n".join(lines)


def seq_question(records, prompt, correct_text, wrong_texts, explain,
                 difficulty="medio", category="Secuencia"):
    """Arma una pregunta de opción múltiple sobre una secuencia de paquetes."""
    opts = [correct_text] + list(wrong_texts)[:3]
    random.shuffle(opts)
    full = render_sequence(records) + "\n" + prompt
    return Question(full, "mcq", opts.index(correct_text), opts,
                    explain=explain, difficulty=difficulty, category=category)


def order_question(records, what, explain, difficulty="medio"):
    """Muestra la secuencia desordenada y pide reconstruir el orden correcto."""
    letters = "ABCDEF"
    shuffled = list(records)
    for _ in range(12):
        random.shuffle(shuffled)
        if shuffled != list(records):
            break
    lines = ["", RULE, f"Paquetes DESORDENADOS de {what}", RULE]
    for k, r in enumerate(shuffled):
        lines.append(f"  {letters[k]})  {r['src']:>15} -> {r['dst']:<15} "
                     f"{r['proto']:<5} {r['detail']}")
    lines.append(RULE)
    answer = "".join(letters[shuffled.index(r)] for r in records)
    used = letters[:len(records)]
    ejemplo = used[1:] + used[0]          # nunca coincide con el orden mostrado
    prompt = ("\n".join(lines) + "\n¿En qué orden ocurren realmente estos "
              f"paquetes? Escribe las letras seguidas, sin espacios "
              f"(ejemplo: {ejemplo}).")
    return Question(prompt, "text", answer, explain=explain,
                    difficulty=difficulty, category="Secuencia - orden")


# ---- detectores de patrones sobre la linea de tiempo -----------------------

def _same_flow(a, b, reverse=False):
    if reverse:
        return (a["src"] == b["dst"] and a["dst"] == b["src"]
                and a["sport"] == b["dport"] and a["dport"] == b["sport"])
    return (a["src"] == b["src"] and a["dst"] == b["dst"]
            and a["sport"] == b["sport"] and a["dport"] == b["dport"])


def find_handshake(tl):
    """SYN -> SYN,ACK -> ACK del mismo flujo TCP."""
    tcp = [r for r in tl if r["proto"] == "TCP"]
    for idx, syn in enumerate(tcp):
        if syn["flags"] != "S":
            continue
        synack = None
        for r in tcp[idx + 1:idx + 40]:
            if synack is None and r["flags"] == "SA" and _same_flow(syn, r, True):
                synack = r
            elif synack is not None and r["flags"] == "A" and _same_flow(syn, r):
                return [syn, synack, r]
    return None


def find_teardown(tl):
    """Cierre de conexión: FIN,ACK -> ACK -> FIN,ACK -> ACK."""
    tcp = [r for r in tl if r["proto"] == "TCP"]
    for idx, fin in enumerate(tcp):
        if fin["flags"] not in ("FA", "F"):
            continue
        seq = [fin]
        for r in tcp[idx + 1:idx + 30]:
            if not (_same_flow(fin, r) or _same_flow(fin, r, True)):
                continue
            seq.append(r)
            if len(seq) == 4:
                return seq
    return None


def find_refused(tl):
    """SYN respondido con RST: puerto cerrado / conexión rechazada."""
    tcp = [r for r in tl if r["proto"] == "TCP"]
    for idx, syn in enumerate(tcp):
        if syn["flags"] != "S":
            continue
        for r in tcp[idx + 1:idx + 15]:
            if r["flags"] in ("RA", "R") and _same_flow(syn, r, True):
                seq = [syn, r]
                extra = [x for x in tcp[idx + 1:idx + 15]
                         if x not in seq and x["flags"] == "S"][:2]
                return sorted(seq + extra, key=lambda x: x["num"])
    return None


def find_port_scan(tl):
    """Un mismo origen manda SYN a muchos puertos distintos del mismo destino."""
    syns = [r for r in tl if r["proto"] == "TCP" and r["flags"] == "S"]
    groups = defaultdict(list)
    for r in syns:
        groups[(r["src"], r["dst"])].append(r)
    for (src, dst), items in groups.items():
        ports = {r["dport"] for r in items}
        if len(ports) >= 4:
            seen, out = set(), []
            for r in items:
                if r["dport"] not in seen:
                    seen.add(r["dport"])
                    out.append(r)
                if len(out) == 5:
                    break
            return out
    return None


def find_syn_flood(tl):
    """Muchos SYN al mismo destino/puerto y casi ningun SYN,ACK de vuelta."""
    syns = [r for r in tl if r["proto"] == "TCP" and r["flags"] == "S"]
    synacks = [r for r in tl if r["proto"] == "TCP" and r["flags"] == "SA"]
    groups = defaultdict(list)
    for r in syns:
        groups[(r["dst"], r["dport"])].append(r)
    for (dst, dport), items in groups.items():
        if len(items) >= 15 and len(synacks) < len(items) * 0.5:
            return items[:6]
    return None


def find_ping(tl):
    """Echo Request seguido de su Echo Reply (dos rondas si las hay)."""
    icmp = [r for r in tl if r["proto"] == "ICMP"]
    seq = []
    for idx, req in enumerate(icmp):
        if req["icmp_type"] != 8:
            continue
        for rep in icmp[idx + 1:idx + 10]:
            if (rep["icmp_type"] == 0 and rep["src"] == req["dst"]
                    and rep["dst"] == req["src"]):
                seq.extend([req, rep])
                break
        if len(seq) >= 4:
            return seq[:4]
    return seq if len(seq) >= 2 else None


def find_icmp_flood(tl):
    """Ráfaga de Echo Request sin respuesta entre el mismo par de hosts."""
    reqs = defaultdict(list)
    for r in tl:
        if r["proto"] == "ICMP" and r["icmp_type"] == 8:
            reqs[(r["src"], r["dst"])].append(r)
    for pair, items in reqs.items():
        if len(items) >= 20:
            replies = [r for r in tl if r["proto"] == "ICMP" and r["icmp_type"] == 0
                       and r["src"] == pair[1] and r["dst"] == pair[0]]
            if len(replies) < len(items) * 0.3:
                return items[:6]
    return None


def find_arp_resolution(tl):
    """ARP request + su reply, y el primer paquete IP que va después."""
    for idx, req in enumerate(tl):
        if req["proto"] != "ARP" or req["arp_op"] != "request":
            continue
        for rep in tl[idx + 1:idx + 12]:
            if rep["proto"] == "ARP" and rep["arp_op"] == "reply" and rep["src"] == req["dst"]:
                seq = [req, rep]
                for nxt in tl[tl.index(rep) + 1:tl.index(rep) + 6]:
                    if nxt["proto"] != "ARP":
                        seq.append(nxt)
                        break
                return seq
    return None


def find_arp_spoof(tl):
    """Varias replies ARP donde una MAC reclama IPs distintas (o al revés)."""
    replies = [r for r in tl if r["proto"] == "ARP" and r["arp_op"] == "reply"]
    by_mac = defaultdict(set)
    by_ip = defaultdict(set)
    for r in replies:
        by_mac[r["hwsrc"]].add(r["src"])
        by_ip[r["src"]].add(r["hwsrc"])
    bad_macs = {m for m, ips in by_mac.items() if len(ips) > 1}
    bad_ips = {ip for ip, macs in by_ip.items() if len(macs) > 1}
    if not bad_macs and not bad_ips:
        return None
    seq = [r for r in replies if r["hwsrc"] in bad_macs or r["src"] in bad_ips]
    return seq[:5] if len(seq) >= 2 else None


def find_dns_then_connect(tl):
    """Consulta DNS -> respuesta -> conexión TCP a la IP resuelta."""
    for idx, q in enumerate(tl):
        if q["proto"] != "DNS" or q["qr"] != 0:
            continue
        for resp in tl[idx + 1:idx + 20]:
            if resp["proto"] == "DNS" and resp["qr"] == 1 and resp["qname"] == q["qname"]:
                seq = [q, resp]
                for nxt in tl[tl.index(resp) + 1:tl.index(resp) + 15]:
                    if nxt["proto"] == "TCP" and nxt["dst"] in resp["answers"]:
                        seq.append(nxt)
                        break
                return seq
    return None


def find_dhcp_dora(tl):
    """Discover -> Offer -> Request -> ACK."""
    wanted = ["Discover", "Offer", "Request", "ACK"]
    seq, pos = [], 0
    for r in tl:
        if r["proto"] == "DHCP" and r["dhcp"] == wanted[pos]:
            seq.append(r)
            pos += 1
            if pos == len(wanted):
                return seq
    return seq if len(seq) >= 3 else None


def find_unreachable(tl):
    """Un paquete de ida y el ICMP Destination Unreachable que lo rebota."""
    for idx, r in enumerate(tl):
        if r["proto"] == "ICMP" and r["icmp_type"] == 3:
            start = max(0, idx - 3)
            return tl[start:idx + 1]
    return None


# ---- construcción de las preguntas de secuencia ---------------------------

def build_sequence_questions(ds: PcapDataset):
    """Preguntas que muestran 3-6 paquetes juntos para interpretar qué ocurre."""
    tl = ds.timeline
    qs = []

    hs = find_handshake(tl)
    if hs:
        qs.append(seq_question(
            hs,
            "Estos tres paquetes pertenecen al mismo flujo TCP. ¿Qué está "
            "ocurriendo en esta secuencia?",
            "El establecimiento de una conexión TCP (three-way handshake)",
            ["El cierre ordenado de una conexión TCP ya establecida",
             "Un escaneo de puertos que fue rechazado por el servidor",
             "Una retransmisión por pérdida de paquetes"],
            explain=f"Lee las flags en orden: #{hs[0]['num']} [SYN] es el cliente "
                    f"pidiendo abrir la conexión, #{hs[1]['num']} [SYN, ACK] es el "
                    f"servidor aceptando y pidiendo lo mismo en sentido contrario, "
                    f"y #{hs[2]['num']} [ACK] es el cliente confirmando. Recién "
                    "después de ese tercer paquete la conexión está establecida y "
                    "pueden viajar datos. Fíjate también en que el sentido "
                    "origen/destino se invierte en el segundo paquete.",
            difficulty="facil", category="Secuencia - TCP",
        ))
        qs.append(order_question(
            hs, "un three-way handshake de TCP",
            explain="El orden siempre es SYN (cliente) -> SYN,ACK (servidor) -> "
                    "ACK (cliente). Puedes reconstruirlo sin ver los tiempos: solo "
                    "el SYN va solo, el SYN,ACK viaja en sentido contrario y el ACK "
                    "cierra el ciclo en el sentido original.",
            difficulty="medio",
        ))

    td = find_teardown(tl)
    if td:
        qs.append(seq_question(
            td,
            "¿Qué representa esta secuencia de paquetes TCP?",
            "El cierre de la conexión TCP: cada extremo manda su FIN y el otro lo confirma",
            ["La apertura de una conexión TCP nueva",
             "Un ataque SYN flood contra el servidor",
             "Una negociación de cifrado TLS"],
            explain="El cierre ordenado de TCP es bidireccional: cada lado cierra "
                    "su mitad de la conexión con un FIN y espera el ACK del otro. "
                    "Por eso ves el patrón FIN,ACK / ACK repetido en los dos "
                    "sentidos. Un RST, en cambio, corta de golpe sin este baile.",
            difficulty="medio", category="Secuencia - TCP",
        ))

    ref = find_refused(tl)
    if ref:
        qs.append(seq_question(
            ref,
            "El primer paquete es un SYN y la respuesta es un RST. ¿Qué está "
            "pasando con ese puerto del destino?",
            "El puerto está cerrado: nadie escucha ahí y el host rechaza la conexión",
            ["El puerto está abierto y la conexión se estableció correctamente",
             "El paquete se perdió y será retransmitido",
             "El servidor está pidiendo autenticación antes de responder"],
            explain="Cuando llega un SYN a un puerto donde ningún proceso escucha, "
                    "el sistema responde RST (reset) en vez de SYN,ACK. Esta pareja "
                    "SYN -> RST es exactamente lo que un escáner como nmap usa para "
                    "marcar un puerto como 'closed'; si en cambio recibiera SYN,ACK "
                    "lo marcaría como 'open', y si no recibiera nada, como 'filtered'.",
            difficulty="medio", category="Secuencia - TCP",
        ))

    scan = find_port_scan(tl)
    if scan:
        ports = ", ".join(str(r["dport"]) for r in scan)
        qs.append(seq_question(
            scan,
            f"Todos estos SYN salen de {scan[0]['src']} hacia {scan[0]['dst']}, "
            f"pero a puertos distintos ({ports}). ¿Qué actividad describe mejor "
            "la secuencia?",
            "Un escaneo de puertos: se prueba puerto por puerto para ver cuáles están abiertos",
            ["Una única descarga de un archivo grande por HTTP",
             "Un handshake TCP normal repetido con el mismo servicio",
             "Una consulta DNS recursiva"],
            explain="La firma de un port scan es un mismo origen mandando SYN a "
                    "muchos puertos distintos del mismo destino, casi al mismo "
                    "tiempo y sin llegar a completar los handshakes. El atacante "
                    "solo quiere saber qué responde cada puerto (SYN,ACK = abierto, "
                    "RST = cerrado, silencio = filtrado por firewall).",
            difficulty="dificil", category="Secuencia - Seguridad",
        ))

    flood = find_syn_flood(tl)
    if flood:
        qs.append(seq_question(
            flood,
            f"Estos SYN llegan al puerto {flood[0]['dport']} de {flood[0]['dst']} "
            "y casi ninguno recibe SYN,ACK de vuelta ni llega a completarse. "
            "¿Qué está ocurriendo?",
            "Un SYN flood: se abren muchas conexiones a medias para agotar los recursos del servidor",
            ["Un cierre ordenado de varias conexiones",
             "Tráfico HTTPS normal de varios clientes",
             "Un ping masivo entre dos hosts"],
            explain="En el SYN flood el atacante nunca manda el tercer paquete "
                    "(ACK) del handshake. El servidor deja cada conexión en estado "
                    "SYN_RECV ocupando memoria en su tabla de conexiones, hasta "
                    "quedarse sin espacio para clientes legítimos. Además suele "
                    "falsificar la IP de origen, por eso bloquear una sola IP no "
                    "sirve; se mitiga con SYN cookies o rate limiting.",
            difficulty="dificil", category="Secuencia - Seguridad",
        ))

    ping = find_ping(tl)
    if ping:
        qs.append(seq_question(
            ping,
            "¿Qué está ocurriendo entre estos dos hosts?",
            "Un ping: cada Echo Request recibe su Echo Reply, así que el destino responde",
            ["El destino está caído y no contesta ninguna solicitud",
             "Se está estableciendo una conexión TCP",
             "Se está resolviendo un nombre de dominio"],
            explain="El par Echo Request (type=8) seguido de Echo Reply (type=0) "
                    "con los hosts invertidos es la ida y vuelta de un ping. Que "
                    "haya reply significa que el destino está vivo y accesible. "
                    "Si vieras solo Echo Request repetidos sin reply, el destino "
                    "estaría caído, filtrado por firewall, o estarías ante un flood.",
            difficulty="facil", category="Secuencia - ICMP",
        ))

    iflood = find_icmp_flood(tl)
    if iflood:
        qs.append(seq_question(
            iflood,
            f"Esta ráfaga de Echo Request de {iflood[0]['src']} a "
            f"{iflood[0]['dst']} se repite cientos de veces en muy poco tiempo y "
            "apenas hay respuestas. ¿Qué describe mejor la secuencia?",
            "Un ICMP flood: un DoS que busca saturar al destino con solicitudes",
            ["Un diagnóstico de red normal con la herramienta ping",
             "Un traceroute descubriendo la ruta hacia el destino",
             "Una transferencia de archivos por ICMP"],
            explain="Un ping de diagnóstico manda un paquete por segundo. Cientos "
                    "o miles de Echo Request en fracciones de segundo (típico de "
                    "'hping3 --flood' o 'ping -f') buscan consumir ancho de banda o "
                    "CPU del destino. Mira los tiempos relativos entre paquetes: "
                    "ahí es donde se nota la diferencia entre un ping y un flood.",
            difficulty="dificil", category="Secuencia - Seguridad",
        ))

    arp = find_arp_resolution(tl)
    if arp:
        qs.append(seq_question(
            arp,
            "¿Qué está ocurriendo en esta secuencia?",
            "Una resolución ARP normal: se pregunta por la MAC de una IP y su dueño responde",
            ["Un envenenamiento de la caché ARP (ARP spoofing)",
             "Una consulta DNS para traducir un nombre a una IP",
             "Un intento de conexión TCP a un puerto cerrado"],
            explain="ARP traduce una IP (capa 3) a una MAC (capa 2). El primer "
                    "paquete es un broadcast preguntando '¿quién tiene esta IP?' y "
                    "el segundo es la respuesta del dueño diciendo 'está en esta "
                    "MAC'. Recién con esa MAC en mano el host puede enviar el "
                    "tráfico IP que ves después. Lo sospechoso sería ver respuestas "
                    "sin que nadie haya preguntado.",
            difficulty="facil", category="Secuencia - ARP",
        ))

    spoof = find_arp_spoof(tl)
    if spoof:
        qs.append(seq_question(
            spoof,
            "Mira quién dice ser cada IP en estas respuestas ARP. ¿Qué está "
            "ocurriendo?",
            "ARP spoofing: se anuncian asociaciones IP-MAC falsas para interceptar el tráfico",
            ["Una resolución ARP normal entre dos hosts de la red",
             "Un servidor DHCP repartiendo direcciones a los clientes",
             "Un router anunciando una ruta nueva por RIP"],
            explain="En una red sana cada IP corresponde a una sola MAC. Aquí hay "
                    "respuestas contradictorias (una MAC reclamando varias IPs, o "
                    "una IP reclamada por varias MACs), que es justo lo que hace "
                    "arpspoof/ettercap para que las víctimas manden su tráfico al "
                    "atacante. Wireshark lo suele marcar como 'duplicate use of "
                    "<IP> detected!'. El atacante luego reenvía el tráfico para que "
                    "nadie note el corte: eso es el Man-in-the-Middle.",
            difficulty="dificil", category="Secuencia - Seguridad",
        ))

    dns = find_dns_then_connect(tl)
    if dns and len(dns) >= 2:
        if len(dns) >= 3:
            correct = ("Primero se resuelve el nombre por DNS y después se abre "
                       "la conexión TCP hacia la IP que devolvió esa respuesta")
            wrongs = ["Se abre la conexión TCP y después se consulta el DNS",
                      "Son dos conversaciones sin ninguna relación entre sí",
                      "El servidor DNS rechazó la consulta y no hubo conexión"]
            expl = (f"El orden importa: #{dns[0]['num']} pregunta por "
                    f"'{dns[0]['qname']}', #{dns[1]['num']} responde con "
                    f"{', '.join(dns[1]['answers']) or 'una IP'}, y solo entonces "
                    f"#{dns[2]['num']} abre la conexión TCP hacia esa misma IP. "
                    "Ese encadenamiento (nombre -> IP -> conexión) es lo que un "
                    "atacante rompe con DNS spoofing: si falsifica la respuesta, "
                    "el tercer paquete se va a un servidor suyo.")
        else:
            correct = "Una resolución DNS: se consulta un nombre y el servidor devuelve su IP"
            wrongs = ["Una transferencia de zona DNS entre dos servidores",
                      "Un ataque de amplificación DNS en curso",
                      "Un handshake TCP hacia el puerto 53"]
            expl = ("La consulta (qr=0) y la respuesta (qr=1) llevan el mismo "
                    "nombre de dominio y viajan en sentidos opuestos. Comparar la "
                    "IP devuelta con la que esperas es la forma básica de detectar "
                    "DNS spoofing.")
        qs.append(seq_question(
            dns, "¿Qué está ocurriendo en esta secuencia y en qué orden?",
            correct, wrongs, explain=expl,
            difficulty="medio", category="Secuencia - DNS",
        ))

    dora = find_dhcp_dora(tl)
    if dora:
        qs.append(seq_question(
            dora,
            "¿Qué proceso están completando estos paquetes?",
            "La asignación de una dirección IP por DHCP (Discover, Offer, Request, ACK)",
            ["Una resolución de nombres contra un servidor DNS",
             "Un handshake TCP de tres pasos",
             "Un envenenamiento de la caché ARP"],
            explain="Es el ciclo DORA de DHCP: el cliente, que todavía no tiene IP, "
                    "manda un Discover por broadcast (0.0.0.0 -> 255.255.255.255); "
                    "el servidor le hace una Offer con una IP disponible; el cliente "
                    "la pide formalmente con Request; y el servidor confirma con ACK. "
                    "Un atacante con un servidor DHCP falso puede responder primero "
                    "y quedarse como gateway de la víctima (DHCP spoofing).",
            difficulty="medio", category="Secuencia - DHCP",
        ))
        if len(dora) >= 3:
            qs.append(order_question(
                dora, "una asignación de dirección por DHCP",
                explain="El orden es siempre Discover -> Offer -> Request -> ACK. "
                        "Se deduce de la lógica: el cliente no puede pedir (Request) "
                        "una IP que todavía no le ofrecieron, ni el servidor puede "
                        "confirmar algo que no se le ha pedido.",
                difficulty="medio",
            ))

    unre = find_unreachable(tl)
    if unre and len(unre) >= 2:
        qs.append(seq_question(
            unre,
            "El último paquete de la secuencia es un ICMP Destination Unreachable. "
            "¿Qué te dice eso sobre los paquetes anteriores?",
            "No llegaron a su destino: algún router o el propio host avisa que no pudo entregarlos",
            ["Llegaron correctamente y esto es solo una confirmación de recibo",
             "El destino aceptó la conexión y está pidiendo más datos",
             "Es un mensaje de diagnóstico rutinario sin relación con ellos"],
            explain="ICMP type=3 lo genera un router (o el host destino) para avisar "
                    "al origen que su paquete no pudo entregarse; el campo 'code' "
                    "precisa el motivo (red inalcanzable, host inalcanzable, puerto "
                    "inalcanzable, prohibido administrativamente por un firewall...). "
                    "Por eso siempre hay que leerlo junto con los paquetes que lo "
                    "provocaron, no aislado.",
            difficulty="medio", category="Secuencia - ICMP",
        ))

    # ---- lectura generica de una ventana de paquetes consecutivos ----------
    if len(tl) >= 4:
        start = random.randint(0, max(0, len(tl) - 5))
        window = tl[start:start + random.randint(3, 5)]
        if len(window) >= 3:
            first = window[0]
            qs.append(Question(
                render_sequence(window, "Ventana de paquetes consecutivos") +
                f"\n¿Cuántos paquetes de esta ventana salen desde {first['src']}?",
                "text", sum(1 for r in window if r["src"] == first["src"]),
                explain="Leer una captura no es mirar paquetes sueltos: hay que "
                        "seguir quién habla con quién y en qué sentido. Contar los "
                        "paquetes por origen dentro de una ventana es el primer "
                        "paso para separar las conversaciones que van intercaladas.",
                difficulty="facil", category="Secuencia - lectura",
            ))
            protos = [r["proto"] for r in window]
            dominante = max(set(protos), key=protos.count)
            otros = [p for p in ["ARP", "ICMP", "TCP", "UDP", "DNS", "DHCP"]
                     if p != dominante]
            random.shuffle(otros)
            qs.append(seq_question(
                window,
                "¿Qué protocolo aparece más veces en esta ventana de paquetes?",
                dominante, otros[:3],
                explain="Identificar el protocolo dominante de un tramo de la "
                        "captura orienta la hipótesis: mucho ARP sugiere "
                        "descubrimiento o spoofing en la red local, mucho ICMP "
                        "puede ser diagnóstico o un flood, y mucho DNS puede "
                        "indicar resolución masiva o tunneling.",
                difficulty="facil", category="Secuencia - lectura",
            ))

    return qs


# ---------------------------------------------------------------------------
# Banco de preguntas teóricas de ciberseguridad (independientes del pcap)
# ---------------------------------------------------------------------------

def theory_questions():
    bank = [
        Question(
            "¿Qué es el ARP Spoofing?",
            "mcq", 1,
            ["Un método para acelerar la resolución de nombres DNS",
             "Enviar respuestas ARP falsas para asociar la MAC del atacante "
             "con la IP de otro host y así interceptar su tráfico",
             "Un tipo de cifrado usado en redes WiFi",
             "Una técnica de compresión de paquetes"],
            explain="El ARP Spoofing (o ARP poisoning) explota que ARP no "
                     "autentica sus respuestas: cualquier host puede anunciar "
                     "'yo soy esta IP' y los demás lo creen sin verificar.",
            difficulty="facil", category="Teoría - MITM",
        ),
        Question(
            "En un ataque Man-in-the-Middle (MITM) exitoso vía ARP spoofing, "
            "¿por qué el atacante suele activar IP forwarding en su propio host?",
            "mcq", 0,
            ["Para reenviar el tráfico interceptado a su destino real y que "
             "la victima no note ninguna interrupción",
             "Para acelerar su propia conexión a internet",
             "Porque es un requisito obligatorio del protocolo ARP",
             "Para cifrar el tráfico antes de reenviarlo"],
            explain="Si el atacante no reenvía el tráfico, la comunicación entre "
                     "las victimas simplemente se corta y el ataque se detecta "
                     "fácil. Reenviarlo (forwarding) permite espiar sin romper "
                     "la conexión -- por eso el TTL baja 1 al pasar por el.",
            difficulty="medio", category="Teoría - MITM",
        ),
        Question(
            "¿Qué caracteriza a un ataque de tipo 'Smurf' (DoS por amplificación "
            "ICMP)?",
            "mcq", 2,
            ["Se basa en fuerza bruta contra contraseñas",
             "Explota una vulnerabilidad de desbordamiento de buffer",
             "Envía solicitudes ICMP echo a una dirección de broadcast, "
             "falsificando como origen la IP de la victima, para que todos "
             "los hosts de la red respondan a la victima",
             "Es un tipo de phishing dirigido"],
            explain="El factor de amplificación viene de que un solo paquete "
                     "enviado al broadcast genera N respuestas (una por cada "
                     "host de la subred), todas dirigidas a la IP falsificada.",
            difficulty="medio", category="Teoría - DoS",
        ),
        Question(
            "¿Cuál es el orden correcto del 'three-way handshake' de TCP para "
            "establecer una conexión?",
            "mcq", 0,
            ["SYN -> SYN-ACK -> ACK", "ACK -> SYN -> SYN-ACK",
             "SYN -> ACK -> SYN-ACK", "FIN -> SYN -> ACK"],
            explain="El cliente envía SYN, el servidor responde SYN-ACK, y el "
                     "cliente confirma con ACK. Recién ahí la conexión queda "
                     "establecida y pueden fluir datos.",
            difficulty="facil", category="Teoría - TCP",
        ),
        Question(
            "¿Por qué un ataque SYN flood es difícil de mitigar solo con "
            "'ignorar paquetes de origen desconocido'?",
            "mcq", 1,
            ["Porque TCP no usa direcciones IP",
             "Porque el atacante puede falsificar (spoofear) la IP de origen "
             "en cada paquete SYN, por lo que bloquear una IP no detiene el ataque",
             "Porque los paquetes SYN van cifrados",
             "Porque el servidor no puede leer paquetes SYN"],
            explain="Al no requerir que se complete el handshake, el atacante "
                     "puede mandar SYN con IP origen falsa cada vez, dificultando "
                     "el filtrado por IP. Mitigaciones reales usan técnicas como "
                     "SYN cookies.",
            difficulty="dificil", category="Teoría - DoS",
        ),
        Question(
            "¿Qué es el DNS Spoofing / caché poisoning?",
            "mcq", 0,
            ["Insertar una respuesta DNS falsa para que un dominio legítimo "
             "resuelva a una IP controlada por el atacante",
             "Un método legítimo de balanceo de carga entre servidores DNS",
             "Cifrar las consultas DNS con TLS",
             "Un fallo de hardware en el router"],
            explain="Si el atacante logra inyectar una respuesta falsa (o "
                     "envenenar la caché de un resolver), redirige a las victimas "
                     "hacia sitios maliciosos aunque escriban el dominio correcto.",
            difficulty="medio", category="Teoría - DNS",
        ),
        Question(
            "¿Cuál es la función principal del campo TTL en un paquete IP?",
            "mcq", 1,
            ["Indicar el tamaño máximo del payload",
             "Limitar cuántos saltos (routers) puede atravesar un paquete "
             "antes de ser descartado, evitando bucles infinitos",
             "Cifrar el contenido del paquete",
             "Indicar la prioridad de QoS del paquete"],
            explain="Cada router que reenvía el paquete decrementa el TTL en 1; "
                     "si llega a 0, el paquete se descarta. Por eso comparar "
                     "TTLs es útil para detectar saltos inesperados (como un "
                     "MITM).",
            difficulty="facil", category="Teoría - Redes",
        ),
        Question(
            "En un switch de red (a diferencia de un hub), ¿por qué el ARP "
            "spoofing es necesario para poder 'esnifar' el tráfico de otro host?",
            "mcq", 0,
            ["Porque el switch solo envía cada trama al puerto correspondiente "
             "a la MAC destino, así que un atacante no ve tráfico ajeno salvo "
             "que lo redirijan hacia el",
             "Porque los switches no soportan Ethernet",
             "Porque el switch cifra automáticamente todo el tráfico",
             "No es necesario, un switch ya replica todo el tráfico como un hub"],
            explain="Un hub retransmite a todos los puertos (fácil de esnifar); "
                     "un switch aprende qué MAC está en qué puerto y envía el "
                     "tráfico solo ahí. Para ver tráfico ajeno en un switch, un "
                     "atacante necesita técnicas como ARP spoofing o MAC flooding.",
            difficulty="dificil", category="Teoría - Redes",
        ),
        Question(
            "¿Qué es el modo promiscuo de una interfaz de red?",
            "mcq", 0,
            ["Un modo en el que la NIC captura todos los paquetes que le "
             "llegan, aunque no vayan dirigidos a su propia MAC",
             "Un modo que cifra automáticamente todo el tráfico saliente",
             "Un protocolo de enrutamiento dinámico",
             "Una función exclusiva de los routers Cisco"],
            explain="Herramientas como Wireshark o tcpdump necesitan que la "
                     "interfaz esté en modo promiscuo para poder capturar todo "
                     "el tráfico visible en el segmento de red, no solo el "
                     "dirigido a esa máquina.",
            difficulty="facil", category="Teoría - Sniffing",
        ),
        Question(
            "¿Qué hace que un ICMP Redirect falsificado sea peligroso en manos "
            "de un atacante?",
            "mcq", 1,
            ["No tiene ningun efecto real en el enrutamiento",
             "Puede engañar a un host para que envie su tráfico a través de "
             "una ruta/gateway distinta, controlada por el atacante",
             "Solo funciona dentro de redes cifradas con IPsec",
             "Es idéntico a un paquete ARP y no aporta nada nuevo"],
            explain="Los ICMP Redirect legítimos sirven para que un router le "
                     "diga a un host 'usa una ruta mejor'. Si un atacante los "
                     "falsifica, puede reforzar un MITM a nivel de capa 3, además "
                     "del spoofing de ARP en capa 2.",
            difficulty="dificil", category="Teoría - MITM",
        ),
    ]
    return bank


# ---------------------------------------------------------------------------
# Ventana deslizante en la captura: el campo 'win' de TCP
# ---------------------------------------------------------------------------

def build_window_questions(ds: PcapDataset):
    """Preguntas sobre la ventana deslizante real anunciada en los paquetes TCP."""
    tcp = [r for r in ds.timeline if r["proto"] == "TCP" and r["win"] is not None]
    if not tcp:
        return []
    qs = []

    # -- leer el tamaño de ventana de un paquete concreto --
    r = random.choice(tcp)
    qs.append(Question(
        render_sequence([r], "Paquete bajo análisis") +
        f"\n¿Cuántos bytes de ventana (campo win) está anunciando {r['src']} "
        f"en el paquete #{r['num']}?",
        "text", r["win"],
        explain="El campo 'window' de la cabecera TCP es la ventana de recepción "
                "(rwnd): le dice al otro extremo cuántos bytes más puede mandarle "
                "sin esperar confirmación. Es el mecanismo de control de flujo, y "
                "es una ventana deslizante: avanza a medida que llegan los ACK. "
                "Ojo: si la conexión negoció la opción window scaling en el "
                "handshake, el valor real es win multiplicado por 2^s.",
        difficulty="facil", category="Ventana deslizante",
    ))

    # -- evolucion de la ventana dentro de un mismo flujo --
    flows = defaultdict(list)
    for x in tcp:
        flows[(x["src"], x["sport"], x["dst"], x["dport"])].append(x)
    best = max(flows.values(), key=len)

    if len(best) >= 3:
        seq = best[:5] if len(best) >= 5 else best
        last = seq[-1]
        qs.append(Question(
            render_sequence(seq, "Un mismo flujo TCP, en orden") +
            f"\nSegún el último paquete mostrado, ¿cuántos bytes puede tener en "
            f"vuelo {last['dst']} hacia {last['src']} sin recibir un ACK nuevo?",
            "text", last["win"],
            explain=f"La ventana la anuncia quien RECIBE, para limitar a quien "
                    f"ENVÍA. Como #{last['num']} sale de {last['src']}, su win "
                    f"({last['win']} bytes) es el límite que {last['src']} le impone "
                    f"a {last['dst']}. El emisor nunca puede tener más bytes sin "
                    "confirmar que ese valor: esa es la diferencia entre la ventana "
                    "deslizante (cuántos datos caben en vuelo) y el simple "
                    "stop-and-wait (un paquete a la vez).",
            difficulty="medio", category="Ventana deslizante",
        ))

        # el win del SYN aun no tiene aplicado el window scaling: no es comparable
        sin_syn = [x for x in seq if "S" not in str(x["flags"])]
        wins = [x["win"] for x in sin_syn]
        if len(wins) >= 2 and len(set(wins)) > 1:
            qs.append(seq_question(
                sin_syn,
                f"La ventana anunciada en este flujo cambia (va de {wins[0]} a "
                f"{wins[-1]} bytes). ¿Qué significa que la ventana anunciada baje?",
                "Que el buffer de recepción se está llenando: la aplicación no "
                "lee tan rápido como llegan los datos, y se frena al emisor",
                ["Que la conexión se está cerrando de forma ordenada",
                 "Que el enlace físico perdió velocidad",
                 "Que el emisor está retransmitiendo paquetes perdidos"],
                explain="La ventana anunciada refleja el espacio libre en el buffer "
                        "del receptor. Si la aplicación no consume los datos, ese "
                        "espacio se reduce y la ventana encoge: es control de FLUJO "
                        "(proteger al receptor lento), distinto del control de "
                        "CONGESTIÓN (proteger a la red). Si llegara a win=0, el "
                        "emisor debe parar y mandar 'window probes' hasta que el "
                        "receptor anuncie espacio otra vez.",
                difficulty="dificil", category="Ventana deslizante",
            ))

    zero = [x for x in tcp if x["win"] == 0]
    if zero:
        z = zero[0]
        qs.append(seq_question(
            [z],
            f"El paquete #{z['num']} anuncia win=0. ¿Qué debe hacer el otro extremo?",
            "Dejar de enviar datos y sondear periódicamente con 'window probes' "
            "hasta que se anuncie ventana disponible",
            ["Seguir enviando al mismo ritmo, porque win=0 no es vinculante",
             "Cerrar la conexión inmediatamente con un RST",
             "Retransmitir todos los paquetes de la ventana anterior"],
            explain="win=0 (zero window) significa que el buffer del receptor está "
                    "lleno. El emisor debe detenerse; para no quedarse bloqueado "
                    "para siempre si se pierde el anuncio de reapertura, envía "
                    "sondas periódicas (window probes) preguntando si ya hay "
                    "espacio. Es el caso extremo del control de flujo.",
            difficulty="dificil", category="Ventana deslizante",
        ))

    return qs


# ---------------------------------------------------------------------------
# Teoría de protocolos de ventana deslizante: Stop-and-Wait, GBN y Selective Repeat
# ---------------------------------------------------------------------------

def sliding_window_questions():
    """Conceptos y ejercicios numéricos de ventana deslizante, GBN y SR."""
    bank = [
        Question(
            "¿Para qué sirve una ventana deslizante (sliding window) en un "
            "protocolo de transporte confiable?",
            "mcq", 0,
            ["Para permitir que el emisor tenga varios paquetes en vuelo a la vez "
             "en lugar de esperar el ACK de cada uno, aprovechando mejor el enlace",
             "Para cifrar los datos antes de enviarlos por la red",
             "Para dividir el mensaje en fragmentos IP más pequeños",
             "Para elegir la ruta más corta hacia el destino"],
            explain="Con stop-and-wait el emisor manda un paquete y se queda "
                    "esperando su ACK durante todo un RTT, así que el enlace pasa "
                    "casi todo el tiempo ocioso. La ventana deslizante permite "
                    "tener hasta N paquetes sin confirmar simultáneamente, y la "
                    "ventana 'se desliza' hacia adelante a medida que llegan los "
                    "ACK. Stop-and-wait es simplemente el caso N=1.",
            difficulty="facil", category="Ventana deslizante - teoría",
        ),
        Question(
            "¿Cuál es la diferencia esencial entre Go-Back-N y Selective Repeat?",
            "mcq", 1,
            ["Go-Back-N usa ventana deslizante y Selective Repeat no la usa",
             "Ante una pérdida, Go-Back-N retransmite el paquete perdido y TODOS "
             "los posteriores, mientras que Selective Repeat retransmite solo el "
             "que se perdió",
             "Go-Back-N funciona sobre UDP y Selective Repeat sobre TCP",
             "Selective Repeat no necesita números de secuencia"],
            explain="Los dos son protocolos de ventana deslizante; la diferencia "
                    "está en cómo reaccionan a una pérdida. GBN es simple pero "
                    "derrochador: retrocede al primer paquete no confirmado y "
                    "reenvía desde ahí, incluso paquetes que ya habían llegado "
                    "bien. SR es eficiente pero más complejo: reenvía solo lo que "
                    "falta, a costa de buffers y temporizadores en ambos extremos.",
            difficulty="facil", category="Ventana deslizante - teoría",
        ),
        Question(
            "En Go-Back-N, ¿qué hace el RECEPTOR cuando le llega un paquete "
            "fuera de orden?",
            "mcq", 0,
            ["Lo descarta y vuelve a enviar el ACK del último paquete recibido "
             "en orden (ACK acumulativo)",
             "Lo guarda en un buffer y lo confirma individualmente",
             "Lo reenvía al emisor para que lo corrija",
             "Cierra la conexión porque detecta un error"],
            explain="El receptor de GBN no tiene buffer para desorden: solo lleva "
                    "la cuenta del último número de secuencia recibido en orden. "
                    "Por eso descarta cualquier cosa que llegue adelantada y "
                    "repite el ACK acumulativo. Esa simplicidad del receptor es la "
                    "gran ventaja de GBN, y su desperdicio de ancho de banda es la "
                    "gran desventaja.",
            difficulty="medio", category="Go-Back-N",
        ),
        Question(
            "En Selective Repeat, ¿qué hace el RECEPTOR con los paquetes que "
            "llegan fuera de orden pero dentro de su ventana?",
            "mcq", 2,
            ["Los descarta, igual que en Go-Back-N",
             "Los entrega a la aplicación inmediatamente, aunque estén desordenados",
             "Los almacena en un buffer y los confirma individualmente, hasta "
             "poder entregarlos en orden a la aplicación",
             "Los reenvía al emisor pidiendo confirmación"],
            explain="El receptor de SR mantiene su propia ventana y buffer. Guarda "
                    "lo que llega adelantado, manda un ACK individual por cada "
                    "paquete recibido, y solo entrega datos a la capa de aplicación "
                    "cuando puede hacerlo en orden (al llegar el hueco que "
                    "faltaba). Por eso SR necesita ventana y buffer también en el "
                    "receptor, no solo en el emisor.",
            difficulty="medio", category="Selective Repeat",
        ),
        Question(
            "¿Cuántos temporizadores (timers) necesita cada protocolo?",
            "mcq", 1,
            ["Ninguno de los dos usa temporizadores",
             "Go-Back-N usa un único temporizador (para el paquete más antiguo "
             "sin confirmar); Selective Repeat necesita un temporizador por cada "
             "paquete enviado y no confirmado",
             "Go-Back-N usa uno por paquete y Selective Repeat uno solo",
             "Ambos usan exactamente un temporizador por conexión"],
            explain="Como GBN retransmite siempre la ventana completa desde el más "
                    "antiguo, le basta un temporizador asociado a ese paquete: si "
                    "vence, reenvía todo. SR, en cambio, debe saber exactamente "
                    "cuál venció para reenviar solo ese, así que lleva un "
                    "temporizador independiente por paquete en vuelo. Es una de "
                    "las razones de su mayor complejidad de implementación.",
            difficulty="medio", category="Ventana deslizante - teoría",
        ),
        Question(
            "¿Qué es un ACK acumulativo y qué protocolo lo usa?",
            "mcq", 0,
            ["Un ACK n que confirma TODOS los paquetes hasta el n inclusive; "
             "lo usa Go-Back-N (y también TCP)",
             "Un ACK que confirma un único paquete concreto; lo usa Go-Back-N",
             "Un ACK que se envía solo al final de la transferencia completa",
             "Un ACK que viaja cifrado para evitar falsificaciones"],
            explain="Con ACK acumulativo, si el emisor recibe ACK 7 sabe que todo "
                    "lo anterior llegó bien, aunque se hayan perdido ACK "
                    "intermedios: un solo ACK cubre el hueco. Selective Repeat usa "
                    "en cambio ACK individuales (uno por paquete). TCP usa ACK "
                    "acumulativo, y con la opción SACK puede además indicar bloques "
                    "sueltos recibidos, acercándose al comportamiento de SR.",
            difficulty="medio", category="Ventana deslizante - teoría",
        ),
        Question(
            "En Selective Repeat, el tamaño de ventana no puede superar la mitad "
            "del espacio de números de secuencia. ¿Por qué?",
            "mcq", 0,
            ["Porque si fuera mayor, el receptor no podría distinguir una "
             "retransmisión de un paquete nuevo: las ventanas vieja y nueva se "
             "solaparían y el mismo número significaría dos cosas distintas",
             "Porque los buffers de red no soportan ventanas grandes",
             "Porque el temporizador se desbordaría",
             "Porque el ACK acumulativo solo cubre la mitad de la ventana"],
            explain="Es el resultado clásico: en SR debe cumplirse W <= 2^k / 2, es "
                    "decir la mitad del espacio de secuencia. Si no, tras un ciclo "
                    "de números el receptor podría aceptar como dato nuevo un "
                    "duplicado retransmitido, corrompiendo el flujo. En Go-Back-N "
                    "la cota es más holgada: W <= 2^k - 1, porque el receptor solo "
                    "acepta el siguiente número en orden.",
            difficulty="dificil", category="Selective Repeat",
        ),
        Question(
            "¿Cuál es la principal DESVENTAJA de Go-Back-N frente a Selective "
            "Repeat en un enlace con muchas pérdidas?",
            "mcq", 1,
            ["Que necesita mucha más memoria en el receptor",
             "Que desperdicia ancho de banda retransmitiendo paquetes que ya "
             "habían llegado correctamente al receptor",
             "Que no puede detectar paquetes corruptos",
             "Que no permite tener más de un paquete en vuelo"],
            explain="Con una tasa de pérdidas alta y una ventana grande, cada "
                    "pérdida en GBN provoca la retransmisión de toda la ventana. "
                    "El enlace se llena de datos que el receptor ya tenía, y la "
                    "eficiencia cae en picada. SR paga ese precio con complejidad "
                    "(buffers y timers por paquete) en lugar de ancho de banda.",
            difficulty="medio", category="Go-Back-N",
        ),
        Question(
            "TCP no es exactamente Go-Back-N ni Selective Repeat. ¿Por qué se "
            "dice que es un híbrido de los dos?",
            "mcq", 0,
            ["Porque usa ACK acumulativos como GBN, pero el receptor sí "
             "almacena en buffer los segmentos fuera de orden y con la opción "
             "SACK puede confirmar bloques sueltos, como SR",
             "Porque alterna entre GBN y SR según la hora del día",
             "Porque usa GBN para enviar y SR para recibir",
             "Porque no usa números de secuencia por paquete sino por byte, y "
             "eso lo deja fuera de ambas familias"],
            explain="TCP numera bytes, no paquetes, y confirma de forma acumulativa "
                    "(estilo GBN). Pero una implementación real no descarta lo que "
                    "llega adelantado: lo guarda, y con SACK (Selective "
                    "Acknowledgment) le dice al emisor exactamente qué bloques "
                    "tiene, de modo que solo se retransmita el hueco. Ese "
                    "comportamiento es el de SR.",
            difficulty="dificil", category="Ventana deslizante - teoría",
        ),
        Question(
            "En TCP, ¿cuál es la diferencia entre la ventana de recepción (rwnd) "
            "y la ventana de congestión (cwnd)?",
            "mcq", 1,
            ["Son dos nombres para el mismo campo de la cabecera TCP",
             "rwnd la anuncia el receptor para protegerse a sí mismo (control de "
             "flujo) y cwnd la calcula el emisor para no saturar la red (control "
             "de congestión); el emisor usa el mínimo de las dos",
             "rwnd solo existe en IPv6 y cwnd solo en IPv4",
             "cwnd viaja en la cabecera TCP y rwnd se negocia por ICMP"],
            explain="La cantidad de datos que el emisor puede tener en vuelo es "
                    "min(cwnd, rwnd). Son dos problemas distintos: rwnd protege al "
                    "RECEPTOR de ser inundado (viaja en el campo 'window' que ves "
                    "en la captura), y cwnd protege a la RED de la congestión (es "
                    "una variable interna del emisor, no se transmite y no se ve "
                    "en el pcap).",
            difficulty="dificil", category="Ventana deslizante - teoría",
        ),
        Question(
            "El campo 'window' de la cabecera TCP tiene solo 16 bits (máximo "
            "65535 bytes). ¿Cómo se consiguen ventanas mayores en enlaces "
            "rápidos de alta latencia?",
            "mcq", 0,
            ["Con la opción Window Scaling, negociada en el handshake: el valor "
             "anunciado se multiplica por 2^s",
             "Enviando dos cabeceras TCP por segmento",
             "Cambiando a UDP, que no tiene ese límite",
             "Fragmentando los paquetes a nivel IP"],
            explain="En un enlace de alta capacidad y RTT grande, 64 KB de ventana "
                    "no alcanzan para llenar el 'tubo' y el emisor se queda parado "
                    "esperando ACK. La opción Window Scale (RFC 7323) se acuerda en "
                    "el SYN/SYN-ACK y define un factor de escala s, de modo que la "
                    "ventana real es win * 2^s. Por eso un pcap puede mostrar "
                    "win=85 cuando la ventana efectiva son decenas de KB.",
            difficulty="dificil", category="Ventana deslizante - teoría",
        ),
    ]

    # ---------- ejercicios numéricos generados al azar ----------
    k = random.choice([3, 4, 5, 6])
    bank.append(Question(
        f"Un protocolo de ventana deslizante usa números de secuencia de {k} bits "
        f"(es decir, {2 ** k} números distintos, de 0 a {2 ** k - 1}). ¿Cuál es el "
        "tamaño MÁXIMO de ventana permitido si el protocolo es Go-Back-N?",
        "text", 2 ** k - 1,
        explain=f"En Go-Back-N la cota es W <= 2^k - 1 = {2 ** k} - 1 = "
                f"{2 ** k - 1}. Se resta uno porque, si la ventana ocupara todo el "
                "espacio de secuencia, el receptor no podría distinguir una ventana "
                "completamente nueva de una retransmisión íntegra de la anterior: "
                "los ACK perdidos harían ambigua la numeración.",
        difficulty="medio", category="Go-Back-N",
    ))

    k2 = random.choice([3, 4, 5, 6])
    bank.append(Question(
        f"Ese mismo protocolo, con números de secuencia de {k2} bits "
        f"({2 ** k2} números distintos), pero ahora implementado como Selective "
        "Repeat. ¿Cuál es el tamaño MÁXIMO de ventana permitido?",
        "text", 2 ** (k2 - 1),
        explain=f"En Selective Repeat la cota es la mitad del espacio de "
                f"secuencia: W <= 2^k / 2 = 2^{k2 - 1} = {2 ** (k2 - 1)}. Es más "
                "restrictiva que en GBN porque el receptor de SR acepta paquetes "
                "fuera de orden dentro de su ventana; si las ventanas del emisor y "
                "del receptor pudieran solaparse, un duplicado retransmitido se "
                "colaría como si fuera un dato nuevo.",
        difficulty="dificil", category="Selective Repeat",
    ))

    n = random.choice([4, 5, 6, 7, 8])
    base = random.choice([0, 10, 20, 100])
    perdido = base + random.randint(0, n - 2)
    ultimo = base + n - 1
    retransmitidos = ultimo - perdido + 1
    bank.append(Question(
        f"En Go-Back-N con ventana N={n}, el emisor envía los paquetes {base} a "
        f"{ultimo} y se pierde el paquete {perdido}. Todos los demás llegan bien, "
        "pero el receptor los descarta por estar fuera de orden. Cuando vence el "
        f"temporizador, ¿cuántos paquetes retransmite el emisor?",
        "text", retransmitidos,
        explain=f"GBN retrocede hasta el primer paquete no confirmado y reenvía "
                f"desde ahí: del {perdido} al {ultimo}, es decir "
                f"{ultimo} - {perdido} + 1 = {retransmitidos} paquetes. Los "
                f"{retransmitidos - 1} que van después del perdido se retransmiten "
                "aunque hubieran llegado perfectamente, porque el receptor de GBN "
                "no los guardó. En Selective Repeat, en cambio, se retransmitiría "
                "un solo paquete.",
        difficulty="medio", category="Go-Back-N",
    ))

    n2 = random.choice([4, 6, 8])
    bank.append(Question(
        f"Mismo escenario que antes (ventana N={n2}, se pierde UN paquete del "
        "medio y el resto llega bien), pero ahora el protocolo es Selective "
        "Repeat. ¿Cuántos paquetes se retransmiten?",
        "text", 1,
        explain="Solo uno: el que se perdió. El receptor de SR guardó en su buffer "
                "los que llegaron adelantados y los confirmó individualmente, así "
                "que el emisor sabe exactamente cuál falta. Comparar este número "
                "con el de Go-Back-N es la mejor forma de ver por qué SR aprovecha "
                "mucho mejor el ancho de banda cuando hay pérdidas.",
        difficulty="medio", category="Selective Repeat",
    ))

    mbps = random.choice([10, 100, 1000])
    rtt_ms = random.choice([20, 50, 100, 200])
    bdp_bytes = int(mbps * 1_000_000 * (rtt_ms / 1000) / 8)
    bank.append(Question(
        f"Un enlace de {mbps} Mbps tiene un RTT de {rtt_ms} ms. ¿Cuántos BYTES "
        "debe poder tener el emisor en vuelo (producto ancho de banda x retardo) "
        "para aprovechar el 100% del enlace?",
        "text", bdp_bytes,
        explain=f"BDP = ancho de banda x RTT = {mbps} Mbps x {rtt_ms} ms = "
                f"{mbps} x 10^6 bits/s x {rtt_ms / 1000} s = "
                f"{int(mbps * 1_000_000 * (rtt_ms / 1000)):,} bits, que entre 8 son "
                f"{bdp_bytes:,} bytes. Si la ventana es menor que el BDP, el emisor "
                "se queda esperando ACK con el enlace ocioso; por eso en enlaces "
                "rápidos con latencia alta hace falta window scaling.",
        difficulty="dificil", category="Ventana deslizante - teoría",
    ))

    win_raw = random.choice([85, 229, 501, 1024])
    scale = random.choice([2, 4, 7])
    bank.append(Question(
        f"En el handshake se negoció Window Scaling con factor de escala s={scale}. "
        f"Un paquete anuncia win={win_raw} en la cabecera. ¿Cuántos bytes de "
        "ventana son realmente?",
        "text", win_raw * (2 ** scale),
        explain=f"La ventana real es win x 2^s = {win_raw} x 2^{scale} = "
                f"{win_raw} x {2 ** scale} = {win_raw * (2 ** scale)} bytes. Por eso "
                "no se puede leer el campo 'window' de forma literal sin haber "
                "visto el handshake: Wireshark muestra 'window size (scaled)' solo "
                "si capturó los paquetes SYN donde se negoció la opción.",
        difficulty="dificil", category="Ventana deslizante - teoría",
    ))

    return bank


# ---------------------------------------------------------------------------
# Flujo principal del juego
# ---------------------------------------------------------------------------

FILES_DIR = Path(__file__).resolve().parent / "files"


def find_candidate_pcaps():
    """Lista los .pcap de la carpeta relativa 'files' (junto a este script)."""
    if not FILES_DIR.is_dir():
        return []
    return sorted(FILES_DIR.glob("*.pcap"))


def select_pcap_path():
    candidates = find_candidate_pcaps()
    if not candidates:
        print(f"\nNo encontré archivos .pcap en la carpeta '{FILES_DIR}'.")
        print("Coloca ahí tus capturas .pcap y vuelve a ejecutar el juego.")
        sys.exit(1)

    banner("Capturas disponibles en la carpeta 'files'")
    options = [c.name for c in candidates]
    idx = ask_choice("Elige el archivo .pcap con el que quieres practicar:",
                     options)
    return str(candidates[idx])


def select_difficulty():
    labels = ["Fácil", "Medio", "Difícil", "Mixto (todas)"]
    idx = ask_choice("Elige la dificultad:", labels)
    return ["facil", "medio", "dificil", "mixto"][idx]


def select_num_questions(pool_size):
    default = min(10, pool_size) if pool_size else 0
    raw = input(f"¿Cuántas preguntas quieres responder? (1-{pool_size}, "
                f"enter = {default}): ").strip()
    if not raw:
        return default
    try:
        n = int(raw)
    except ValueError:
        return default
    return max(1, min(n, pool_size))


def main():
    banner("PCAP QUIZ - Trivia de análisis de tráfico y ciberseguridad")
    print("Este juego lee un archivo .pcap real y te hace preguntas sobre su "
          "contenido (ARP, ICMP, TCP, UDP, DNS, DHCP), combinadas con preguntas "
          "teóricas de seguridad de redes.")
    print("Además de paquetes sueltos, te muestra secuencias de 3 a 6 paquetes "
          "para que deduzcas, por su contenido y su orden, qué está ocurriendo "
          "en la red.")
    print("Incluye también ventana deslizante, Go-Back-N y Selective Repeat, "
          "con ejercicios numéricos y con la ventana real anunciada en la "
          "captura.")

    path = select_pcap_path()
    print(f"\nCargando '{path}' ...")
    try:
        ds = PcapDataset(path)
    except Exception as e:
        print(f"No pude leer el archivo: {e}")
        sys.exit(1)

    banner("Resumen de la captura")
    for k, v in ds.summary().items():
        print(f"  {k}: {v}")

    difficulty = select_difficulty()

    pool = (build_dataset_questions(ds) + build_sequence_questions(ds)
            + build_window_questions(ds) + theory_questions()
            + sliding_window_questions())
    if difficulty != "mixto":
        pool = [q for q in pool if q.difficulty == difficulty]
    random.shuffle(pool)

    if not pool:
        print("No hay preguntas disponibles para esa combinación de archivo "
              "y dificultad. Prueba con 'Mixto'.")
        sys.exit(0)

    n = select_num_questions(len(pool))
    selected = pool[:n]

    banner(f"Comenzando quiz: {n} preguntas ({difficulty})")
    score = 0
    try:
        for i, q in enumerate(selected, 1):
            print(f"\nPregunta {i}/{n}")
            if q.ask():
                score += 1
    except (KeyboardInterrupt, EOFError):
        print("\n\nJuego interrumpido.")

    banner("Resultado final")
    pct = 100 * score / n if n else 0
    print(f"Puntaje: {score}/{n}  ({pct:.0f}%)")
    if pct >= 90:
        print("Excelente dominio de lectura de pcap y conceptos de seguridad.")
    elif pct >= 70:
        print("Buen nivel. Revisa las notas de las preguntas que fallaste.")
    elif pct >= 40:
        print("Vas por buen camino, pero conviene repasar ARP/MITM/DoS/DNS "
              "spoofing con calma.")
    else:
        print("Te recomiendo repasar los fundamentos de TCP/IP, ARP y los "
              "tipos de ataque antes de otra ronda.")
    print("\n¡Gracias por jugar!")


if __name__ == "__main__":
    main()
