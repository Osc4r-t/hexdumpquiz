#!/usr/bin/env python3
"""
RANDOM TCP SCENARIOS  ·  SYN, ACK and the sliding window
========================================================
Builds a different TCP situation every time (handshake, data transfer, losses,
a window filling up, teardown) and asks about it at three levels:

  EASY    with the diagram in front of you: flags, ISN, sequence numbers.
  MEDIUM  with the diagram: work out the next seq/ack, the real window, MSS.
  HARD    NO diagram. Only the written parameters, and everything has to be
          derived: sequence numbers, bytes in flight, effective window, what
          happens when something is lost.

The diagram and the answers come from the same simulation, so they always
agree.

Usage:
    python3 tcp_escenarios.py            interactive menu
    python3 tcp_escenarios.py --easy     one round at that level
    python3 tcp_escenarios.py --demo     shows a solved scenario
"""

import random
import re
import sys
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

A = "=" * 74
B = "-" * 74


# ---------------------------------------------------------------------------
# Model
# ---------------------------------------------------------------------------

@dataclass
class Seg:
    """One TCP segment of the exchange."""
    n: int
    de: str               # "C" (client) or "S" (server)
    flags: str
    seq: int
    ack: Optional[int]
    datos: int            # payload bytes
    win_campo: int        # raw value of the window field
    win_real: int         # with the scale factor already applied
    perdido: bool = False
    nota: str = ""


@dataclass
class Escenario:
    variante: str
    ip_c: str
    ip_s: str
    puerto_c: int
    puerto_s: int
    servicio: str
    isn_c: int
    isn_s: int
    mss: int
    ws_c: int
    ws_s: int
    win_c: int            # campo window crudo del cliente
    win_s: int            # campo window crudo del servidor
    cwnd: int             # ventana de congestión del cliente
    segs: List[Seg] = field(default_factory=list)
    datos_enviados: List[int] = field(default_factory=list)
    perdido_idx: Optional[int] = None
    acks_duplicados: int = 0

    # --- derived values used by the questions ---
    @property
    def win_real_s(self) -> int:
        return self.win_s * (2 ** self.ws_s)

    @property
    def win_real_c(self) -> int:
        return self.win_c * (2 ** self.ws_c)

    @property
    def ventana_efectiva(self) -> int:
        return min(self.cwnd, self.win_real_s)

    @property
    def segmentos_en_ventana(self) -> int:
        return self.ventana_efectiva // self.mss

    def de_nombre(self, de: str) -> str:
        return "client" if de == "C" else "server"


SERVICIOS = [(80, "HTTP"), (443, "HTTPS"), (22, "SSH"), (21, "FTP control"),
             (25, "SMTP"), (110, "POP3"), (143, "IMAP"), (3306, "MySQL")]

VARIANTES = ["handshake", "datos", "perdida", "cierre", "ventana_llena"]


# ---------------------------------------------------------------------------
# Scenario generation
# ---------------------------------------------------------------------------

def nueva_ip() -> str:
    base = random.choice(["192.168", "10.0", "172.16"])
    if base == "10.0":
        return f"10.0.{random.randint(0, 5)}.{random.randint(2, 250)}"
    if base == "172.16":
        return f"172.16.{random.randint(0, 5)}.{random.randint(2, 250)}"
    return f"192.168.{random.randint(0, 5)}.{random.randint(2, 250)}"


def generar(nivel: str, variante: Optional[str] = None) -> Escenario:
    """Creates a random scenario and simulates the whole exchange."""
    if variante is None:
        variante = random.choice(VARIANTES)

    puerto_s, servicio = random.choice(SERVICIOS)
    # at hard level the ISNs are real 32-bit values; easier levels use
    # smaller ones so the arithmetic stays doable
    if nivel == "dificil":
        isn_c = random.randint(1_000_000_000, 4_000_000_000)
        isn_s = random.randint(1_000_000_000, 4_000_000_000)
    else:
        isn_c = random.randint(10_000, 999_999)
        isn_s = random.randint(10_000, 999_999)

    e = Escenario(
        variante=variante,
        ip_c=nueva_ip(), ip_s=nueva_ip(),
        puerto_c=random.randint(32768, 60999),
        puerto_s=puerto_s, servicio=servicio,
        isn_c=isn_c, isn_s=isn_s,
        mss=random.choice([536, 1220, 1360, 1460]),
        ws_c=random.choice([0, 2, 3, 7]),
        ws_s=random.choice([0, 2, 4, 7]),
        win_c=random.choice([64240, 65535, 29200, 8192]),
        win_s=random.choice([229, 501, 502, 1024, 5840]),
        cwnd=random.choice([2, 3, 4, 6, 10]) * random.choice([536, 1460]),
    )
    simular(e)
    return e


def simular(e: Escenario) -> None:
    """Builds the exchange step by step. Everything else derives from here."""
    segs = e.segs
    n = 0

    def añadir(de, flags, seq, ack, datos, win_campo, escala, nota="",
               perdido=False):
        nonlocal n
        n += 1
        segs.append(Seg(n, de, flags, seq, ack, datos, win_campo,
                        win_campo * (2 ** escala), perdido, nota))
        return segs[-1]

    # ---- handshake: the SYN consumes one sequence number ----
    añadir("C", "SYN", e.isn_c, None, 0, e.win_c, 0,
           "window scaling does not apply to the SYN yet")
    seq_c = e.isn_c + 1

    añadir("S", "SYN, ACK", e.isn_s, seq_c, 0, e.win_s, 0,
           "acknowledges the client SYN with ISN+1")
    seq_s = e.isn_s + 1

    añadir("C", "ACK", seq_c, seq_s, 0, e.win_c, e.ws_c,
           "handshake complete, the connection is established")

    if e.variante == "handshake":
        return

    # ---- client sends data ----
    if e.variante == "ventana_llena":
        cuantos = max(2, e.segmentos_en_ventana + 1)
    else:
        cuantos = random.randint(2, 4)

    tamaños = []
    for i in range(cuantos):
        if e.variante == "ventana_llena":
            tamaños.append(e.mss)
        else:
            tamaños.append(random.choice([e.mss, e.mss,
                                          random.randint(20, e.mss - 1)]))
    e.datos_enviados = tamaños

    if e.variante == "perdida":
        e.perdido_idx = random.randrange(0, len(tamaños))

    esperado_s = seq_c          # lo que el servidor espera recibir
    for i, largo in enumerate(tamaños):
        se_pierde = (e.variante == "perdida" and i == e.perdido_idx)
        añadir("C", "PSH, ACK", seq_c, seq_s, largo, e.win_c, e.ws_c,
               "LOST in the network" if se_pierde else "", se_pierde)
        seq_c += largo
        if se_pierde:
            # it never arrived: the server has no idea, so it sends no ACK
            continue
        if seq_c - largo == esperado_s:
            esperado_s += largo
        duplicado = (e.perdido_idx is not None and i > e.perdido_idx)
        añadir("S", "ACK", seq_s, esperado_s, 0, e.win_s, e.ws_s,
               "duplicate ACK: the same byte is still missing" if duplicado else "")
        if duplicado:
            e.acks_duplicados += 1

    if e.variante == "cierre":
        añadir("C", "FIN, ACK", seq_c, seq_s, 0, e.win_c, e.ws_c,
               "the FIN also consumes a sequence number")
        seq_c += 1
        añadir("S", "ACK", seq_s, seq_c, 0, e.win_s, e.ws_s)
        añadir("S", "FIN, ACK", seq_s, seq_c, 0, e.win_s, e.ws_s)
        seq_s += 1
        añadir("C", "ACK", seq_c, seq_s, 0, e.win_c, e.ws_c,
               "fully closed on both sides")


# ---------------------------------------------------------------------------
# Presentation
# ---------------------------------------------------------------------------

def dibujar(e: Escenario, hasta: Optional[int] = None) -> str:
    """Table of the exchange: the aligned seq and ack columns make the
    progression obvious at a glance (easy and medium levels)."""
    segs = e.segs if hasta is None else e.segs[:hasta]
    lineas = [
        "", A,
        f"  {e.ip_c}:{e.puerto_c}  (client)   <-->   "
        f"{e.ip_s}:{e.puerto_s}  ({e.servicio})",
        A,
        f"   {'#':>2}  {'dir':<10} {'flags':<10} {'seq':>11} {'ack':>11}"
        f" {'len':>5} {'win':>7}",
        "  " + "-" * 70,
    ]
    notas = []
    for x in segs:
        if x.de == "C":
            sentido = "C ══✗" if x.perdido else "C ═══►"
        else:
            sentido = "◄═══ S"
        ack = str(x.ack) if x.ack is not None else "-"
        lineas.append(
            f"   {x.n:>2}  {sentido:<10} {x.flags:<10} {x.seq:>11} {ack:>11}"
            f" {x.datos:>5} {x.win_campo:>7}")
        if x.nota:
            notas.append(f"      #{x.n}: {x.nota}")
    lineas.append("  " + "-" * 70)
    lineas.append("   C = client, S = server.  len = bytes of data.")
    lineas.append("   win = RAW value of the window field (scale not applied).")
    if notas:
        lineas.append("")
        lineas.extend(notas)
    lineas.append(A)
    return "\n".join(lineas)


def ficha(e: Escenario, con_intercambio: bool = True) -> str:
    """Only the parameters, as text. This is what the hard level gives you."""
    l = [
        "", A, "  SCENARIO DATA  (no diagram: you have to work it out)", A,
        f"    Client             {e.ip_c}:{e.puerto_c}",
        f"    Server             {e.ip_s}:{e.puerto_s}  ({e.servicio})",
        "",
        f"    Client ISN         {e.isn_c}",
        f"    Server ISN         {e.isn_s}",
        f"    Negotiated MSS     {e.mss} bytes",
        f"    Window scale       client s={e.ws_c}   server s={e.ws_s}",
        f"    Window field       client {e.win_c}    server {e.win_s}",
        f"    Client cwnd        {e.cwnd} bytes",
    ]
    if con_intercambio and e.datos_enviados:
        l += ["",
              "    Once the handshake is complete, the client sends, in order, "
              "segments of:",
              "      " + ", ".join(f"{x} bytes" for x in e.datos_enviados)]
        if e.perdido_idx is not None:
            l.append(f"    Segment number {e.perdido_idx + 1} of that list IS LOST "
                     "in the network;")
            l.append("    all the others arrive fine.")
    if e.variante == "cierre":
        l.append("    When it is done, the client closes the connection with a FIN.")
    l.append(A)
    return "\n".join(l)


# ---------------------------------------------------------------------------
# Question engine
# ---------------------------------------------------------------------------

@dataclass
class Pregunta:
    enunciado: str
    respuesta: Any
    explicacion: str
    tipo: str = "num"          # "num" | "texto" | "opcion"
    opciones: List[str] = field(default_factory=list)


def _num(texto: str) -> Optional[int]:
    t = str(texto).strip().lower().replace(" ", "").replace(",", "").replace("_", "")
    if t.startswith("0x"):
        try:
            return int(t[2:], 16)
        except ValueError:
            return None
    try:
        return int(t)
    except ValueError:
        return None


def acierta(dado: str, p: Pregunta) -> bool:
    if p.tipo == "num":
        n = _num(dado)
        return n is not None and n == int(p.respuesta)
    if p.tipo == "opcion":
        letras = "ABCDEFGH"
        d = dado.strip().upper()
        return d in letras[:len(p.opciones)] and letras.index(d) == p.respuesta
    limpio = " ".join(dado.strip().lower().split())
    esperado = " ".join(str(p.respuesta).strip().lower().split())
    limpio = re.sub(r"[^a-z0-9]", "", limpio)
    esperado = re.sub(r"[^a-z0-9]", "", esperado)
    return limpio == esperado


def _opcion(correcta: str, otras: List[str]) -> Tuple[List[str], int]:
    opts = [correcta] + [x for x in otras if x != correcta][:3]
    random.shuffle(opts)
    return opts, opts.index(correcta)


# ---------------------------------------------------------------------------
# EASY: read the diagram
# ---------------------------------------------------------------------------

def preguntas_faciles(e: Escenario) -> List[Pregunta]:
    qs = []
    syn, synack, ack = e.segs[0], e.segs[1], e.segs[2]

    qs.append(Pregunta(
        "What is the client's ISN (initial sequence number)?",
        e.isn_c,
        f"It is the seq of the first packet, the SYN: {e.isn_c}. It is chosen "
        "at random precisely so an attacker cannot predict it and inject data "
        "into the connection."))

    qs.append(Pregunta(
        "What ACK number does the server send in its SYN-ACK (segment #2)?",
        synack.ack,
        f"{e.isn_c} + 1 = {synack.ack}. The SYN carries no data at all, but it "
        "does CONSUME a sequence number, so the next byte the server expects "
        f"is {synack.ack}."))

    opts, idx = _opcion(
        "The SYN consumes a sequence number even though it carries no data",
        ["The server adds one padding byte",
         "It is a Wireshark glitch when showing relative numbers",
         "The +1 accounts for the TCP header"])
    qs.append(Pregunta(
        "Why is the SYN-ACK's ack ISN+1 and not ISN, if the SYN carries no data?",
        idx, "SYN and FIN are the two flags that consume a sequence number "
             "without carrying data. That is why the handshake advances the "
             "numbering by one, and so does the teardown.",
        tipo="opcion", opciones=opts))

    qs.append(Pregunta(
        "Which flags does segment #2 carry?",
        "SYN ACK",
        "It is the SYN-ACK: the server accepts the connection (SYN) and at the "
        "same time acknowledges the client's SYN (ACK). It is the only segment "
        "of the handshake carrying both.",
        tipo="texto"))

    qs.append(Pregunta(
        "How many segments does the handshake take, before the first byte of "
        "data travels?",
        3, "SYN, SYN-ACK and ACK: the three-way handshake. The connection is "
           "established once the third one is sent; data can start from there."))

    qs.append(Pregunta(
        "What is the value of the window field in the client's SYN (segment #1)?",
        e.win_c,
        f"The field reads {e.win_c}. Careful: window scaling does NOT apply to "
        "the SYN, because the option is being negotiated in that very packet. "
        "The scale only counts for later segments."))

    qs.append(Pregunta(
        "At which sequence number does the client start numbering its DATA "
        "bytes, once the handshake is complete?",
        e.isn_c + 1,
        f"{e.isn_c} + 1 = {e.isn_c + 1}. The ISN was spent on the SYN, so the "
        "first real data byte gets the next number. That is the seq you see in "
        "the handshake's ACK (segment #3)."))

    datos = [x for x in e.segs if x.datos > 0 and not x.perdido]
    if datos:
        d = datos[0]
        qs.append(Pregunta(
            f"How many bytes of data does segment #{d.n} carry?",
            d.datos,
            f"The len column says it: {d.datos} bytes. A segment with len=0 is "
            "pure control (an ACK, a SYN or a FIN); the ones carrying data are "
            "what make the sequence number advance."))
    return qs

# ---------------------------------------------------------------------------
# MEDIUM: compute from the diagram
# ---------------------------------------------------------------------------

def preguntas_medias(e: Escenario) -> List[Pregunta]:
    qs = []

    qs.append(Pregunta(
        f"The server negotiated window scale s={e.ws_s} and advertises the "
        f"window field={e.win_s} after the handshake. How many BYTES of window "
        "is that really?",
        e.win_real_s,
        f"{e.win_s} x 2^{e.ws_s} = {e.win_s} x {2 ** e.ws_s} = {e.win_real_s} "
        "bytes. The window field is 16 bits wide, so without the scale you "
        "could never advertise more than 65535."))

    qs.append(Pregunta(
        f"With that real server window ({e.win_real_s} bytes) and an MSS of "
        f"{e.mss}, how many FULL segments can the client keep in flight before "
        "running out of window?",
        e.win_real_s // e.mss,
        f"{e.win_real_s} // {e.mss} = {e.win_real_s // e.mss} full segments. It "
        "is the same reasoning as the window size N of a sliding window, only "
        "TCP measures it in bytes instead of packets."))

    datos = [x for x in e.segs if x.datos > 0 and not x.perdido]
    if datos:
        d = datos[0]
        i = e.segs.index(d)
        real = next((x.ack for x in e.segs[i + 1:] if x.de == "S"), None)
        if real is not None:
            hay_hueco = (real != d.seq + d.datos)
            if hay_hueco:
                explica = (
                    f"Careful, here it is NOT {d.seq} + {d.datos} = "
                    f"{d.seq + d.datos}. Another segment was lost before this "
                    f"one, so the server is still waiting for byte {real} and "
                    "cannot acknowledge past the gap: TCP's ACK is CUMULATIVE. "
                    "It will buffer this segment, but keep repeating ACK "
                    f"{real} until the missing piece arrives.")
            else:
                explica = (
                    f"{d.seq} + {d.datos} = {real}. The ACK points at the NEXT "
                    "byte expected, not the last one received, and being "
                    "cumulative it implicitly confirms everything before it.")
            qs.append(Pregunta(
                f"Segment #{d.n} goes out with seq={d.seq} and len={d.datos}. "
                "What ACK number will the server return when it arrives?",
                real, explica))

        siguiente_seq = d.seq + d.datos
        qs.append(Pregunta(
            f"What sequence number will the client's NEXT data segment carry, "
            f"after #{d.n}?",
            siguiente_seq,
            f"{d.seq} + {d.datos} = {siguiente_seq}. The sender numbers the "
            "bytes it puts on the wire, and that does NOT depend on what gets "
            "acknowledged: even if an earlier segment was lost, the client's "
            "seq keeps advancing all the same. What falls behind in that case "
            "is the receiver's ACK, not the sender's seq."))

    total_datos = sum(x.datos for x in e.segs if x.de == "C")
    if total_datos:
        entregados = sum(x.datos for x in e.segs if x.de == "C" and not x.perdido)
        qs.append(Pregunta(
            "Adding up every client segment, how many bytes of data did it try "
            "to send in total (counting the ones that were lost)?",
            total_datos,
            f"{' + '.join(str(x.datos) for x in e.segs if x.de == 'C' and x.datos)}"
            f" = {total_datos} bytes."
            + (f" Of those, only {entregados} reached the server."
               if entregados != total_datos else "")))

    qs.append(Pregunta(
        f"The client's cwnd is {e.cwnd} bytes and the real window advertised by "
        f"the server is {e.win_real_s}. How many bytes can the client have in "
        "flight at most?",
        e.ventana_efectiva,
        f"min(cwnd, rwnd) = min({e.cwnd}, {e.win_real_s}) = "
        f"{e.ventana_efectiva} bytes. Both apply at once: rwnd protects the "
        "RECEIVER from being flooded and cwnd protects the NETWORK from "
        "congestion. Whichever is smaller is the one holding you back."
        + (" Here the bottleneck is the receiver's window."
           if e.win_real_s < e.cwnd else " Here the bottleneck is congestion.")))

    opts, idx = _opcion(
        "In the window field of the TCP header",
        ["In a TCP option negotiated during the handshake",
         "In the urgent pointer field",
         "Nowhere: cwnd is never transmitted, it is internal to the sender"])
    qs.append(Pregunta(
        "Where does the receive window (rwnd) travel inside the packet?",
        idx,
        "rwnd is the window field, 2 bytes of the TCP header, readable in any "
        "dump. cwnd on the other hand is an internal variable of the sender: it "
        "is never transmitted and you will never see it in a capture.",
        tipo="opcion", opciones=opts))

    if e.perdido_idx is not None:
        dups = [x for x in e.segs if x.de == "S" and "duplicate" in x.nota]
        if dups:
            qs.append(Pregunta(
                "The server repeats the same ACK number several times. Which "
                "value does it repeat?",
                dups[0].ack,
                f"It repeats ACK {dups[0].ack}, the byte it is missing. Even as "
                "later segments keep arriving, a cumulative ACK cannot move "
                "past the gap: it gets stuck there. Those repeated ACKs are the "
                "DUPLICATE ACKs."))
            qs.append(Pregunta(
                "How many duplicate ACKs does the server send in this exchange?",
                e.acks_duplicados,
                f"{e.acks_duplicados}. Every segment arriving after the gap "
                "triggers one. When the sender collects 3 duplicate ACKs it "
                "does not wait for the timer to expire: it immediately resends "
                "the missing segment. That is FAST RETRANSMIT."))
    return qs

# ---------------------------------------------------------------------------
# HARD: no diagram, parameters only
# ---------------------------------------------------------------------------

def preguntas_dificiles(e: Escenario) -> List[Pregunta]:
    """Everything is derived from the parameter sheet: the exchange is hidden."""
    qs = []
    tras_handshake_c = e.isn_c + 1
    tras_handshake_s = e.isn_s + 1

    qs.append(Pregunta(
        "Without looking at any diagram: what (seq, ack) pair does the THIRD "
        "segment of the handshake carry, the ACK sent by the client? Answer "
        "the seq only.",
        tras_handshake_c,
        f"seq = client ISN + 1 = {e.isn_c} + 1 = {tras_handshake_c}, because "
        f"the SYN consumed one number. And its ack would be server ISN + 1 = "
        f"{tras_handshake_s}, for the same reason on the server's SYN."))

    qs.append(Pregunta(
        "And what ACK number does that same third handshake segment carry?",
        tras_handshake_s,
        f"Server ISN + 1 = {e.isn_s} + 1 = {tras_handshake_s}. The handshake is "
        "symmetric: each side consumes a number with its SYN and the other "
        "confirms it by adding one."))

    if e.datos_enviados:
        k = min(len(e.datos_enviados), random.randint(2, len(e.datos_enviados)))
        previos = sum(e.datos_enviados[:k - 1])
        seq_k = tras_handshake_c + previos
        suma = " + ".join(str(x) for x in e.datos_enviados[:k - 1]) or "0"
        qs.append(Pregunta(
            f"The client sends the segments of the list in order. What "
            f"sequence number does segment number {k} of that list go out with?",
            seq_k,
            f"The first one gets {tras_handshake_c} (ISN+1). Before segment {k} "
            f"there were {suma} = {previos} bytes sent, so its seq is "
            f"{tras_handshake_c} + {previos} = {seq_k}. Remember TCP numbers "
            "bytes, not segments: the seq jumps by as many units as there are "
            "bytes ahead of it."))

        total = sum(e.datos_enviados)
        if e.perdido_idx is None:
            final = tras_handshake_c + total
            qs.append(Pregunta(
                "If every segment arrives fine, what ACK number will the server "
                "return right after receiving the LAST data segment?",
                final,
                f"{tras_handshake_c} + {total} = {final}. It is the next byte it "
                "would expect, with all the data acknowledged."
                + (" Careful: if a FIN arrives afterwards the ACK goes up by "
                   "one more, because the FIN also consumes a sequence number."
                   if e.variante == "cierre" else "")))
        else:
            hasta = sum(e.datos_enviados[:e.perdido_idx])
            atascado = tras_handshake_c + hasta
            qs.append(Pregunta(
                f"Segment number {e.perdido_idx + 1} of the list is lost and all "
                "the others arrive fine. At what ACK number does the server get "
                "stuck?",
                atascado,
                f"At {atascado}: that is the first byte it is missing. TCP's ACK "
                "is CUMULATIVE, so even though the later segments do reach it, "
                "it cannot acknowledge past the gap. It will buffer them (just "
                "as Selective Repeat would), but keep repeating that same ACK."))
            posteriores = len(e.datos_enviados) - e.perdido_idx - 1
            qs.append(Pregunta(
                "How many DUPLICATE ACKs will that loss produce?",
                posteriores,
                f"One for each segment arriving after the gap: {posteriores}. "
                "Nothing arrives from the lost segment itself, so it generates "
                "no ACK at all."
                + (" With 3 or more, the sender would do a fast retransmit "
                   "without waiting for the timer." if posteriores >= 3 else
                   " Three are needed to trigger a fast retransmit, so here you "
                   "would have to wait for the timer to expire.")))

    qs.append(Pregunta(
        f"The server has window scale s={e.ws_s} and its window field reads "
        f"{e.win_s} in the segments after the handshake. How many bytes of real "
        "window is it advertising?",
        e.win_real_s,
        f"{e.win_s} x 2^{e.ws_s} = {e.win_real_s} bytes. Without having captured "
        "the handshake it would be impossible to know: the scale factor only "
        "travels there."))

    qs.append(Pregunta(
        f"With cwnd={e.cwnd}, that receiver window, and an MSS of {e.mss}: how "
        "many FULL segments can the client leave unacknowledged before it has "
        "to stop?",
        e.segmentos_en_ventana,
        f"The effective window is min({e.cwnd}, {e.win_real_s}) = "
        f"{e.ventana_efectiva} bytes, and {e.ventana_efectiva} // {e.mss} = "
        f"{e.segmentos_en_ventana} full segments. That is exactly the N "
        "parameter of a sliding window, expressed in bytes."))

    if e.datos_enviados:
        acumulado = 0
        bloquea_en = None
        for i, x in enumerate(e.datos_enviados, 1):
            acumulado += x
            if acumulado > e.ventana_efectiva:
                bloquea_en = i
                break
        if bloquea_en:
            previo = sum(e.datos_enviados[:bloquea_en - 1])
            qs.append(Pregunta(
                "Assuming NO ACK arrives in the meantime: how many segments of "
                "the list does the client manage to send before running out of "
                "window?",
                bloquea_en - 1,
                f"With {e.ventana_efectiva} bytes of effective window, after "
                f"{bloquea_en - 1} segments it has {previo} bytes in flight; the "
                f"next one ({e.datos_enviados[bloquea_en - 1]} bytes) would go "
                f"over {e.ventana_efectiva}, so the client stops and waits for "
                "an ACK to slide the window. That is exactly what blocking on a "
                "full window looks like."))
        else:
            qs.append(Pregunta(
                "Assuming NO ACK arrives in the meantime: how many segments of "
                "the list does the client manage to send before running out of "
                "window?",
                len(e.datos_enviados),
                f"All {len(e.datos_enviados)} of them: they add up to "
                f"{sum(e.datos_enviados)} bytes and the effective window is "
                f"{e.ventana_efectiva}, so they all fit without blocking."))

    if e.variante == "cierre":
        total = sum(e.datos_enviados)
        seq_fin = tras_handshake_c + total
        qs.append(Pregunta(
            "After sending all the data the client sends a FIN. What sequence "
            "number does that FIN go out with?",
            seq_fin,
            f"{tras_handshake_c} + {total} = {seq_fin}: right after the last "
            "byte of data."))
        qs.append(Pregunta(
            "And what ACK number does the server reply to that FIN with?",
            seq_fin + 1,
            f"{seq_fin} + 1 = {seq_fin + 1}. The FIN, like the SYN, consumes a "
            "sequence number even though it carries no data. Those are the only "
            "two flags that do."))

    opts, idx = _opcion(
        "Three duplicate ACKs in a row",
        ["A single duplicate ACK",
         "The retransmission timer expiring",
         "The receiver window dropping to zero"])
    qs.append(Pregunta(
        "What triggers a FAST RETRANSMIT in TCP, without waiting for the timer?",
        idx,
        "Three duplicate ACKs. The reasoning is that if repeated ACKs keep "
        "coming it is because the later segments ARE getting through: the "
        "network is not down, only one segment was lost. Waiting out the whole "
        "timer would be a waste.",
        tipo="opcion", opciones=opts))

    opts, idx = _opcion(
        "Stop and send periodic window probes until space is advertised",
        ["Close the connection with a RST",
         "Keep sending at half the rate",
         "Retransmit the whole window from the start"])
    qs.append(Pregunta(
        "If the server ever advertised window=0, what should the client do?",
        idx,
        "window=0 means the receiver's buffer is full. The sender stops; and so "
        "it does not stay blocked forever if the reopening announcement is "
        "lost, it sends periodic probes asking whether there is room yet.",
        tipo="opcion", opciones=opts))

    return qs

GENERADORES = {
    "facil": preguntas_faciles,
    "medio": preguntas_medias,
    "dificil": preguntas_dificiles,
}


# ---------------------------------------------------------------------------
# Game round
# ---------------------------------------------------------------------------

ETIQUETA = {"facil": "EASY", "medio": "MEDIUM", "dificil": "HARD"}


def contexto(e: Escenario, nivel: str) -> str:
    """Easy and medium see the exchange; hard gets the parameters only."""
    if nivel == "dificil":
        return ficha(e)
    return dibujar(e) + "\n" + resumen_parametros(e)


def resumen_parametros(e: Escenario) -> str:
    return "\n".join([
        f"   negotiated MSS {e.mss}   ·   window scale: client s={e.ws_c}, "
        f"server s={e.ws_s}",
        f"   client cwnd {e.cwnd} bytes",
        ""])


def ronda(nivel: str, cuantas: int = 6,
          variante: Optional[str] = None) -> Tuple[int, int]:
    e = generar(nivel, variante)
    qs = GENERADORES[nivel](e)
    random.shuffle(qs)
    qs = qs[:cuantas]

    print(contexto(e, nivel))
    if nivel == "dificil":
        print("  No diagram: everything has to be derived from the data above.\n")

    aciertos = 0
    for i, q in enumerate(qs, 1):
        print(B)
        print(f"[{ETIQUETA[nivel]}]  Question {i}/{len(qs)}")
        print(f"  {q.enunciado}")
        if q.tipo == "opcion":
            for j, o in enumerate(q.opciones):
                print(f"    {'ABCDEFGH'[j]}) {o}")
            dado = input("  Your answer (letter): ")
        else:
            dado = input("  Your answer: ")
        if acierta(dado, q):
            print("  >> Correct.")
            aciertos += 1
        else:
            if q.tipo == "opcion":
                correcta = f"{'ABCDEFGH'[q.respuesta]}) {q.opciones[q.respuesta]}"
            else:
                correcta = q.respuesta
            print(f"  >> Wrong. Answer: {correcta}")
        print(f"     {q.explicacion}")

    print("\n" + A)
    print(f"  {aciertos}/{len(qs)} at {ETIQUETA[nivel]} level")
    print(A)
    if nivel == "dificil" and aciertos < len(qs):
        print("\n  This is what the exchange actually looked like:")
        print(dibujar(e))
    return aciertos, len(qs)


def menu(titulo: str, opciones: List[str]) -> int:
    print(f"\n{titulo}")
    for i, o in enumerate(opciones, 1):
        print(f"  {i}) {o}")
    while True:
        bruto = input("> ").strip()
        if bruto.isdigit() and 1 <= int(bruto) <= len(opciones):
            return int(bruto) - 1
        print(f"Type a number between 1 and {len(opciones)}.")


def interactivo() -> None:
    print(A)
    print("  RANDOM TCP SCENARIOS  ·  SYN, ACK and the sliding window")
    print(A)
    print("  Every round builds a different situation: handshake, data")
    print("  transfer, a loss, the window filling up, or the teardown.")
    print("  EASY and MEDIUM show you the exchange; HARD gives only the")
    print("  parameters, and you have to work the numbers out yourself.")

    total_ok = total_q = 0
    while True:
        idx = menu("Which level?",
                   ["Easy    (with diagram: read flags, ISN, seq and ack)",
                    "Medium  (with diagram: work out seq/ack, window, MSS)",
                    "Hard    (NO diagram: parameters only)",
                    "All three levels in a row, same kind of scenario",
                    "Quit"])
        if idx == 4:
            break
        if idx == 3:
            variante = random.choice(VARIANTES)
            for niv in ("facil", "medio", "dificil"):
                a, b = ronda(niv, 4, variante)
                total_ok += a
                total_q += b
        else:
            niv = ["facil", "medio", "dificil"][idx]
            a, b = ronda(niv, 6)
            total_ok += a
            total_q += b

    if total_q:
        print(f"\nSession total: {total_ok}/{total_q} "
              f"({100 * total_ok / total_q:.0f}%)")


def main() -> None:
    args = [a.lower().lstrip("-") for a in sys.argv[1:]]
    if not args:
        interactivo()
        return
    if "demo" in args:
        e = generar("medio")
        print(dibujar(e))
        print(ficha(e))
        for nivel in ("facil", "medio", "dificil"):
            print(f"\n{B}\n  {ETIQUETA[nivel]} level questions\n{B}")
            for q in GENERADORES[nivel](e):
                if q.tipo == "opcion":
                    correcta = q.opciones[q.respuesta]
                else:
                    correcta = q.respuesta
                print(f"\n  · {q.enunciado}")
                print(f"    -> {correcta}")
        return
    traduccion = {"easy": "facil", "medium": "medio", "hard": "dificil"}
    for ingles, nivel in traduccion.items():
        if ingles in args or nivel in args:
            ronda(nivel)
            return
    print(__doc__)


if __name__ == "__main__":
    try:
        main()
    except (KeyboardInterrupt, EOFError):
        print("\n")
